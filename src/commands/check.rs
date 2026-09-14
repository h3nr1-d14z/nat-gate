use colored::Colorize;
use serde::Serialize;
use std::fs;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::backend;
use crate::logging::events;
use crate::output;
use crate::utils::check_root;

#[derive(Debug, Serialize)]
struct CheckResult {
    ip_forwarding: ForwardingStatus,
    rules: Vec<RuleHealth>,
    overall_status: String,
}

#[derive(Debug, Serialize)]
struct ForwardingStatus {
    ipv4: bool,
    ipv6: bool,
}

#[derive(Debug, Serialize)]
struct RuleHealth {
    proto: String,
    port: String,
    target: String,
    reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_open: Option<bool>,
    status: String,
}

impl RuleHealth {
    /// Passing states for overall-health accounting. An active UDP flow is a
    /// healthy state too — it must not drag the summary to "degraded".
    fn is_healthy(&self) -> bool {
        matches!(self.status.as_str(), "OK" | "UDP_FLOW_ACTIVE")
    }
}

/// Run the check command to verify nat-gate configuration health
pub fn run(port: Option<u16>, json_output: bool) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    backend::check_dependencies()?;

    if !json_output {
        println!("{}", "Checking nat-gate configuration...".blue().bold());
        println!();
    }

    // Check IP forwarding
    let ipv4_forward = check_ip_forwarding(false);
    let ipv6_forward = check_ip_forwarding(true);

    if !json_output {
        println!("  IP forwarding (IPv4): {}", status_str(ipv4_forward));
        println!("  IP forwarding (IPv6): {}", status_str(ipv6_forward));
        println!();
    }

    // Get rules and check their health
    let ipv4_rules = get_forwarding_rules(false)?;
    let ipv6_rules = get_forwarding_rules(true)?;

    let mut all_rules: Vec<RuleHealth> = Vec::new();
    let mut all_ok = ipv4_forward; // Start with IP forwarding status

    // Check IPv4 rules
    if !ipv4_rules.is_empty() {
        if !json_output {
            println!("  {} Rule Health:", "IPv4".cyan());
        }

        for rule in &ipv4_rules {
            let health = check_rule_health(rule, port);
            if !health.is_healthy() {
                all_ok = false;
            }
            if !json_output {
                print_rule_health(&health);
            }
            all_rules.push(health);
        }

        if !json_output {
            println!();
        }
    }

    // Check IPv6 rules
    if !ipv6_rules.is_empty() {
        if !json_output {
            println!("  {} Rule Health:", "IPv6".cyan());
        }

        for rule in &ipv6_rules {
            let health = check_rule_health(rule, port);
            if !health.is_healthy() {
                all_ok = false;
            }
            if !json_output {
                print_rule_health(&health);
            }
            all_rules.push(health);
        }

        if !json_output {
            println!();
        }
    }

    // Handle case with no rules
    if ipv4_rules.is_empty() && ipv6_rules.is_empty() && !json_output {
        println!("  {}", "No nat-gate rules found.".yellow());
        println!();
    }

    // Determine overall status
    let overall_status = if all_ok && !all_rules.is_empty() {
        "healthy"
    } else if all_rules.is_empty() {
        "no_rules"
    } else if !ipv4_forward && !ipv6_forward {
        "ip_forwarding_disabled"
    } else {
        "degraded"
    };

    if json_output {
        let result = CheckResult {
            ip_forwarding: ForwardingStatus {
                ipv4: ipv4_forward,
                ipv6: ipv6_forward,
            },
            rules: all_rules,
            overall_status: overall_status.to_string(),
        };
        output::print_value(serde_json::json!({
            "success": true,
            "data": result
        }));
    } else {
        // Print summary
        match overall_status {
            "healthy" => println!("{}", "All checks passed!".green().bold()),
            "no_rules" => println!(
                "{}",
                "No rules to check. Use 'nat-gate add' to create forwarding rules.".yellow()
            ),
            "ip_forwarding_disabled" => println!(
                "{}",
                "IP forwarding is disabled. Run 'sudo nat-gate init' to enable it.".red()
            ),
            _ => println!(
                "{}",
                "Some checks failed. Review the issues above.".yellow()
            ),
        }
    }

    Ok(())
}

/// Check if IP forwarding is enabled
fn check_ip_forwarding(ipv6: bool) -> bool {
    let path = if ipv6 {
        "/proc/sys/net/ipv6/conf/all/forwarding"
    } else {
        "/proc/sys/net/ipv4/ip_forward"
    };

    fs::read_to_string(path)
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Format status as colored string
fn status_str(ok: bool) -> colored::ColoredString {
    if ok {
        "OK".green()
    } else {
        "DISABLED".red()
    }
}

/// Simple rule info for checking
struct RuleInfo {
    proto: String,
    port: String,
    target: String,
}
/// Get forwarding rules from iptables
fn get_forwarding_rules(ipv6: bool) -> Result<Vec<RuleInfo>, String> {
    let store = backend::load_rules(ipv6)?;
    Ok(store
        .rules()
        .map(|r| RuleInfo {
            proto: r.proto.clone(),
            port: r.port.clone(),
            target: r.target.clone(),
        })
        .collect())
}

/// Result of a port-level probe for a single rule.
enum PortCheck {
    /// No specific port was asked for, or the rule's port didn't match.
    NotChecked,
    /// A probe ran. `active` is true if the port looked open / a flow matched.
    Checked { active: bool },
}

impl PortCheck {
    #[cfg(test)]
    fn checked(active: bool) -> Self {
        PortCheck::Checked { active }
    }
    fn from_opt(v: Option<bool>) -> Self {
        match v {
            Some(active) => PortCheck::Checked { active },
            None => PortCheck::NotChecked,
        }
    }
}

/// Map a port probe (plus reachability) to a status string. Pure: no I/O, no
/// printing, so it can be unit-tested without a kernel or network.
fn rule_status(reachable: bool, port_check: PortCheck, proto: &str) -> &'static str {
    if !reachable {
        return "UNREACHABLE";
    }

    match port_check {
        PortCheck::NotChecked => "OK",
        // A UDP rule has no meaningful "open/closed" probe. If a matching
        // conntrack flow is present the forward is live and healthy; absent
        // one we honestly report it as closed rather than fabricating a pass.
        PortCheck::Checked { active: true } if proto == "udp" => "UDP_FLOW_ACTIVE",
        PortCheck::Checked { active: true } => "OK",
        PortCheck::Checked { active: false } => "PORT_CLOSED",
    }
}

/// Check the health of a single rule
fn check_rule_health(rule: &RuleInfo, specific_port: Option<u16>) -> RuleHealth {
    // Check if target is reachable via ping
    let reachable = ping_host(&rule.target);

    // Optionally check if the specific port is open / has an active flow
    let port_open = if let Some(port) = specific_port {
        // Only check if the rule matches the requested port
        let rule_port: Option<u16> = rule.port.split('-').next().and_then(|p| p.parse().ok());
        if rule_port == Some(port) {
            Some(check_port(&rule.target, port, &rule.proto))
        } else {
            None
        }
    } else {
        None
    };

    let status = rule_status(reachable, PortCheck::from_opt(port_open), &rule.proto);

    RuleHealth {
        proto: rule.proto.clone(),
        port: rule.port.clone(),
        target: rule.target.clone(),
        reachable,
        port_open,
        status: status.to_string(),
    }
}

/// Print rule health status
fn print_rule_health(health: &RuleHealth) {
    let status_display = match health.status.as_str() {
        "OK" => {
            let msg = if health.port_open == Some(true) {
                "(target reachable, port open)"
            } else {
                "(target reachable)"
            };
            format!("{} {}", "OK".green(), msg.dimmed())
        }
        "UDP_FLOW_ACTIVE" => format!(
            "{} {}",
            "OK".green(),
            "(target reachable, udp flow active)".dimmed()
        ),
        "PORT_CLOSED" => format!(
            "{} {}",
            "WARN".yellow(),
            "(target reachable, port closed)".dimmed()
        ),
        "UNREACHABLE" => format!("{} {}", "WARN".yellow(), "(target unreachable)".dimmed()),
        _ => format!("{}", "UNKNOWN".dimmed()),
    };

    println!(
        "    {}:{} -> {}: {}",
        health.proto, health.port, health.target, status_display
    );
}

/// Ping a host to check if it's reachable
fn ping_host(host: &str) -> bool {
    // Determine if IPv6
    let is_ipv6 = host.contains(':');

    let result = if is_ipv6 {
        Command::new("ping")
            .args(["-6", "-c", "1", "-W", "2", host])
            .output()
    } else {
        Command::new("ping")
            .args(["-c", "1", "-W", "2", host])
            .output()
    };

    result.map(|o| o.status.success()).unwrap_or(false)
}

/// Check if a port is open / has an active flow, without shelling out to nc/bash.
///
/// TCP: a plain connect — meaningful for connection-oriented protocols.
/// UDP: connectionless, so a connect proves nothing; instead inspect the
/// conntrack table for a matching flow (`conntrack -L -p udp -o extended`),
/// reusing the shared `events::parse_line` parser. If conntrack is missing or
/// the table read fails we return false (honest closed/unknown) — never a
/// fabricated pass.
fn check_port(host: &str, port: u16, proto: &str) -> bool {
    if proto == "udp" {
        let Some(conntrack_output) = fetch_udp_conntrack() else {
            return false;
        };
        return udp_flow_active(&conntrack_output, port);
    }

    // Resolve via ToSocketAddrs: handles both IPv4 and IPv6 targets
    use std::net::ToSocketAddrs;
    let addr = match (host, port).to_socket_addrs() {
        Ok(mut addrs) => addrs.next(),
        Err(_) => None,
    };
    match addr {
        Some(a) => TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok(),
        None => false,
    }
}

/// Spawn `conntrack -L -p udp -o extended` and return its stdout, or `None`
/// when conntrack is absent or the table read fails. Mirrors the spawn in
/// `sessions::fetch_live`; never fabricates output on failure.
fn fetch_udp_conntrack() -> Option<String> {
    let output = Command::new("conntrack")
        .args(["-L", "-p", "udp", "-o", "extended"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// True if any parsed conntrack flow's forwarded port matches `port`. A
/// DNAT'd flow carries the rule's target port as the original destination
/// port (post-DNAT) and, equivalently, as the reply source port. We reuse
/// the shared `events::parse_line` parser rather than writing a second one.
/// Pure: no I/O, so it is unit-tested without a kernel.
fn udp_flow_active(conntrack_output: &str, port: u16) -> bool {
    conntrack_output.lines().any(|line| {
        let Some(ev) = events::parse_line(line) else {
            return false;
        };
        ev.proto == "udp" && (ev.original.dport == port || ev.reply.sport == port)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_str() {
        assert_eq!(status_str(true).to_string(), "OK");
        assert_eq!(status_str(false).to_string(), "DISABLED");
    }

    // --- rule_status: the status vocabulary wired through check output ----

    #[test]
    fn rule_status_reachable_not_checked_is_ok() {
        assert_eq!(rule_status(true, PortCheck::NotChecked, "tcp"), "OK");
        assert_eq!(rule_status(true, PortCheck::NotChecked, "udp"), "OK");
    }

    #[test]
    fn rule_status_unreachable_is_unreachable() {
        // Port check is irrelevant when the host does not answer ping.
        assert_eq!(
            rule_status(false, PortCheck::checked(true), "tcp"),
            "UNREACHABLE"
        );
        assert_eq!(
            rule_status(false, PortCheck::checked(false), "udp"),
            "UNREACHABLE"
        );
    }

    #[test]
    fn rule_status_tcp_open_closed() {
        assert_eq!(rule_status(true, PortCheck::checked(true), "tcp"), "OK");
        assert_eq!(
            rule_status(true, PortCheck::checked(false), "tcp"),
            "PORT_CLOSED"
        );
    }

    #[test]
    fn rule_status_udp_active_uses_dedicated_status() {
        // A matching UDP flow is healthy but distinct from a TCP open probe.
        assert_eq!(
            rule_status(true, PortCheck::checked(true), "udp"),
            "UDP_FLOW_ACTIVE"
        );
        // An absent UDP flow falls back to the honest closed/unknown status.
        assert_eq!(
            rule_status(true, PortCheck::checked(false), "udp"),
            "PORT_CLOSED"
        );
    }

    // --- udp_flow_active: conntrack classification (no kernel) -----------

    /// Same extended format `fetch_udp_conntrack` would capture live.
    const CT_MATCHING: &str = "ipv4 2 udp 17 src=203.0.113.9 dst=198.51.100.2 sport=40001 dport=19132 src=100.64.0.20 dst=203.0.113.9 sport=19132 dport=40001 [ASSURED] mark=0 use=1";
    const CT_OTHER: &str = "ipv4 2 udp 17 src=203.0.113.9 dst=198.51.100.2 sport=40001 dport=27015 src=100.64.0.20 dst=203.0.113.9 sport=27015 dport=40001 mark=0 use=1";

    #[test]
    fn udp_flow_active_matches_forwarded_port() {
        // Port matches via both original dport and reply sport.
        assert!(udp_flow_active(CT_MATCHING, 19132));
    }

    #[test]
    fn udp_flow_active_matches_reply_sport_only() {
        // A line where the original dport differs but reply sport matches the
        // forwarded port (reply-src port) still counts as active.
        let line = "ipv4 2 udp 17 src=203.0.113.9 dst=198.51.100.2 sport=40001 dport=9000 src=100.64.0.20 dst=203.0.113.9 sport=19132 dport=40001";
        assert!(udp_flow_active(line, 19132));
    }

    #[test]
    fn udp_flow_active_ignores_non_matching_flow() {
        assert!(!udp_flow_active(CT_OTHER, 19132));
    }

    #[test]
    fn udp_flow_active_ignores_tcp_line() {
        // A TCP flow to the same port must not satisfy a UDP probe.
        let line = "ipv4 2 tcp 6 src=203.0.113.9 dst=198.51.100.2 sport=40001 dport=19132 src=100.64.0.20 dst=203.0.113.9 sport=19132 dport=40001";
        assert!(!udp_flow_active(line, 19132));
    }

    #[test]
    fn udp_flow_active_empty_when_conntrack_missing() {
        // When conntrack is absent it produces no output at all: no flow,
        // so udp_flow_active returns false — the honest closed/unknown state,
        // never a fabricated pass.
        assert!(!udp_flow_active("", 19132));
    }

    /// End-to-end: a missing conntrack (empty output) drives the same
    /// reachable-but-closed status an absent flow would.
    #[test]
    fn conntrack_missing_yields_closed_not_active() {
        let active = udp_flow_active("", 19132);
        assert_eq!(
            rule_status(true, PortCheck::checked(active), "udp"),
            "PORT_CLOSED"
        );
    }

    /// End-to-end: a matching conntrack flow drives UDP_FLOW_ACTIVE.
    #[test]
    fn matching_flow_yields_active_status() {
        let active = udp_flow_active(CT_MATCHING, 19132);
        assert!(active);
        assert_eq!(
            rule_status(true, PortCheck::checked(active), "udp"),
            "UDP_FLOW_ACTIVE"
        );
    }

    // --- TCP path is byte-identical --------------------------------------

    #[test]
    fn rule_status_tcp_unchanged_across_all_probes() {
        // The UDP-aware branch must not perturb TCP classification.
        assert_eq!(rule_status(true, PortCheck::checked(true), "tcp"), "OK");
        assert_eq!(
            rule_status(true, PortCheck::checked(false), "tcp"),
            "PORT_CLOSED"
        );
        assert_eq!(
            rule_status(false, PortCheck::checked(true), "tcp"),
            "UNREACHABLE"
        );
        assert_eq!(rule_status(true, PortCheck::NotChecked, "tcp"), "OK");
    }
}
