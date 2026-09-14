use colored::Colorize;
use serde::Serialize;
use std::fs;
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use crate::backend;
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
            if health.status != "OK" {
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
            if health.status != "OK" {
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

/// Check the health of a single rule
fn check_rule_health(rule: &RuleInfo, specific_port: Option<u16>) -> RuleHealth {
    // Check if target is reachable via ping
    let reachable = ping_host(&rule.target);

    // Optionally check if the specific port is open
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

    // Determine status
    let status = if reachable {
        if let Some(open) = port_open {
            if open {
                "OK"
            } else {
                "PORT_CLOSED"
            }
        } else {
            "OK"
        }
    } else {
        "UNREACHABLE"
    };

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

/// Check if a TCP port is open, without shelling out to nc/bash
fn check_port(host: &str, port: u16, proto: &str) -> bool {
    // UDP: connectionless — a plain connect proves nothing meaningful.
    // Report unknown as closed, same as the previous nc-based behavior.
    if proto == "udp" {
        return false;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_str() {
        assert_eq!(status_str(true).to_string(), "OK");
        assert_eq!(status_str(false).to_string(), "DISABLED");
    }
}
