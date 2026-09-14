//! `nat-gate proxy …` — manage PROXY-protocol forwarding rules + daemon.
//!
//! Rules live in `/etc/nat-gate/proxy.yaml`. `add` validates proto/IP/port,
//! refuses to collide with an existing iptables DNAT rule on the same proto
//! + port (a DNAT and a userspace proxy can't both bind the same port), then
//!   writes the config. `del` / `list` / `daemon` round out the surface.

use colored::Colorize;

use crate::backend;
use crate::output;
use crate::proxy::{ProxyConfig, ProxyRule};
use crate::utils::check_root;

/// Validate that proto is exactly "tcp" (PROXY protocol is TCP-only).
fn validate_tcp(proto: &str) -> Result<String, String> {
    match proto.to_lowercase().as_str() {
        "tcp" => Ok("tcp".to_string()),
        "udp" => Err("PROXY protocol is TCP only; UDP is not supported. Use 'nat-gate add udp' for plain UDP forwarding.".to_string()),
        _ => Err(format!("Unsupported protocol '{proto}'. PROXY mode requires TCP.")),
    }
}

/// Parse and validate a single port in 1..=65535.
fn parse_port(s: &str, field: &str) -> Result<u16, String> {
    let p: u16 = s
        .parse()
        .map_err(|_| format!("Invalid {field}: '{s}' (expected 1-65535)"))?;
    if p == 0 {
        return Err(format!("Invalid {field}: 0 is not allowed"));
    }
    Ok(p)
}

/// Validate an IPv4 or IPv6 address string.
fn validate_ip_addr(s: &str) -> Result<String, String> {
    s.parse::<std::net::IpAddr>()
        .map(|_| s.to_string())
        .map_err(|_| format!("Invalid IP address: '{s}'"))
}

/// Validate a proxy-protocol selector.
fn validate_proxy_protocol(s: &str) -> Result<String, String> {
    match s {
        "v1" | "v2" | "none" => Ok(s.to_string()),
        _ => Err(format!(
            "Invalid --proxy-protocol '{s}'. Must be v1, v2, or none."
        )),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// `proxy add <proto> <port> <target-ip> [target-port] --proxy-protocol <v1|v2|none>`
pub fn add(
    proto: &str,
    port: &str,
    target: &str,
    target_port: Option<&str>,
    proxy_protocol: &str,
    json_output: bool,
) -> Result<(), String> {
    check_root()?;

    let proto = validate_tcp(proto)?;
    let port_val = parse_port(port, "listen port")?;
    let target_ip = validate_ip_addr(target)?;
    let target_port_val = match target_port {
        Some(tp) => parse_port(tp, "target port")?,
        None => port_val, // default to listen port
    };
    let pp = validate_proxy_protocol(proxy_protocol)?;

    // Refuse to collide with an existing iptables DNAT rule on the same
    // proto+port — both can't bind the same listener.
    check_no_iptables_conflict(&proto, port)?;

    let mut config = ProxyConfig::load()?;
    if config.rules.iter().any(|r| r.port == port_val) {
        return Err(format!(
            "A proxy rule for port {port_val} already exists. Remove it first with 'nat-gate proxy del {port_val}'."
        ));
    }

    let rule = ProxyRule {
        proto: proto.clone(),
        port: port_val,
        target: target_ip,
        target_port: target_port_val,
        proxy_protocol: pp,
    };
    config.rules.push(rule.clone());
    config.save()?;

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": &rule,
        }));
    } else {
        println!(
            "{}",
            format!(
                "Added proxy rule: tcp/{} -> {}:{} ({})",
                rule.port, rule.target, rule.target_port, rule.proxy_protocol
            )
            .green()
            .bold()
        );
    }
    Ok(())
}

/// `proxy del <port>`
pub fn del(port: &str, json_output: bool) -> Result<(), String> {
    check_root()?;
    let port_val = parse_port(port, "port")?;

    let mut config = ProxyConfig::load()?;
    let before = config.rules.len();
    config.rules.retain(|r| r.port != port_val);
    if config.rules.len() == before {
        return Err(format!("No proxy rule found for port {port_val}"));
    }
    config.save()?;

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "deleted_port": port_val,
        }));
    } else {
        println!(
            "{}",
            format!("Deleted proxy rule for port {port_val}")
                .green()
                .bold()
        );
    }
    Ok(())
}

/// `proxy list` — JSON or plain.
pub fn list(json_output: bool) -> Result<(), String> {
    let config = ProxyConfig::load()?;
    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "rules": &config.rules,
                "count": config.rules.len(),
            }
        }));
    } else if config.rules.is_empty() {
        println!("{}", "No proxy rules configured.".dimmed());
    } else {
        println!("{}", "PROXY forwarding rules:".blue().bold());
        for r in &config.rules {
            println!(
                "  tcp/{:<7} {:<22} {}",
                r.port,
                format!("{}:{}", r.target, r.target_port),
                r.proxy_protocol,
            );
        }
    }
    Ok(())
}

/// `proxy daemon [--dir DIR]`
pub fn daemon(log_dir: Option<&str>) -> Result<(), String> {
    crate::proxy::daemon::run(log_dir)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// True if an iptables forwarding rule already exists for `proto`+`port`
/// in either address family. We load both stores before erroring so the
/// user gets a complete picture.
fn check_no_iptables_conflict(proto: &str, port: &str) -> Result<(), String> {
    let v4 = backend::load_rules(false).ok();
    let v6 = backend::load_rules(true).ok();

    let in_v4 = v4
        .as_ref()
        .and_then(|s| s.find(proto, port))
        .map(|r| r.target.clone());
    let in_v6 = v6
        .as_ref()
        .and_then(|s| s.find(proto, port))
        .map(|r| r.target.clone());

    if in_v4.is_some() || in_v6.is_some() {
        let which = match (in_v4, in_v6) {
            (Some(t), Some(_)) => format!(" (iptables: {t}, ip6tables also has a rule)"),
            (Some(t), None) => format!(" (iptables target: {t})"),
            (None, Some(t)) => format!(" (ip6tables target: {t})"),
            (None, None) => String::new(),
        };
        return Err(format!(
            "An iptables forwarding rule for {proto}/{port} already exists{which}. \
             Delete it first with: nat-gate del {proto} {port} (or with -6 for IPv6)."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_validator_accepts_tcp_rejects_udp() {
        assert_eq!(validate_tcp("tcp").unwrap(), "tcp");
        let err = validate_tcp("udp").unwrap_err();
        assert!(err.contains("TCP only"), "{err}");
    }

    #[test]
    fn port_parse_basic() {
        assert_eq!(parse_port("25565", "listen port").unwrap(), 25565);
        assert!(parse_port("0", "listen port").is_err());
        assert!(parse_port("abc", "listen port").is_err());
    }

    #[test]
    fn ip_validator_accepts_v4_and_v6() {
        assert!(validate_ip_addr("10.0.0.1").is_ok());
        assert!(validate_ip_addr("fd7a:115c:a1e0::5").is_ok());
        assert!(validate_ip_addr("not-an-ip").is_err());
    }

    #[test]
    fn proxy_protocol_selector() {
        for ok in &["v1", "v2", "none"] {
            assert_eq!(validate_proxy_protocol(ok).unwrap(), *ok);
        }
        assert!(validate_proxy_protocol("v3").is_err());
    }
}
