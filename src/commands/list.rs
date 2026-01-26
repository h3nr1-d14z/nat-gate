use colored::Colorize;
use regex::Regex;
use serde::Serialize;
use serde_json;

use crate::iptables::IptablesExecutor;
use crate::output;
use crate::utils::{check_iptables, check_root};

#[derive(Debug, Serialize)]
struct ForwardingRule {
    proto: String,
    port: String,
    target: String,
    interface: Option<String>,
}

pub fn run(ipv6: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    check_iptables()?;

    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };
    let rules_output = IptablesExecutor::list_nat_rules(ipv6)?;
    let rules = parse_forwarding_rules(&rules_output);

    if rules.is_empty() {
        if json_output {
            output::print_value(serde_json::json!({
                "success": true,
                "data": {
                    "rules": [],
                    "count": 0,
                    "ip_version": ip_version
                }
            }));
        } else {
            println!(
                "{}",
                format!("No nat-gate {ip_version} forwarding rules found.").yellow()
            );
            let v6_flag = if ipv6 { " -6" } else { "" };
            println!(
                "Use {} to add a rule.",
                format!("nat-gate add{v6_flag} <tcp|udp> <port> <target>").cyan()
            );
        }
        return Ok(());
    }

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "rules": rules,
                "count": rules.len(),
                "ip_version": ip_version
            }
        }));
    } else {
        println!(
            "{}",
            format!("Active nat-gate {ip_version} forwarding rules:")
                .blue()
                .bold()
        );
        println!();

        // Table header
        println!("┌──────────┬─────────────┬─────────────────────┬────────────┐");
        println!(
            "│ {} │ {} │ {} │ {} │",
            "Protocol".bold(),
            "Port       ".bold(),
            "Target              ".bold(),
            "Interface ".bold()
        );
        println!("├──────────┼─────────────┼─────────────────────┼────────────┤");

        // Table rows
        for rule in &rules {
            let iface = rule.interface.as_deref().unwrap_or("-");
            println!(
                "│ {:<8} │ {:>11} │ {:<19} │ {:<10} │",
                rule.proto, rule.port, rule.target, iface
            );
        }

        println!("└──────────┴─────────────┴─────────────────────┴────────────┘");
        println!();
        println!("Total: {} rule(s)", rules.len().to_string().green());
    }

    Ok(())
}

fn parse_forwarding_rules(iptables_output: &str) -> Vec<ForwardingRule> {
    let mut rules = Vec::new();
    let mut in_prerouting = false;

    // Pattern to match our rules in PREROUTING chain
    // Matches both single ports and port ranges
    // Example: tcp dpt:443 /* nat-gate:tcp:443 */ to:100.64.0.5:443
    // Example: tcp dpts:8000:8080 /* nat-gate:tcp:8000-8080 */ to:100.64.0.5:8000-8080
    let rule_pattern = Regex::new(
        r"(tcp|udp)\s+dpt[s]?:(\d+(?::\d+)?)\s+/\*\s*nat-gate:(tcp|udp):(\S+)\s*\*/\s+to:([\d.:a-fA-F\[\]]+)",
    )
    .unwrap();

    // Pattern to extract interface
    let interface_pattern = Regex::new(r"\s+(\w+)\s+\*\s+").unwrap();

    for line in iptables_output.lines() {
        // Track which chain we're in
        if line.starts_with("Chain PREROUTING") {
            in_prerouting = true;
            continue;
        } else if line.starts_with("Chain ") {
            in_prerouting = false;
            continue;
        }

        // Only parse PREROUTING rules to avoid duplicates
        if !in_prerouting {
            continue;
        }

        // Check if line contains nat-gate marker
        if !line.contains("nat-gate:") {
            continue;
        }

        // Try to extract rule details
        if let Some(cap) = rule_pattern.captures(line) {
            if let (Some(proto), Some(port_from_comment), Some(target)) = (
                cap.get(1).map(|m| m.as_str()),
                cap.get(4).map(|m| m.as_str()),
                cap.get(5).map(|m| m.as_str()),
            ) {
                // Extract interface if present
                let interface = interface_pattern
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .filter(|s| s != "*");

                // Extract just the IP from target (remove port)
                let target_ip = target
                    .rsplit_once(':')
                    .map(|(ip, _)| ip.trim_matches(|c| c == '[' || c == ']'))
                    .unwrap_or(target);

                rules.push(ForwardingRule {
                    proto: proto.to_string(),
                    port: port_from_comment.to_string(),
                    target: target_ip.to_string(),
                    interface,
                });
            }
        }
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_forwarding_rules() {
        let output = r#"Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 /* nat-gate:tcp:443 */ to:100.64.0.5:443
2        0     0 DNAT       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:51820 /* nat-gate:udp:51820 */ to:100.64.0.10:51820
3        0     0 DNAT       tcp  --  eth0   *       0.0.0.0/0            0.0.0.0/0            tcp dpts:8000:8080 /* nat-gate:tcp:8000-8080 */ to:100.64.0.5:8000-8080

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 MASQUERADE  tcp  --  *      *       0.0.0.0/0            100.64.0.5           tcp dpt:443 /* nat-gate:tcp:443 */
"#;

        let rules = parse_forwarding_rules(output);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].proto, "tcp");
        assert_eq!(rules[0].port, "443");
        assert_eq!(rules[0].target, "100.64.0.5");
        assert_eq!(rules[1].proto, "udp");
        assert_eq!(rules[1].port, "51820");
        assert_eq!(rules[2].port, "8000-8080");
    }
}
