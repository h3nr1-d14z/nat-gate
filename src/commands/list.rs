use colored::Colorize;
use regex::Regex;

use crate::iptables::IptablesExecutor;
use crate::utils::{check_iptables, check_root};

#[derive(Debug)]
struct ForwardingRule {
    proto: String,
    port: u16,
    target: String,
}

pub fn run() -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    check_iptables()?;

    let rules_output = IptablesExecutor::list_nat_rules()?;
    let rules = parse_forwarding_rules(&rules_output);

    if rules.is_empty() {
        println!("{}", "No nat-gate forwarding rules found.".yellow());
        println!("Use {} to add a rule.", "nat-gate add <tcp|udp> <port> <target>".cyan());
        return Ok(());
    }

    println!("{}", "Active nat-gate forwarding rules:".blue().bold());
    println!();

    // Table header
    println!("┌──────────┬───────┬─────────────────┐");
    println!("│ {} │ {} │ {} │",
        "Protocol".bold(),
        "Port ".bold(),
        "Target          ".bold()
    );
    println!("├──────────┼───────┼─────────────────┤");

    // Table rows
    for rule in &rules {
        println!(
            "│ {:<8} │ {:>5} │ {:<15} │",
            rule.proto,
            rule.port,
            rule.target
        );
    }

    println!("└──────────┴───────┴─────────────────┘");
    println!();
    println!("Total: {} rule(s)", rules.len().to_string().green());

    Ok(())
}

fn parse_forwarding_rules(iptables_output: &str) -> Vec<ForwardingRule> {
    let mut rules = Vec::new();
    let mut in_prerouting = false;

    // Pattern to match our rules in PREROUTING chain
    // Example: 1    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 /* nat-gate:tcp:443 */ to:100.64.0.5:443
    let rule_pattern = Regex::new(
        r"(tcp|udp)\s+dpt:(\d+)\s+/\*\s*nat-gate:(tcp|udp):(\d+)\s*\*/\s+to:([\d.]+):\d+"
    ).unwrap();

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
            if let (Some(proto), Some(port), Some(target)) = (
                cap.get(1).map(|m| m.as_str()),
                cap.get(2).and_then(|m| m.as_str().parse::<u16>().ok()),
                cap.get(5).map(|m| m.as_str()),
            ) {
                rules.push(ForwardingRule {
                    proto: proto.to_string(),
                    port,
                    target: target.to_string(),
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

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 MASQUERADE  tcp  --  *      *       0.0.0.0/0            100.64.0.5           tcp dpt:443 /* nat-gate:tcp:443 */
"#;

        let rules = parse_forwarding_rules(output);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].proto, "tcp");
        assert_eq!(rules[0].port, 443);
        assert_eq!(rules[0].target, "100.64.0.5");
        assert_eq!(rules[1].proto, "udp");
        assert_eq!(rules[1].port, 51820);
        assert_eq!(rules[1].target, "100.64.0.10");
    }
}
