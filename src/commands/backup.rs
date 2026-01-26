use std::fs;
use std::io::{self, Write};

use colored::Colorize;
use regex::Regex;
use serde_json;

use crate::config::{BackupData, RuleConfig};
use crate::iptables::IptablesExecutor;
use crate::output;
use crate::utils::{check_iptables, check_root};

const DEFAULT_BACKUP_FILE: &str = "./nat-gate-backup.json";

pub fn run(file: Option<&str>, ipv6: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    check_iptables()?;

    let output_file = file.unwrap_or(DEFAULT_BACKUP_FILE);

    if !json_output {
        println!(
            "{}",
            format!("Backing up nat-gate rules to {output_file}")
                .blue()
                .bold()
        );
    }

    // Get current rules
    let rules_output = IptablesExecutor::list_nat_rules(ipv6)?;
    let rules = parse_rules_for_export(&rules_output, ipv6);

    if rules.is_empty() {
        if json_output {
            output::print_error("No nat-gate rules found to backup");
        } else {
            println!("{}", "No nat-gate rules found to backup.".yellow());
        }
        return Ok(());
    }

    // Create backup data
    let backup = BackupData::new(rules);
    let json_str = serde_json::to_string_pretty(&backup)
        .map_err(|e| format!("Failed to serialize rules: {e}"))?;

    // Write to file or stdout
    if output_file == "-" {
        io::stdout()
            .write_all(json_str.as_bytes())
            .map_err(|e| format!("Failed to write to stdout: {e}"))?;
        println!();
    } else {
        fs::write(output_file, &json_str)
            .map_err(|e| format!("Failed to write backup file: {e}"))?;
    }

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "file": output_file,
            "rules_count": backup.rules.len(),
            "version": backup.version,
            "exported_at": backup.exported_at.to_rfc3339()
        }));
    } else {
        println!("{}", "OK".green());
        println!(
            "\n{}",
            format!("Backed up {} rule(s) to {}", backup.rules.len(), output_file)
                .green()
                .bold()
        );
    }

    Ok(())
}

/// Parse iptables output to extract rules for export
fn parse_rules_for_export(iptables_output: &str, ipv6: bool) -> Vec<RuleConfig> {
    let mut rules = Vec::new();
    let mut in_prerouting = false;

    // Pattern to match nat-gate rules
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

                rules.push(RuleConfig {
                    protocol: proto.to_string(),
                    port: port_from_comment.to_string(),
                    target: target_ip.to_string(),
                    interface,
                    ipv6,
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
    fn test_parse_rules_for_export() {
        let output = r#"Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 /* nat-gate:tcp:443 */ to:100.64.0.5:443
2        0     0 DNAT       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:51820 /* nat-gate:udp:51820 */ to:100.64.0.10:51820

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
"#;

        let rules = parse_rules_for_export(output, false);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].protocol, "tcp");
        assert_eq!(rules[0].port, "443");
        assert_eq!(rules[0].target, "100.64.0.5");
        assert_eq!(rules[1].protocol, "udp");
        assert_eq!(rules[1].port, "51820");
    }
}
