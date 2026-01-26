use colored::Colorize;
use regex::Regex;
use serde::Serialize;

use crate::iptables::IptablesExecutor;
use crate::output;
use crate::utils::{check_iptables, check_root, save_iptables_rules};

#[derive(Debug, Serialize)]
struct FlushResult {
    ip_version: String,
    rules_deleted: usize,
    chains_cleaned: Vec<String>,
}

/// Run the flush command to remove all nat-gate managed rules
pub fn run(ipv6: bool, dry_run: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    check_iptables()?;

    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };

    if !json_output && !dry_run {
        println!(
            "{}",
            format!("Flushing all nat-gate {ip_version} rules")
                .blue()
                .bold()
        );
    }

    // Get current rules
    let rules_output = IptablesExecutor::list_nat_rules(ipv6)?;

    // Find all nat-gate rules in both chains
    let rules_to_delete = find_all_natgate_rules(&rules_output);

    if rules_to_delete.is_empty() {
        if json_output {
            output::print_value(serde_json::json!({
                "success": true,
                "message": format!("No nat-gate {} rules found to flush", ip_version),
                "data": {
                    "ip_version": ip_version,
                    "rules_deleted": 0
                }
            }));
        } else if dry_run {
            println!(
                "{} No nat-gate {} rules found to flush",
                "[DRY-RUN]".yellow(),
                ip_version
            );
        } else {
            println!(
                "{}",
                format!("No nat-gate {ip_version} rules found to flush.").yellow()
            );
        }
        return Ok(());
    }

    let rule_count = rules_to_delete.len();

    if dry_run {
        if json_output {
            output::print_dry_run_action(
                "flush",
                serde_json::json!({
                    "ip_version": ip_version,
                    "rules_to_delete": rule_count,
                    "rules": rules_to_delete.iter().map(|(chain, line, marker)| {
                        serde_json::json!({
                            "chain": chain,
                            "line": line,
                            "marker": marker
                        })
                    }).collect::<Vec<_>>()
                }),
            );
        } else {
            println!(
                "{} Would delete {} nat-gate {} rule(s):",
                "[DRY-RUN]".yellow(),
                rule_count,
                ip_version
            );
            for (chain, line, marker) in &rules_to_delete {
                println!("  - {chain} line {line}: {marker}");
            }
        }
        return Ok(());
    }

    // Delete rules (already sorted by line number descending)
    let mut deleted_count = 0;
    let mut cleaned_chains: Vec<String> = Vec::new();

    for (chain, line_num, marker) in &rules_to_delete {
        if !json_output {
            print!("  Deleting from {chain} (line {line_num}, {marker})... ");
        }
        match IptablesExecutor::delete_rule_by_line(chain, *line_num, ipv6) {
            Ok(_) => {
                deleted_count += 1;
                if !cleaned_chains.contains(chain) {
                    cleaned_chains.push(chain.clone());
                }
                if !json_output {
                    println!("{}", "OK".green());
                }
            }
            Err(e) => {
                if !json_output {
                    println!("{}", "FAILED".red());
                    eprintln!("    {}", e.yellow());
                }
            }
        }
    }

    // Save rules
    if !json_output {
        print!("  Saving rules... ");
    }
    match save_iptables_rules() {
        Ok(_) => {
            if !json_output {
                println!("{}", "OK".green());
            }
        }
        Err(e) => {
            if !json_output {
                println!("{}", "WARNING".yellow());
                println!("    {}", e.yellow());
            }
        }
    }

    if json_output {
        let result = FlushResult {
            ip_version: ip_version.to_string(),
            rules_deleted: deleted_count,
            chains_cleaned: cleaned_chains,
        };
        output::print_value(serde_json::json!({
            "success": true,
            "data": result
        }));
    } else {
        println!(
            "\n{}",
            format!("Successfully flushed {deleted_count} nat-gate {ip_version} rule(s)")
                .green()
                .bold()
        );
    }

    Ok(())
}

/// Find all nat-gate rules for flushing
/// Returns Vec<(chain, line_number, comment_marker)> sorted by line number descending
fn find_all_natgate_rules(iptables_list_output: &str) -> Vec<(String, u32, String)> {
    let mut rules: Vec<(String, u32, String)> = Vec::new();
    let mut current_chain = String::new();

    let chain_pattern = Regex::new(r"^Chain (\w+)").unwrap();
    let marker_pattern = Regex::new(r"nat-gate:(\w+):(\S+)").unwrap();

    for line in iptables_list_output.lines() {
        // Check for chain header
        if let Some(cap) = chain_pattern.captures(line) {
            if let Some(chain) = cap.get(1) {
                current_chain = chain.as_str().to_string();
            }
            continue;
        }

        // Only process PREROUTING and POSTROUTING chains
        if current_chain != "PREROUTING" && current_chain != "POSTROUTING" {
            continue;
        }

        // Check if this line contains nat-gate marker
        if let Some(marker_cap) = marker_pattern.captures(line) {
            let marker = marker_cap.get(0).map(|m| m.as_str()).unwrap_or("");

            // Extract line number (first number in the line)
            if let Some(line_num_str) = line.split_whitespace().next() {
                if let Ok(num) = line_num_str.parse::<u32>() {
                    rules.push((current_chain.clone(), num, marker.to_string()));
                }
            }
        }
    }

    // Sort by chain (POSTROUTING first, then PREROUTING) and then by line number descending
    // This ensures we delete POSTROUTING rules before PREROUTING to avoid index shifting issues
    rules.sort_by(|a, b| {
        // POSTROUTING comes before PREROUTING
        let chain_order = |c: &str| if c == "POSTROUTING" { 0 } else { 1 };
        match chain_order(&a.0).cmp(&chain_order(&b.0)) {
            std::cmp::Ordering::Equal => b.1.cmp(&a.1), // Higher line numbers first within same chain
            other => other,
        }
    });

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_all_natgate_rules() {
        let output = r#"Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 /* nat-gate:tcp:443 */ to:100.64.0.5:443
2        0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 /* nat-gate:tcp:80 */ to:100.64.0.5:80
3        0     0 DNAT       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:51820 /* nat-gate:udp:51820 */ to:100.64.0.10:51820

Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 MASQUERADE  tcp  --  *      *       0.0.0.0/0            100.64.0.5           tcp dpt:443 /* nat-gate:tcp:443 */
2        0     0 MASQUERADE  tcp  --  *      *       0.0.0.0/0            100.64.0.5           tcp dpt:80 /* nat-gate:tcp:80 */
3        0     0 MASQUERADE  udp  --  *      *       0.0.0.0/0            100.64.0.10          udp dpt:51820 /* nat-gate:udp:51820 */
"#;

        let rules = find_all_natgate_rules(output);

        // Should find 6 rules total (3 PREROUTING + 3 POSTROUTING)
        assert_eq!(rules.len(), 6);

        // POSTROUTING rules should come first (higher priority for deletion)
        assert_eq!(rules[0].0, "POSTROUTING");
        assert_eq!(rules[1].0, "POSTROUTING");
        assert_eq!(rules[2].0, "POSTROUTING");

        // Then PREROUTING rules
        assert_eq!(rules[3].0, "PREROUTING");
        assert_eq!(rules[4].0, "PREROUTING");
        assert_eq!(rules[5].0, "PREROUTING");

        // Within each chain, higher line numbers should come first
        assert_eq!(rules[0].1, 3); // POSTROUTING line 3
        assert_eq!(rules[1].1, 2); // POSTROUTING line 2
        assert_eq!(rules[2].1, 1); // POSTROUTING line 1
    }

    #[test]
    fn test_find_all_natgate_rules_empty() {
        let output = r#"Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
"#;

        let rules = find_all_natgate_rules(output);
        assert_eq!(rules.len(), 0);
    }
}
