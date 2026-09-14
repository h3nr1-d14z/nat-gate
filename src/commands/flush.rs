use colored::Colorize;
use serde::Serialize;

use crate::iptables::rulestore::RuleStore;
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

    // Load current state: every nat-gate entry, both chains, orphans included
    let store = RuleStore::load(ipv6)?;
    let entries: Vec<_> = store.entries().to_vec();

    if entries.is_empty() {
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

    let rule_count = entries.len();

    if dry_run {
        if json_output {
            output::print_dry_run_action(
                "flush",
                serde_json::json!({
                    "ip_version": ip_version,
                    "rules_to_delete": rule_count,
                    "rules": entries.iter().map(|e| {
                        serde_json::json!({
                            "chain": e.chain.as_str(),
                            "marker": e.rule.marker()
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
            for entry in &entries {
                println!("  - {} ({})", entry.chain.as_str(), entry.rule.marker());
            }
        }
        return Ok(());
    }

    // Delete each entry by its exact spec — immune to line-number shifts,
    // so ordering no longer matters
    let mut deleted_count = 0;
    let mut failed_count = 0;
    let mut cleaned_chains: Vec<String> = Vec::new();

    for entry in &entries {
        if !json_output {
            print!(
                "  Deleting from {} ({})... ",
                entry.chain.as_str(),
                entry.rule.marker()
            );
        }
        match IptablesExecutor::delete_rule_spec(entry.chain.as_str(), &entry.spec, ipv6) {
            Ok(_) => {
                deleted_count += 1;
                if !cleaned_chains.contains(&entry.chain.as_str().to_string()) {
                    cleaned_chains.push(entry.chain.as_str().to_string());
                }
                if !json_output {
                    println!("{}", "OK".green());
                }
            }
            Err(e) => {
                failed_count += 1;
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
    } else if failed_count == 0 {
        println!(
            "\n{}",
            format!("Successfully flushed {deleted_count} nat-gate {ip_version} rule(s)")
                .green()
                .bold()
        );
    } else {
        println!(
            "\n{}",
            format!("Flushed {deleted_count} rule(s); {failed_count} deletion(s) failed")
                .yellow()
                .bold()
        );
    }

    Ok(())
}
