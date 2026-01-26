use std::fs;

use colored::Colorize;
use serde_json;

use crate::config::BackupData;
use crate::iptables::IptablesExecutor;
use crate::output;
use crate::utils::{check_iptables, check_root, save_iptables_rules};

pub fn run(file: &str, dry_run: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks (skip if dry-run since we won't modify anything)
    if !dry_run {
        check_root()?;
        check_iptables()?;
    }

    if !json_output && !dry_run {
        println!(
            "{}",
            format!("Restoring nat-gate rules from {file}")
                .blue()
                .bold()
        );
    }

    // Read backup file
    let content = fs::read_to_string(file)
        .map_err(|e| format!("Failed to read backup file: {e}"))?;

    let backup: BackupData = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse backup file: {e}"))?;

    if backup.rules.is_empty() {
        if json_output {
            output::print_error("No rules found in backup file");
        } else {
            println!("{}", "No rules found in backup file.".yellow());
        }
        return Ok(());
    }

    if !json_output {
        println!(
            "  Found {} rule(s) from version {} ({})",
            backup.rules.len(),
            backup.version,
            backup.exported_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }

    // Validate all rules first
    for rule in &backup.rules {
        rule.validate()?;
    }

    let mut dry_run_actions = Vec::new();
    let mut success_count = 0;
    let mut skipped_count = 0;

    for rule in &backup.rules {
        let ip_version = if rule.ipv6 { "IPv6" } else { "IPv4" };
        let iface_info = rule
            .interface
            .as_ref()
            .map(|i| format!(" on {i}"))
            .unwrap_or_default();

        if dry_run {
            let action = serde_json::json!({
                "action": "add_rule",
                "protocol": rule.protocol,
                "port": rule.port,
                "target": rule.target,
                "interface": rule.interface,
                "ipv6": rule.ipv6
            });
            dry_run_actions.push(action);

            if !json_output {
                println!(
                    "{} Would add: {} {} {} -> {}{}",
                    "[DRY-RUN]".yellow(),
                    ip_version,
                    rule.protocol.to_uppercase(),
                    rule.port,
                    rule.target,
                    iface_info
                );
            }
            continue;
        }

        // Check if rule already exists
        let existing_rules = IptablesExecutor::list_nat_rules(rule.ipv6)?;
        let comment = IptablesExecutor::comment_marker(&rule.protocol, &rule.port);

        if existing_rules.contains(&comment) {
            if !json_output {
                println!(
                    "  {} {} {} {} (already exists)",
                    "Skipping".yellow(),
                    ip_version,
                    rule.protocol.to_uppercase(),
                    rule.port
                );
            }
            skipped_count += 1;
            continue;
        }

        // Add the rules
        if !json_output {
            print!(
                "  Adding {} {} {} -> {}{}... ",
                ip_version,
                rule.protocol.to_uppercase(),
                rule.port,
                rule.target,
                iface_info
            );
        }

        IptablesExecutor::add_prerouting_rule(
            &rule.protocol,
            &rule.port,
            &rule.target,
            rule.interface.as_deref(),
            rule.ipv6,
        )?;

        IptablesExecutor::add_postrouting_rule(
            &rule.protocol,
            &rule.port,
            &rule.target,
            rule.ipv6,
        )?;

        if !json_output {
            println!("{}", "OK".green());
        }
        success_count += 1;
    }

    if dry_run {
        if json_output {
            output::print_dry_run_actions(dry_run_actions);
        } else {
            println!(
                "\n{}",
                format!("[DRY-RUN] Would restore {} rule(s)", backup.rules.len())
                    .yellow()
                    .bold()
            );
        }
        return Ok(());
    }

    // Save rules
    if success_count > 0 {
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
    }

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "restored": success_count,
            "skipped": skipped_count,
            "total": backup.rules.len()
        }));
    } else {
        println!(
            "\n{}",
            format!(
                "Restored {success_count} rule(s), skipped {skipped_count} (already existed)"
            )
            .green()
            .bold()
        );
    }

    Ok(())
}
