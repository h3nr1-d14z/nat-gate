use colored::Colorize;
use serde_json;

use crate::backend;
use crate::config::{load_config_from_path_or_default, RuleConfig};
use crate::output;
use crate::utils::check_root;

pub fn run(config_path: Option<&str>, dry_run: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks (skip if dry-run)
    if !dry_run {
        check_root()?;
        backend::check_dependencies()?;
    }

    // Load config file
    let (path, config) = load_config_from_path_or_default(config_path)?;

    if !json_output && !dry_run {
        println!("{}", format!("Applying rules from {path:?}").blue().bold());
    }

    if config.rules.is_empty() {
        if json_output {
            output::print_error("No rules defined in config file");
        } else {
            println!("{}", "No rules defined in config file.".yellow());
        }
        return Ok(());
    }

    if !json_output && !dry_run {
        println!("  Found {} rule(s) in config", config.rules.len());
    }

    // Validate all rules first
    for rule in &config.rules {
        rule.validate()?;
    }

    let mut dry_run_actions = Vec::new();
    let mut success_count = 0;
    let mut skipped_count = 0;

    for rule in &config.rules {
        let result = apply_rule(rule, dry_run, json_output, &mut dry_run_actions)?;
        match result {
            ApplyResult::Added => success_count += 1,
            ApplyResult::Skipped => skipped_count += 1,
            ApplyResult::DryRun => {}
        }
    }

    if dry_run {
        if json_output {
            output::print_dry_run_actions(dry_run_actions);
        } else {
            println!(
                "\n{}",
                format!("[DRY-RUN] Would apply {} rule(s)", config.rules.len())
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
        match backend::save_rules() {
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
            "applied": success_count,
            "skipped": skipped_count,
            "total": config.rules.len(),
            "config_file": path.to_string_lossy()
        }));
    } else {
        println!(
            "\n{}",
            format!("Applied {success_count} rule(s), skipped {skipped_count} (already existed)")
                .green()
                .bold()
        );
    }

    Ok(())
}

enum ApplyResult {
    Added,
    Skipped,
    DryRun,
}

fn apply_rule(
    rule: &RuleConfig,
    dry_run: bool,
    json_output: bool,
    dry_run_actions: &mut Vec<serde_json::Value>,
) -> Result<ApplyResult, String> {
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
            "ipv6": rule.ipv6,
            "limit": rule.limit
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
        return Ok(ApplyResult::DryRun);
    }

    // Check if rule already exists (exact marker match)
    let store = backend::load_rules(rule.ipv6)?;
    if store.find(&rule.protocol, &rule.port).is_some() {
        if !json_output {
            println!(
                "  {} {} {} {} (already exists)",
                "Skipping".yellow(),
                ip_version,
                rule.protocol.to_uppercase(),
                rule.port
            );
        }
        return Ok(ApplyResult::Skipped);
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

    backend::add_prerouting_rule(
        &rule.protocol,
        &rule.port,
        &rule.target,
        rule.interface.as_deref(),
        rule.ipv6,
        rule.limit.as_deref(),
    )?;

    backend::add_postrouting_rule(&rule.protocol, &rule.port, &rule.target, rule.ipv6)?;

    if !json_output {
        println!("{}", "OK".green());
    }

    Ok(ApplyResult::Added)
}
