use std::fs;
use std::io::{self, Write};

use colored::Colorize;
use serde_json;

use crate::backend;
use crate::config::{BackupData, RuleConfig};
use crate::output;
use crate::utils::check_root;

const DEFAULT_BACKUP_FILE: &str = "./nat-gate-backup.json";

pub fn run(file: Option<&str>, ipv6: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    backend::check_dependencies()?;

    let output_file = file.unwrap_or(DEFAULT_BACKUP_FILE);

    if !json_output {
        println!(
            "{}",
            format!("Backing up nat-gate rules to {output_file}")
                .blue()
                .bold()
        );
    }

    // Get current rules (PREROUTING entries are authoritative)
    let store = backend::load_rules(ipv6)?;
    let rules: Vec<RuleConfig> = store
        .rules()
        .map(|r| RuleConfig {
            protocol: r.proto.clone(),
            port: r.port.clone(),
            target: r.target.clone(),
            interface: r.interface.clone(),
            ipv6,
            limit: r.limit.clone(),
        })
        .collect();

    if rules.is_empty() {
        if json_output {
            output::print_error("No nat-gate rules found to backup");
        } else {
            println!("{}", "No nat-gate rules found to backup.".yellow());
        }
        return Ok(());
    }

    // Create backup data
    let mut backup = BackupData::new(rules);

    // Include PROXY-protocol rules if present.
    let proxy_config = crate::proxy::ProxyConfig::load()?;
    backup.proxy_rules = proxy_config.rules;

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
            format!(
                "Backed up {} rule(s) to {}",
                backup.rules.len(),
                output_file
            )
            .green()
            .bold()
        );
    }

    Ok(())
}
