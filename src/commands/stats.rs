use colored::Colorize;
use serde::Serialize;

use crate::backend;
use crate::output;
use crate::utils::{check_root, format_bytes, format_number};

#[derive(Debug, Serialize)]
struct RuleStatsJson {
    proto: String,
    port: String,
    target: String,
    packets: u64,
    bytes: u64,
}

impl From<&crate::iptables::rulestore::RuleStats> for RuleStatsJson {
    fn from(s: &crate::iptables::rulestore::RuleStats) -> Self {
        RuleStatsJson {
            proto: s.proto.clone(),
            port: s.port.clone(),
            target: s.target.clone(),
            packets: s.packets,
            bytes: s.bytes,
        }
    }
}

/// Run the stats command to show traffic statistics per rule
pub fn run(ipv6: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    backend::check_dependencies()?;

    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };

    // Get rules with statistics (exact counters from iptables-save -c)
    let store = backend::load_rules(ipv6)?;
    let stats = store.stats();

    if stats.is_empty() {
        if json_output {
            output::print_value(serde_json::json!({
                "success": true,
                "data": {
                    "ip_version": ip_version,
                    "rules": [],
                    "count": 0,
                    "total_packets": 0,
                    "total_bytes": 0
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

    // Calculate totals
    let total_packets: u64 = stats.iter().map(|s| s.packets).sum();
    let total_bytes: u64 = stats.iter().map(|s| s.bytes).sum();

    if json_output {
        let rules: Vec<RuleStatsJson> = stats.iter().map(RuleStatsJson::from).collect();
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "ip_version": ip_version,
                "rules": rules,
                "count": stats.len(),
                "total_packets": total_packets,
                "total_bytes": total_bytes
            }
        }));
    } else {
        println!(
            "{}",
            format!("Rule Statistics ({ip_version}):").blue().bold()
        );
        println!();

        // Determine column widths
        let port_width = stats.iter().map(|s| s.port.len()).max().unwrap_or(5).max(5);
        let target_width = stats
            .iter()
            .map(|s| s.target.len())
            .max()
            .unwrap_or(12)
            .max(12);
        let packets_width = stats
            .iter()
            .map(|s| format_number(s.packets).len())
            .max()
            .unwrap_or(8)
            .max(8);
        let bytes_width = stats
            .iter()
            .map(|s| format_bytes(s.bytes).len())
            .max()
            .unwrap_or(8)
            .max(8);

        // Table header
        let port_w = port_width + 4;
        let target_w = target_width + 4;
        let packets_w = packets_width + 2;
        let bytes_w = bytes_width + 2;
        let header_line = format!(
            "{:^10}{:^port_w$}{:<target_w$}{:>packets_w$}{:>bytes_w$}",
            "Protocol", "Port", "Target", "Packets", "Bytes"
        );

        let total_width =
            10 + port_width + 4 + target_width + 4 + packets_width + 2 + bytes_width + 2;
        let separator = "-".repeat(total_width);

        println!("{separator}");
        println!("{}", header_line.bold());
        println!("{separator}");

        // Table rows
        for stat in &stats {
            println!(
                "{:^10}{:^width1$}{:<width2$}{:>width3$}{:>width4$}",
                stat.proto,
                stat.port,
                stat.target,
                format_number(stat.packets),
                format_bytes(stat.bytes),
                width1 = port_width + 4,
                width2 = target_width + 4,
                width3 = packets_width + 2,
                width4 = bytes_width + 2,
            );
        }

        println!("{separator}");

        // Totals row
        println!(
            "{:^10}{:^width1$}{:<width2$}{:>width3$}{:>width4$}",
            "TOTAL".bold(),
            "",
            "",
            format_number(total_packets).green(),
            format_bytes(total_bytes).green(),
            width1 = port_width + 4,
            width2 = target_width + 4,
            width3 = packets_width + 2,
            width4 = bytes_width + 2,
        );

        println!();
        println!(
            "Total: {} rule(s), {} packets, {}",
            stats.len().to_string().green(),
            format_number(total_packets).green(),
            format_bytes(total_bytes).green()
        );
    }

    Ok(())
}
