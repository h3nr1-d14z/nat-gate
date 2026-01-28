use colored::Colorize;
use regex::Regex;
use serde::Serialize;

use crate::iptables::IptablesExecutor;
use crate::output;
use crate::utils::{check_iptables, check_root};

#[derive(Debug, Serialize)]
struct RuleStats {
    proto: String,
    port: String,
    target: String,
    packets: u64,
    bytes: u64,
    #[serde(skip_serializing)]
    bytes_formatted: String,
}

/// Run the stats command to show traffic statistics per rule
pub fn run(ipv6: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    check_iptables()?;

    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };

    // Get rules with statistics
    let rules_output = IptablesExecutor::list_nat_rules(ipv6)?;
    let stats = parse_rule_stats(&rules_output);

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
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "ip_version": ip_version,
                "rules": stats,
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
            .map(|s| s.bytes_formatted.len())
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
                stat.bytes_formatted,
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

/// Parse rule statistics from iptables -L -n -v output
fn parse_rule_stats(iptables_output: &str) -> Vec<RuleStats> {
    let mut stats = Vec::new();
    let mut in_prerouting = false;

    // Use same pattern as list.rs for matching rules - more permissive
    // The packets/bytes are extracted from column positions
    let rule_pattern = Regex::new(
        r"(tcp|udp)\s+dpt[s]?:(\d+(?::\d+)?)\s+/\*\s*nat-gate:(tcp|udp):(\S+)\s*\*/\s+to:([\d.:a-fA-F\[\]]+)",
    )
    .unwrap();

    for line in iptables_output.lines() {
        if line.starts_with("Chain PREROUTING") {
            in_prerouting = true;
            continue;
        } else if line.starts_with("Chain ") {
            in_prerouting = false;
            continue;
        }

        // Only parse PREROUTING rules (to avoid counting twice)
        if !in_prerouting || !line.contains("nat-gate:") {
            continue;
        }

        if let Some(cap) = rule_pattern.captures(line) {
            if let (Some(proto), Some(port), Some(target)) = (
                cap.get(1).map(|m| m.as_str()),
                cap.get(4).map(|m| m.as_str()), // Use port from comment
                cap.get(5).map(|m| m.as_str()),
            ) {
                // Extract packets and bytes from line columns
                // Format: num pkts bytes target prot opt in out source destination ...
                let parts: Vec<&str> = line.split_whitespace().collect();
                let (packets, bytes) = if parts.len() >= 3 {
                    (
                        parse_iptables_number(parts[1]),
                        parse_iptables_number(parts[2]),
                    )
                } else {
                    (0, 0)
                };

                // Extract just the IP from target
                let target_ip = target
                    .rsplit_once(':')
                    .map(|(ip, _)| ip.trim_matches(|c| c == '[' || c == ']'))
                    .unwrap_or(target);

                stats.push(RuleStats {
                    proto: proto.to_string(),
                    port: port.to_string(),
                    target: target_ip.to_string(),
                    packets,
                    bytes,
                    bytes_formatted: format_bytes(bytes),
                });
            }
        }
    }

    stats
}

/// Parse iptables counter format (handles K, M, G suffixes)
fn parse_iptables_number(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }

    let last_char = s.chars().last().unwrap();
    let (num_str, multiplier) = match last_char {
        'K' => (&s[..s.len() - 1], 1_000u64),
        'M' => (&s[..s.len() - 1], 1_000_000u64),
        'G' => (&s[..s.len() - 1], 1_000_000_000u64),
        _ => (s, 1u64),
    };

    num_str.parse::<u64>().unwrap_or(0) * multiplier
}

/// Format a number with thousand separators
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }

    result
}

/// Format bytes in human-readable form
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iptables_number() {
        assert_eq!(parse_iptables_number("0"), 0);
        assert_eq!(parse_iptables_number("1234"), 1234);
        assert_eq!(parse_iptables_number("5K"), 5000);
        assert_eq!(parse_iptables_number("10M"), 10_000_000);
        assert_eq!(parse_iptables_number("2G"), 2_000_000_000);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(100), "100");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1234567), "1,234,567");
    }

    #[test]
    fn test_parse_rule_stats() {
        let output = r#"Chain PREROUTING (policy ACCEPT 100 packets, 50000 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1     1234 56789 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 /* nat-gate:tcp:443 */ to:100.64.0.5:443
2      567 128K DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 /* nat-gate:tcp:80 */ to:100.64.0.5:80
3        0     0 DNAT       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:51820 /* nat-gate:udp:51820 */ to:100.64.0.10:51820

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1     1234 56789 MASQUERADE  tcp  --  *      *       0.0.0.0/0            100.64.0.5           tcp dpt:443 /* nat-gate:tcp:443 */
"#;

        let stats = parse_rule_stats(output);
        assert_eq!(stats.len(), 3);

        assert_eq!(stats[0].proto, "tcp");
        assert_eq!(stats[0].port, "443");
        assert_eq!(stats[0].target, "100.64.0.5");
        assert_eq!(stats[0].packets, 1234);
        assert_eq!(stats[0].bytes, 56789);

        assert_eq!(stats[1].packets, 567);
        assert_eq!(stats[1].bytes, 128000); // 128K

        assert_eq!(stats[2].packets, 0);
        assert_eq!(stats[2].bytes, 0);
    }
}
