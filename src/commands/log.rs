//! `nat-gate log` — query the connection log and run the logging daemon.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use colored::Colorize;

use crate::logging::daemon::{self, DaemonConfig};
use crate::logging::store::{ClientAgg, LogQuery, LogStore};
use crate::output;

/// Parse a human duration: "30m", "24h", "7d", plain seconds if unitless.
fn parse_since(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len()));
    let n: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("Invalid duration '{s}': expected a number"))?;
    let secs = match unit {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => n,
        "m" | "min" | "mins" | "minute" | "minutes" => n * 60.0,
        "h" | "hour" | "hours" => n * 3600.0,
        "d" | "day" | "days" => n * 86400.0,
        "w" | "week" | "weeks" => n * 604800.0,
        _ => return Err(format!("Unknown time unit '{unit}' in '{s}'")),
    };
    Ok(Duration::from_secs_f64(secs))
}

/// Raw filter values from the CLI, parsed into a LogQuery.
pub struct ShowFilters {
    pub since: Option<String>,
    pub client: Option<String>,
    pub port: Option<u16>,
    pub rule: Option<String>,
    pub event: Option<String>,
    pub limit: Option<usize>,
}

pub fn show(filters: ShowFilters, dir: Option<String>, json_output: bool) -> Result<(), String> {
    let since = filters.since.map(|s| parse_since(&s)).transpose()?;
    let client_ip = filters
        .client
        .map(|c| {
            c.parse::<IpAddr>()
                .map_err(|_| format!("Invalid client IP '{c}'"))
        })
        .transpose()?;

    let log_dir = dir.as_deref().unwrap_or(crate::logging::LOG_DIR);
    let store = LogStore::open(Path::new(log_dir))
        .map_err(|e| format!("No connection log found at {log_dir}: {e}"))?;

    let query = LogQuery {
        since,
        client: client_ip,
        port: filters.port,
        rule: filters.rule,
        event: filters.event,
        limit: filters.limit,
    };
    let records = store
        .query(&query)
        .map_err(|e| format!("Failed to read log: {e}"))?;

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "records": records,
                "count": records.len()
            }
        }));
        return Ok(());
    }

    if records.is_empty() {
        println!("{}", "No matching connection records.".yellow());
        println!(
            "Logging is enabled by running: {} (see README for the systemd service)",
            "nat-gate service install --with-logging".cyan()
        );
        return Ok(());
    }

    println!("{}", "Connection log (most recent first):".blue().bold());
    println!();
    for r in &records {
        let ts = daemon::fmt_ts(&r.ts);
        let event = if r.event == "new" {
            "CONNECT".green()
        } else {
            "DISCONN".dimmed()
        };
        let verdict = if r.verdict == "forwarded" {
            r.verdict.green()
        } else {
            r.verdict.yellow()
        };
        let extra = if r.event == "end" {
            format!(
                "  {} {} {}",
                format!("{}s", r.duration_s.unwrap_or(0)).dimmed(),
                format!("{} pkts", r.packets.unwrap_or(0)).dimmed(),
                crate::utils::format_bytes(r.bytes.unwrap_or(0)).dimmed()
            )
        } else {
            String::new()
        };
        println!(
            "  {ts}  {event}  {}  {} -> {}  [{verdict}]{extra}",
            r.client,
            r.proto.to_uppercase(),
            r.target
        );
    }
    println!();
    println!("Total: {} record(s)", records.len().to_string().green());
    Ok(())
}

pub fn top(
    since: Option<String>,
    clients: Option<usize>,
    dir: Option<String>,
    json_output: bool,
) -> Result<(), String> {
    let since = since.map(|s| parse_since(&s)).transpose()?;

    let log_dir = dir.as_deref().unwrap_or(crate::logging::LOG_DIR);
    let store = LogStore::open(Path::new(log_dir))
        .map_err(|e| format!("No connection log found at {log_dir}: {e}"))?;

    let agg = store
        .top_clients(since)
        .map_err(|e| format!("Failed to read log: {e}"))?;

    let n = clients.unwrap_or(10);

    if json_output {
        let top_n: Vec<&ClientAgg> = agg.iter().take(n).collect();
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "clients": top_n.into_iter().map(|a| serde_json::json!({
                    "client": a.client,
                    "sessions": a.sessions,
                    "packets": a.packets,
                    "bytes": a.bytes,
                    "last_seen": daemon::fmt_ts(&a.last_seen),
                })).collect::<Vec<_>>(),
                "count": agg.len().min(n)
            }
        }));
        return Ok(());
    }

    if agg.is_empty() {
        println!("{}", "No aggregated client traffic found.".yellow());
        return Ok(());
    }

    println!(
        "{}",
        "Top clients by traffic (completed sessions):".blue().bold()
    );
    println!();
    println!(
        "  {:<40} {:>10} {:>12} {:>12}  Last seen",
        "Client", "Sessions", "Packets", "Bytes"
    );
    println!("  {}", "-".repeat(90));
    for a in agg.iter().take(n) {
        println!(
            "  {:<40} {:>10} {:>12} {:>12}  {}",
            a.client,
            a.sessions,
            crate::utils::format_number(a.packets),
            crate::utils::format_bytes(a.bytes),
            daemon::fmt_ts(&a.last_seen)
        );
    }
    Ok(())
}

pub fn run_daemon(
    log_dir: Option<String>,
    max_bytes: Option<u64>,
    keep: Option<usize>,
) -> Result<(), String> {
    let mut cfg = DaemonConfig::default();
    if let Some(dir) = log_dir {
        cfg.log_dir = dir.into();
    }
    if let Some(max) = max_bytes {
        cfg.max_bytes = max;
    }
    if let Some(k) = keep {
        cfg.keep = k;
    }
    daemon::run(cfg)
}

pub fn show_status(json_output: bool) -> Result<(), String> {
    let status = daemon::status()?;

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": status
        }));
        return Ok(());
    }

    println!("{}", "nat-gate Connection Logging:".blue().bold());
    println!("  Log directory:  {}", status.log_dir);
    println!("  Rules watched:  {}", status.rules_watched);
    println!(
        "  Current file:   {} ({})",
        crate::logging::LOG_FILE,
        crate::utils::format_bytes(status.current_size_bytes)
    );
    println!("  Rotated files:  {}", status.rotations_kept);
    println!();
    println!(
        "  Daemon: run {} to see systemd unit state",
        "systemctl status nat-gate-logger".cyan()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_since() {
        assert_eq!(parse_since("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_since("24h").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_since("7d").unwrap(), Duration::from_secs(604800));
        assert_eq!(parse_since("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_since("2w").unwrap(), Duration::from_secs(1209600));
        assert!(parse_since("abc").is_err());
        assert!(parse_since("5fortnights").is_err());
    }
}
