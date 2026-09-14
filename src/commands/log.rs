//! `nat-gate log` — query the connection log and run the logging daemon.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Local, NaiveDate, TimeZone, Utc};
use colored::Colorize;

use crate::logging::daemon::{self, DaemonConfig};
use crate::logging::store::{ClientAgg, LogQuery, LogStore, RollupRow};
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

/// `nat-gate log rollup` — daily per-rule traffic summaries derived from
/// completed connection log sessions. Aggregates `end` records by calendar
/// day (in the host's local timezone) and rule marker; `days` bounds how
/// far back to look (default 7). Empty input prints a friendly hint
/// instead of an empty table, mirroring `log show`.
pub fn rollup(days: Option<u32>, dir: Option<String>, json_output: bool) -> Result<(), String> {
    let n = days.unwrap_or(7);
    let since = Some(Duration::from_secs(u64::from(n) * 86_400));

    let log_dir = dir.as_deref().unwrap_or(crate::logging::LOG_DIR);
    let store = LogStore::open(Path::new(log_dir))
        .map_err(|e| format!("No connection log found at {log_dir}: {e}"))?;

    let rows = store
        .rollup(since, end_record_local_day)
        .map_err(|e| format!("Failed to read log: {e}"))?;

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "days": group_rows_by_day(&rows),
                "count": rows.len()
            }
        }));
        return Ok(());
    }

    if rows.is_empty() {
        println!("{}", "No completed sessions to roll up.".yellow());
        println!(
            "Logging is enabled by running: {} (see README for the systemd service)",
            "nat-gate service install --with-logging".cyan()
        );
        return Ok(());
    }

    println!(
        "{}",
        format!("Daily traffic rollup (last {n} day(s)):")
            .blue()
            .bold()
    );
    println!();
    println!(
        "  {:<12} {:<28} {:>11} {:>12} {:>12} {:>11}",
        "Date", "Rule", "Conns", "Bytes", "Packets", "Duration"
    );
    println!("  {}", "-".repeat(90));

    let mut last_day: Option<NaiveDate> = None;
    let mut day_conns: u64 = 0;
    let mut day_bytes: u64 = 0;
    let mut day_packets: u64 = 0;
    let mut day_duration: u64 = 0;

    for r in &rows {
        if last_day != Some(r.day) {
            if last_day.is_some() {
                print_day_subtotal(day_conns, day_bytes, day_packets, day_duration);
            }
            last_day = Some(r.day);
            day_conns = 0;
            day_bytes = 0;
            day_packets = 0;
            day_duration = 0;
        }
        day_conns += r.connections;
        day_bytes += r.bytes;
        day_packets += r.packets;
        day_duration += r.duration_s;

        let label = if r.day == today_local() {
            r.day.to_string().green()
        } else {
            r.day.to_string().normal()
        };
        println!(
            "  {:<12} {:<28} {:>11} {:>12} {:>12} {:>11}",
            label,
            r.rule,
            crate::utils::format_number(r.connections),
            crate::utils::format_bytes(r.bytes),
            crate::utils::format_number(r.packets),
            crate::utils::format_number(r.duration_s)
        );
    }
    if last_day.is_some() {
        print_day_subtotal(day_conns, day_bytes, day_packets, day_duration);
    }

    Ok(())
}

/// Bucket a UTC timestamp into the local calendar day. `Local` knows the
/// host timezone + DST, so the YYYY-MM-DD the user sees matches their wall
/// clock. The store stays pure-UTC; this closure performs the translation.
fn end_record_local_day(ts: &DateTime<Utc>) -> NaiveDate {
    Local.from_utc_datetime(&ts.naive_utc()).date_naive()
}

/// Local calendar date for "today", for highlighting the current day.
fn today_local() -> NaiveDate {
    Local::now().date_naive()
}

/// Print a dimmed subtotal line at the end of each day's rows.
fn print_day_subtotal(conns: u64, bytes: u64, packets: u64, duration: u64) {
    let secs = if duration >= 3600 {
        format!("{}h{}m", duration / 3600, (duration % 3600) / 60)
    } else if duration >= 60 {
        format!("{}m", duration / 60)
    } else {
        format!("{}s", duration)
    };
    println!(
        "  {:<12} {:<28} {:>11} {:>12} {:>12} {:>11}",
        "".to_string().dimmed(),
        "day total".dimmed(),
        crate::utils::format_number(conns).dimmed(),
        crate::utils::format_bytes(bytes).dimmed(),
        crate::utils::format_number(packets).dimmed(),
        secs.dimmed()
    );
}

/// Shape the flat per-rule rows into the nested JSON structure.
fn group_rows_by_day(rows: &[RollupRow]) -> Vec<serde_json::Value> {
    use serde_json::json;
    let mut days: Vec<serde_json::Value> = Vec::new();
    let mut current_day: Option<NaiveDate> = None;
    let mut current_rules: Vec<serde_json::Value> = Vec::new();

    for r in rows {
        if current_day != Some(r.day) {
            if let Some(d) = current_day {
                days.push(json!({
                    "date": d.to_string(),
                    "rules": std::mem::take(&mut current_rules),
                }));
            }
            current_day = Some(r.day);
        }
        current_rules.push(json!({
            "rule": r.rule,
            "connections": r.connections,
            "bytes": r.bytes,
            "packets": r.packets,
            "duration_s": r.duration_s,
        }));
    }
    if let Some(d) = current_day {
        days.push(json!({
            "date": d.to_string(),
            "rules": current_rules,
        }));
    }
    days
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

    use crate::logging::store::RollupRow;
    use chrono::NaiveDate;

    fn row(day: &str, rule: &str, conns: u64, bytes: u64) -> RollupRow {
        RollupRow {
            day: NaiveDate::parse_from_str(day, "%Y-%m-%d").unwrap(),
            rule: rule.to_string(),
            connections: conns,
            bytes,
            packets: conns * 100,
            duration_s: conns * 120,
        }
    }

    #[test]
    fn group_rows_by_day_shapes_nested_json() {
        // Already day-descending then rule-ascending, as the store returns.
        let rows = vec![
            row("2026-09-14", "nat-gate:tcp:25565", 1, 7000),
            row("2026-09-13", "nat-gate:tcp:25565", 2, 3000),
            row("2026-09-13", "nat-gate:udp:19132", 1, 500),
        ];
        let days = group_rows_by_day(&rows);
        assert_eq!(days.len(), 2);
        assert_eq!(days[0]["date"], "2026-09-14");
        assert_eq!(days[0]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(days[0]["rules"][0]["rule"], "nat-gate:tcp:25565");
        assert_eq!(days[1]["date"], "2026-09-13");
        assert_eq!(
            days[1]["rules"].as_array().unwrap().len(),
            2,
            "two rules nested under one day"
        );
        assert_eq!(days[1]["rules"][0]["bytes"], 3000);
        assert_eq!(days[1]["rules"][1]["rule"], "nat-gate:udp:19132");
    }

    #[test]
    fn group_rows_by_day_empty_is_empty() {
        let days = group_rows_by_day(&[]);
        assert!(days.is_empty());
    }

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
