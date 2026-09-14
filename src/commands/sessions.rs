//! `nat-gate sessions` — live flows currently being forwarded.

use std::process::{Command, Stdio};

use colored::Colorize;

use crate::logging::daemon::RuleSnapshot;
use crate::logging::events;
use crate::output;

/// A live forwarded session for display.
#[derive(Debug, serde::Serialize)]
pub struct LiveSession {
    pub proto: String,
    pub client: String,
    pub target: String,
    pub port: u16,
    /// Packets, both directions
    pub packets: u64,
    /// Bytes, both directions
    pub bytes: u64,
}

pub fn run(json_output: bool) -> Result<(), String> {
    // Snapshot of active rules decides what counts as a nat-gate flow.
    let snapshot = RuleSnapshot::load()?;

    let output_result = Command::new("conntrack")
        .args(["-L", "-o", "extended"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!(
            "Failed to run conntrack: {e}. Is conntrack-tools installed? (apt install conntrack / pacman -S conntrack-tools)"
        ))?;

    if !output_result.status.success() {
        return Err(format!(
            "conntrack -L failed: {}",
            String::from_utf8_lossy(&output_result.stderr)
        ));
    }

    let text = String::from_utf8_lossy(&output_result.stdout);
    let mut sessions = Vec::new();

    for line in text.lines() {
        let Some(ev) = events::parse_line(line) else {
            continue;
        };
        let Some((verdict, rule)) = snapshot.filter.classify(&ev) else {
            continue;
        };
        if verdict != crate::logging::filter::Verdict::Forwarded {
            continue; // live listings show actual forwarded traffic
        }
        sessions.push(LiveSession {
            proto: ev.proto.clone(),
            client: format!("{}:{}", ev.original.src, ev.original.sport),
            target: rule.target.to_string(),
            port: ev.reply.sport,
            packets: ev.original.packets + ev.reply.packets,
            bytes: ev.original.bytes + ev.reply.bytes,
        });
    }

    sessions.sort_by_key(|s| std::cmp::Reverse(s.bytes));

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "sessions": sessions,
                "count": sessions.len()
            }
        }));
        return Ok(());
    }

    if sessions.is_empty() {
        println!("{}", "No active forwarded sessions.".yellow());
        return Ok(());
    }

    println!(
        "{}",
        format!("Active sessions ({}):", sessions.len())
            .blue()
            .bold()
    );
    println!();
    println!(
        "  {:<6} {:<26} {:<24} {:<8} {:>12} {:>12}",
        "Proto", "Client", "Target", "Port", "Packets", "Bytes"
    );
    println!("  {}", "-".repeat(96));
    for s in &sessions {
        println!(
            "  {:<6} {:<26} {:<24} {:<8} {:>12} {:>12}",
            s.proto.to_uppercase(),
            truncate(&s.client, 26),
            truncate(&s.target, 24),
            s.port,
            crate::utils::format_number(s.packets),
            crate::utils::format_bytes(s.bytes),
        );
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    crate::utils::truncate_string(s, max)
}
