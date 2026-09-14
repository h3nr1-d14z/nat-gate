//! `nat-gate sessions` — live flows currently being forwarded.

use std::process::{Command, Stdio};

use colored::Colorize;

use crate::logging::daemon::RuleSnapshot;
use crate::logging::events;
use crate::logging::filter::Verdict;
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

/// Parse conntrack `-L -o extended` output, classify each flow against the
/// active rule snapshot, and collect the forwarded sessions. Pure: no I/O,
/// no printing, unsorted (callers sort as needed).
pub fn collect(snapshot: &RuleSnapshot, conntrack_output: &str) -> Vec<LiveSession> {
    let mut sessions = Vec::new();

    for line in conntrack_output.lines() {
        let Some(ev) = events::parse_line(line) else {
            continue;
        };
        let Some((verdict, rule)) = snapshot.filter.classify(&ev) else {
            continue;
        };
        if verdict != Verdict::Forwarded {
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

    sessions
}

/// Load the rule snapshot, spawn `conntrack -L -o extended`, and return the
/// forwarded sessions. Sessions are sorted by bytes descending — the same
/// order the CLI and the TUI display.
pub fn fetch_live() -> Result<Vec<LiveSession>, String> {
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
    let mut sessions = collect(&snapshot, &text);
    sort_by_bytes(&mut sessions);
    Ok(sessions)
}

/// Sort sessions by bytes, descending (most traffic first).
fn sort_by_bytes(sessions: &mut [LiveSession]) {
    sessions.sort_by_key(|s| std::cmp::Reverse(s.bytes));
}

pub fn run(json_output: bool) -> Result<(), String> {
    let sessions = fetch_live()?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::filter::{FlowFilter, MatchRule, PortRange};
    use std::collections::HashSet;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Build a snapshot with one tcp rule: target 100.64.0.5, port 25565.
    fn snapshot_tcp_25565() -> RuleSnapshot {
        let rule = MatchRule {
            proto: "tcp".to_string(),
            target: ip("100.64.0.5"),
            ports: PortRange {
                start: 25565,
                end: 25565,
            },
            marker: "nat-gate:tcp:25565".to_string(),
        };
        let local_addrs: HashSet<IpAddr> = [ip("198.51.100.2")].into_iter().collect();
        RuleSnapshot {
            filter: FlowFilter::new(vec![rule], local_addrs),
            count: 1,
        }
    }

    #[test]
    fn collect_filters_forwarded_and_assembles_fields() {
        let snapshot = snapshot_tcp_25565();
        let conntrack_output = "\
ipv4 2 tcp 6 431999 ESTABLISHED src=203.0.113.7 dst=198.51.100.2 sport=52188 dport=25565 packets=10 bytes=900 src=100.64.0.5 dst=203.0.113.7 sport=25565 dport=52188 packets=8 bytes=700 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=203.0.113.9 dst=198.51.100.2 sport=40001 dport=25565 packets=40 bytes=3600 src=100.64.0.5 dst=203.0.113.9 sport=25565 dport=40001 packets=38 bytes=3400
ipv4 2 tcp 6 431999 ESTABLISHED src=203.0.113.7 dst=198.51.100.2 sport=50099 dport=22 src=198.51.100.2 dst=203.0.113.7 sport=22 dport=50099 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=203.0.113.7 dst=198.51.100.2 sport=50000 dport=25565 src=100.64.0.99 dst=203.0.113.7 sport=25565 dport=50000";

        let mut sessions = collect(&snapshot, conntrack_output);
        sort_by_bytes(&mut sessions);

        // Line 1 and line 2 are forwarded (reply.src == 100.64.0.5 on port 25565).
        // Line 3 is a local SSH connection — no DNAT (reply.src == original.dst), so NotForwarded → filtered out.
        // Line 4 is DNAT'd but reply.src (100.64.0.99) matches no rule → classified None → filtered out.
        assert_eq!(sessions.len(), 2);

        // Sorted by bytes descending: line2 (7000) before line1 (1600).
        assert_eq!(sessions[0].client, "203.0.113.9:40001");
        assert_eq!(sessions[0].target, "100.64.0.5");
        assert_eq!(sessions[0].port, 25565);
        assert_eq!(sessions[0].proto, "tcp");
        assert_eq!(sessions[0].packets, 78); // 40 + 38
        assert_eq!(sessions[0].bytes, 7000); // 3600 + 3400

        assert_eq!(sessions[1].client, "203.0.113.7:52188");
        assert_eq!(sessions[1].packets, 18); // 10 + 8
        assert_eq!(sessions[1].bytes, 1600); // 900 + 700
    }

    #[test]
    fn collect_returns_empty_for_garbage() {
        let snapshot = snapshot_tcp_25565();
        let garbage = "\
this is not conntrack output
random noise
conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.

";
        let sessions = collect(&snapshot, garbage);
        assert!(sessions.is_empty());
    }

    #[test]
    fn collect_returns_empty_for_unparseable_lines() {
        let snapshot = snapshot_tcp_25565();
        // Lines without the ipv4/ipv6 extended-format header are rejected.
        let bad = "tcp      6 431999 ESTABLISHED src=203.0.113.7 dst=198.51.100.2 sport=52188 dport=25565";
        let sessions = collect(&snapshot, bad);
        assert!(sessions.is_empty());
    }
}
