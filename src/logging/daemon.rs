//! The logging daemon behind `nat-gate log daemon`.
//!
//! Spawns `conntrack -E -e NEW,DESTROY`, classifies each event against the
//! active nat-gate rules, and appends matching events to the JSONL store.
//! Designed to run as a systemd service (`Restart=on-failure`); the process
//! exits non-zero if the conntrack stream dies so systemd restarts it.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::events::{self, EventKind, FlowEvent};
use super::filter::{FlowFilter, MatchRule, PortRange, Verdict};
use super::store::{LogRecord, LogStore};
use crate::backend;

/// How often the rule set is refreshed while running.
const RULE_REFRESH: Duration = Duration::from_secs(60);

/// A live rule snapshot: the filter plus the rule count.
pub struct RuleSnapshot {
    pub filter: FlowFilter,
    pub(crate) count: usize,
}

impl RuleSnapshot {
    /// Load active rules (both families) and the host's local addresses.
    /// Failures on one family degrade to that family being unlogged.
    pub fn load() -> Result<RuleSnapshot, String> {
        let mut rules = Vec::new();
        let mut failures = Vec::new();

        for ipv6 in [false, true] {
            match backend::load_rules(ipv6) {
                Ok(store) => {
                    for rule in store.rules() {
                        let Some(ports) = PortRange::parse(&rule.port) else {
                            continue;
                        };
                        let Ok(target) = rule.target.parse::<IpAddr>() else {
                            continue;
                        };
                        rules.push(MatchRule {
                            proto: rule.proto.clone(),
                            target,
                            ports,
                            marker: rule.marker(),
                        });
                    }
                }
                Err(e) => failures.push(format!("{}: {e}", if ipv6 { "IPv6" } else { "IPv4" })),
            }
        }

        let local_addrs = local_addresses();

        if rules.is_empty() && !failures.is_empty() {
            return Err(format!(
                "No rules could be loaded ({})",
                failures.join("; ")
            ));
        }

        let count = rules.len();
        Ok(RuleSnapshot {
            filter: FlowFilter::new(rules, local_addrs),
            count,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.count
    }
}

/// The host's own addresses, used to tell "arrived at this machine" from
/// "this machine dialed out". Best effort: empty on failure (the filter
/// then simply never emits not_forwarded verdicts).
fn local_addresses() -> std::collections::HashSet<IpAddr> {
    let mut out = std::collections::HashSet::new();
    for family in ["-4", "-6"] {
        if let Ok(output) = Command::new("ip")
            .args(["-o", family, "addr", "show"])
            .output()
        {
            if output.status.success() {
                for tok in String::from_utf8_lossy(&output.stdout).split_whitespace() {
                    // Tokens look like "198.51.100.2/24" — address then mask.
                    if let Some((addr, _mask)) = tok.split_once('/') {
                        if let Ok(ip) = addr.parse::<IpAddr>() {
                            out.insert(ip);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Key identifying a flow for duration tracking.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: String,
    client: String,
}

/// Daemon configuration.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub log_dir: PathBuf,
    pub max_bytes: u64,
    pub keep: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            log_dir: Path::new(super::LOG_DIR).to_path_buf(),
            max_bytes: super::store::DEFAULT_MAX_BYTES,
            keep: super::store::DEFAULT_KEEP,
        }
    }
}

/// Run the logging daemon until the conntrack stream ends or is killed.
pub fn run(cfg: DaemonConfig) -> Result<(), String> {
    let store = LogStore::open(&cfg.log_dir)
        .map_err(|e| format!("Failed to open log store at {}: {e}", cfg.log_dir.display()))?
        .with_rotation(cfg.max_bytes, cfg.keep);

    let mut snapshot = RuleSnapshot::load()?;
    let mut last_refresh = Instant::now();

    let mut child = Command::new("conntrack")
        // -o extended is REQUIRED: the default event format lacks the
        // `ipv4 2 tcp 6` family header that parse_line() expects. Without
        // it, no events parse and nothing is logged.
        .args(["-E", "-e", "NEW,DESTROY", "-o", "extended"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!(
            "Failed to start conntrack: {e}. Is conntrack-tools installed? (apt install conntrack / pacman -S conntrack-tools)"
        ))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "conntrack produced no output stream".to_string())?;
    let reader = BufReader::new(stdout);

    // Flows we logged as NEW, to compute durations at DESTROY time.
    // Bounded by kernel flow limits; entries are removed on DESTROY.
    let mut active: HashMap<FlowKey, SystemTime> = HashMap::new();

    eprintln!(
        "nat-gate logger: watching {} rule(s), log at {}",
        snapshot.rule_count(),
        cfg.log_dir.join(super::LOG_FILE).display()
    );

    let result = stream_events(
        reader,
        &store,
        &mut snapshot,
        &mut active,
        &mut last_refresh,
    );

    let _ = child.kill();
    let _ = child.wait();

    result.map_err(|e| format!("conntrack stream ended: {e}"))
}

type StreamResult = Result<(), String>;

fn stream_events<R: BufRead>(
    reader: R,
    store: &LogStore,
    snapshot: &mut RuleSnapshot,
    active: &mut HashMap<FlowKey, SystemTime>,
    last_refresh: &mut Instant,
) -> StreamResult {
    let mut lines = reader.lines();
    loop {
        // Non-blocking-ish refresh: lines() blocks, so refresh piggybacks on
        // event arrival. A quiet system refreshes rarely, which is fine.
        let line = match lines.next() {
            Some(Ok(l)) => l,
            Some(Err(e)) => return Err(e.to_string()),
            None => return Err("end of stream".to_string()),
        };

        if last_refresh.elapsed() >= RULE_REFRESH {
            if let Ok(snap) = RuleSnapshot::load() {
                *snapshot = snap;
            }
            *last_refresh = Instant::now();
        }

        let Some(event) = events::parse_line(&line) else {
            continue;
        };
        let Some((verdict, rule)) = snapshot.filter.classify(&event) else {
            continue;
        };

        if let Err(e) = handle_event(store, active, &event, verdict, rule) {
            eprintln!("nat-gate logger: failed to write record: {e}");
        }
    }
}

fn handle_event(
    store: &LogStore,
    active: &mut HashMap<FlowKey, SystemTime>,
    event: &FlowEvent,
    verdict: Verdict,
    rule: &MatchRule,
) -> std::io::Result<()> {
    let key = FlowKey {
        proto: event.proto.clone(),
        client: format!("{}:{}", event.original.src, event.original.sport),
    };
    let now = SystemTime::now();

    match event.kind {
        EventKind::New => {
            active.insert(key, now);
            let record = LogRecord {
                ts: now.into(),
                event: "new".to_string(),
                proto: event.proto.clone(),
                client: format!("{}:{}", event.original.src, event.original.sport),
                rule: rule.marker.clone(),
                target: rule.target.to_string(),
                verdict: verdict.as_str().to_string(),
                duration_s: None,
                packets: None,
                bytes: None,
            };
            store.append(&record)
        }
        EventKind::Destroy => {
            let started = active.remove(&key);
            let duration_s = started
                .and_then(|s| now.duration_since(s).ok())
                .map(|d| d.as_secs());
            // Counters: both directions summed.
            let packets = event.original.packets + event.reply.packets;
            let bytes = event.original.bytes + event.reply.bytes;
            let record = LogRecord {
                ts: now.into(),
                event: "end".to_string(),
                proto: event.proto.clone(),
                client: format!("{}:{}", event.original.src, event.original.sport),
                rule: rule.marker.clone(),
                target: rule.target.to_string(),
                verdict: verdict.as_str().to_string(),
                duration_s,
                packets: Some(packets),
                bytes: Some(bytes),
            };
            store.append(&record)
        }
    }
}

/// Snapshot of the current log status for `log status` / `check`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStatus {
    pub log_dir: String,
    pub rules_watched: usize,
    pub current_size_bytes: u64,
    pub rotations_kept: usize,
}

/// Read the daemon's status from disk (no daemon RPC; systemd owns uptime).
pub fn status() -> Result<LogStatus, String> {
    let dir = Path::new(super::LOG_DIR);
    let file = dir.join(super::LOG_FILE);
    let size = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
    let mut rotations = 0;
    for i in 1..=super::store::DEFAULT_KEEP + 1 {
        if dir.join(format!("{}.{i}", super::LOG_FILE)).exists() {
            rotations += 1;
        }
    }
    let rules_watched = backend::load_rules(false)
        .map(|s| s.rule_count())
        .unwrap_or(0)
        + backend::load_rules(true)
            .map(|s| s.rule_count())
            .unwrap_or(0);

    Ok(LogStatus {
        log_dir: dir.display().to_string(),
        rules_watched,
        current_size_bytes: size,
        rotations_kept: rotations,
    })
}

/// Convert a system time to RFC3339 (used by commands for display).
pub fn fmt_ts(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::events::Tuple;
    use crate::logging::store::LogQuery;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Drive the daemon's event handler directly with canned events.
    #[test]
    fn new_then_destroy_logs_duration_and_counters() {
        let dir = std::env::temp_dir().join(format!("nat-gate-daemon-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = LogStore::open(&dir).unwrap();

        let rule = MatchRule {
            proto: "tcp".to_string(),
            target: ip("100.64.0.5"),
            ports: PortRange {
                start: 25565,
                end: 25565,
            },
            marker: "nat-gate:tcp:25565".to_string(),
        };

        let new_event = FlowEvent {
            kind: EventKind::New,
            proto: "tcp".to_string(),
            original: Tuple {
                src: ip("203.0.113.7"),
                dst: ip("198.51.100.2"),
                sport: 52188,
                dport: 25565,
                ..Default::default()
            },
            reply: Tuple {
                src: ip("100.64.0.5"),
                dst: ip("203.0.113.7"),
                sport: 25565,
                dport: 52188,
                ..Default::default()
            },
        };
        handle_event(
            &store,
            &mut HashMap::new(),
            &new_event,
            Verdict::Forwarded,
            &rule,
        )
        .unwrap();

        let mut destroy_event = new_event.clone();
        destroy_event.kind = EventKind::Destroy;
        destroy_event.original.packets = 10;
        destroy_event.original.bytes = 900;
        destroy_event.reply.packets = 8;
        destroy_event.reply.bytes = 700;

        // Duration needs an active entry; simulate by pre-inserting.
        let mut active = HashMap::new();
        active.insert(
            FlowKey {
                proto: "tcp".to_string(),
                client: "203.0.113.7:52188".to_string(),
            },
            SystemTime::now() - Duration::from_secs(65),
        );
        handle_event(
            &store,
            &mut active,
            &destroy_event,
            Verdict::Forwarded,
            &rule,
        )
        .unwrap();

        let records = store.query(&LogQuery::default()).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].event, "new");
        assert_eq!(records[0].event, "end");
        assert_eq!(records[0].packets, Some(18));
        assert_eq!(records[0].bytes, Some(1600));
        let d = records[0].duration_s.expect("duration computed");
        assert!((64..=66).contains(&d), "duration ~65s, got {d}");

        std::fs::remove_dir_all(dir).unwrap();
    }
}
