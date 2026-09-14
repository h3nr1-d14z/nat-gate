//! Append-only JSONL connection log with size-based rotation.
//!
//! Layout: `<dir>/connections.jsonl` plus up to `keep` rotated files
//! (`.1` … `.N`, newest first). One JSON object per line.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Default rotation threshold: 10 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Default number of rotated files to keep.
pub const DEFAULT_KEEP: usize = 5;

/// One logged connection event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    /// RFC 3339 timestamp of when the event was observed
    pub ts: DateTime<Utc>,
    /// "new" or "end"
    pub event: String,
    /// "tcp" or "udp"
    pub proto: String,
    /// Client address that initiated the flow
    pub client: String,
    /// Rule marker, e.g. "nat-gate:tcp:25565"
    pub rule: String,
    /// Target the flow was (or would have been) forwarded to
    pub target: String,
    /// "forwarded" or "not_forwarded"
    pub verdict: String,
    /// Session duration in seconds (end events only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_s: Option<u64>,
    /// Total packets both directions (end events only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
    /// Total bytes both directions (end events only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// Query filters for reading the log.
#[derive(Debug, Clone, Default)]
pub struct LogQuery {
    /// Only records newer than this age
    pub since: Option<Duration>,
    /// Only records involving this client
    pub client: Option<IpAddr>,
    /// Only records on this forwarded port
    pub port: Option<u16>,
    /// Only records for this rule marker
    pub rule: Option<String>,
    /// Only this event type ("new"/"end")
    pub event: Option<String>,
    /// Maximum number of records to return (most recent first)
    pub limit: Option<usize>,
}

/// Aggregated stats for one client (for `log top`).
#[derive(Debug, Clone, Default)]
pub struct ClientAgg {
    pub client: String,
    pub sessions: u64,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: DateTime<Utc>,
}

/// One row of a daily per-rule traffic rollup (for `log rollup`).
///
/// `day` is the calendar day of the record's timestamp as the caller
/// localizes it; all counters come from `end` records, which carry
/// session totals.
#[derive(Debug, Clone)]
pub struct RollupRow {
    /// Calendar day of the record's timestamp (caller-localized)
    pub day: NaiveDate,
    pub rule: String,
    pub connections: u64,
    pub bytes: u64,
    pub packets: u64,
    pub duration_s: u64,
}

/// The JSONL store.
pub struct LogStore {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
}

impl LogStore {
    /// Store at the given directory with default rotation settings.
    pub fn open(dir: &Path) -> std::io::Result<LogStore> {
        fs::create_dir_all(dir)?;
        Ok(LogStore {
            path: dir.join(super::LOG_FILE),
            max_bytes: DEFAULT_MAX_BYTES,
            keep: DEFAULT_KEEP,
        })
    }

    /// Override rotation settings.
    pub fn with_rotation(mut self, max_bytes: u64, keep: usize) -> Self {
        self.max_bytes = max_bytes;
        self.keep = keep;
        self
    }

    /// Append one record, rotating first if the file has grown past the
    /// threshold. Each line is flushed on write so a kill -9 never loses
    /// more than the event being written.
    pub fn append(&self, record: &LogRecord) -> std::io::Result<()> {
        self.rotate_if_needed()?;

        let line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut w = BufWriter::new(file);
        writeln!(w, "{line}")?;
        w.flush()
    }

    fn rotate_if_needed(&self) -> std::io::Result<()> {
        let Ok(meta) = fs::metadata(&self.path) else {
            return Ok(());
        };
        if meta.len() < self.max_bytes {
            return Ok(());
        }
        // Shift .(N-1) -> .N ... .1 -> .2, then main -> .1. Each rename
        // overwrites its destination, so the old .{keep} file — the oldest
        // data — is dropped as .{keep-1} takes its place.
        for i in (1..self.keep).rev() {
            let from = self.rotated(i);
            let to = self.rotated(i + 1);
            if from.exists() {
                fs::rename(&from, &to)?;
            }
        }
        fs::rename(&self.path, self.rotated(1))?;
        Ok(())
    }

    fn rotated(&self, n: usize) -> PathBuf {
        let mut s = self.path.as_os_str().to_owned();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    /// Read records matching the query, most recent first across the
    /// current file and its rotations. Skips unparseable lines (a torn
    /// final line after a crash must not kill the reader).
    pub fn query(&self, q: &LogQuery) -> std::io::Result<Vec<LogRecord>> {
        let cutoff = q
            .since
            .and_then(|d| SystemTime::now().checked_sub(d))
            .map(DateTime::<Utc>::from);

        let mut out: Vec<LogRecord> = Vec::new();
        let limit = q.limit.unwrap_or(usize::MAX);

        // Current file first (newest), then .1, .2, … Only files that
        // exist are scanned — a brand-new store that has never been
        // appended to has no current file yet, and `query`/`top`/`rollup`
        // should read as empty rather than error (mirrors `log show`'s
        // friendly empty-log message in the command layer).
        let mut files = vec![self.path.clone()];
        for i in 1..=self.keep {
            let p = self.rotated(i);
            if p.exists() {
                files.push(p);
            }
        }
        files.retain(|p| p.exists());

        // Files are scanned newest-first; within a file records are
        // chronological (oldest first). Collect each file's matches, then
        // take from its tail so `limit` selects the NEWEST records.
        for path in files {
            if out.len() >= limit {
                break;
            }
            let mut file_matches: Vec<LogRecord> = Vec::new();
            let file = File::open(&path)?;
            for line in BufReader::new(file).lines() {
                let Ok(line) = line else { continue };
                let Ok(rec) = serde_json::from_str::<LogRecord>(&line) else {
                    continue;
                };
                if let Some(c) = cutoff {
                    if rec.ts < c {
                        continue;
                    }
                }
                if let Some(client) = &q.client {
                    if !rec.client.starts_with(&format!("{client}:"))
                        && !rec.client.starts_with(&format!("[{client}]"))
                        && rec.client != client.to_string()
                    {
                        continue;
                    }
                }
                if let Some(port) = q.port {
                    if !rule_covers_port(&rec.rule, port) {
                        continue;
                    }
                }
                if let Some(rule) = &q.rule {
                    if &rec.rule != rule {
                        continue;
                    }
                }
                if let Some(ev) = &q.event {
                    if &rec.event != ev {
                        continue;
                    }
                }
                file_matches.push(rec);
            }

            // Newest-first from this file, up to the remaining limit.
            let remaining = limit - out.len();
            let take_from = file_matches.len().saturating_sub(remaining);
            out.extend(file_matches[take_from..].iter().rev().cloned());
        }

        Ok(out)
    }

    /// Aggregate per-client statistics for `log top`, newest records last.
    pub fn top_clients(&self, since: Option<Duration>) -> std::io::Result<Vec<ClientAgg>> {
        let q = LogQuery {
            since,
            event: Some("end".to_string()),
            ..Default::default()
        };
        let records = self.query(&q)?;

        let mut agg: std::collections::HashMap<String, ClientAgg> =
            std::collections::HashMap::new();
        for rec in records {
            let client_ip = rec
                .client
                .rsplit_once(':')
                .map(|(ip, _)| ip.trim_matches(|c| c == '[' || c == ']'))
                .unwrap_or(&rec.client)
                .to_string();
            let entry = agg.entry(client_ip.clone()).or_insert_with(|| ClientAgg {
                client: client_ip,
                ..Default::default()
            });
            entry.sessions += 1;
            entry.packets += rec.packets.unwrap_or(0);
            entry.bytes += rec.bytes.unwrap_or(0);
            if rec.ts > entry.last_seen {
                entry.last_seen = rec.ts;
            }
        }

        let mut list: Vec<ClientAgg> = agg.into_values().collect();
        list.sort_by_key(|a| std::cmp::Reverse(a.bytes));
        Ok(list)
    }

    /// Aggregate daily per-rule traffic from completed sessions.
    ///
    /// Reads only `end` records — those carry `duration_s`/`packets`/`bytes`
    /// — using the same query path (and rotation handling) as
    /// [`LogStore::top_clients`]. `since`, when given, is a hard age cutoff.
    /// Records are grouped into calendar days by `to_day`, which lets the
    /// caller localize the bucket (the command passes a UTC→local-day
    /// conversion; tests pass a UTC or fixed-offset one).
    ///
    /// Rows are sorted by day (most recent first), then rule marker
    /// (ascending) for deterministic output.
    pub fn rollup<F>(&self, since: Option<Duration>, to_day: F) -> std::io::Result<Vec<RollupRow>>
    where
        F: Fn(&DateTime<Utc>) -> NaiveDate,
    {
        let q = LogQuery {
            since,
            event: Some("end".to_string()),
            ..Default::default()
        };
        let records = self.query(&q)?;

        // (day, rule) -> running totals. A HashMap is unordered; we impose
        // a stable sort below.
        let mut agg: std::collections::HashMap<(NaiveDate, String), RollupRow> =
            std::collections::HashMap::new();
        for rec in records {
            let day = to_day(&rec.ts);
            let key = (day, rec.rule.clone());
            let entry = agg.entry(key.clone()).or_insert_with(|| RollupRow {
                day,
                rule: rec.rule.clone(),
                connections: 0,
                bytes: 0,
                packets: 0,
                duration_s: 0,
            });
            entry.connections += 1;
            entry.bytes += rec.bytes.unwrap_or(0);
            entry.packets += rec.packets.unwrap_or(0);
            entry.duration_s += rec.duration_s.unwrap_or(0);
        }

        let mut list: Vec<RollupRow> = agg.into_values().collect();
        // Most recent day first; within a day, rule marker ascending so a
        // reader scanning the table sees a stable order across runs.
        list.sort_by(|a, b| b.day.cmp(&a.day).then_with(|| a.rule.cmp(&b.rule)));
        Ok(list)
    }
}

/// True if a rule marker ("nat-gate:tcp:443" / "nat-gate:tcp:8000-8080")
/// covers the given port.
fn rule_covers_port(rule: &str, port: u16) -> bool {
    let Some(spec) = rule.rsplit(':').next() else {
        return false;
    };
    if let Some((a, b)) = spec.split_once('-') {
        match (a.parse::<u16>(), b.parse::<u16>()) {
            (Ok(start), Ok(end)) => port >= start && port <= end,
            _ => false,
        }
    } else {
        spec.parse::<u16>().map(|p| p == port).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(client: &str, event: &str, rule: &str, bytes: Option<u64>) -> LogRecord {
        LogRecord {
            ts: Utc::now(),
            event: event.to_string(),
            proto: "tcp".to_string(),
            client: client.to_string(),
            rule: rule.to_string(),
            target: "100.64.0.5".to_string(),
            verdict: "forwarded".to_string(),
            duration_s: if event == "end" { Some(120) } else { None },
            packets: if event == "end" { Some(100) } else { None },
            bytes,
        }
    }

    fn temp_store(tag: &str) -> (LogStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("nat-gate-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = LogStore::open(&dir).unwrap();
        (store, dir)
    }

    #[test]
    fn append_and_query_round_trip() {
        let (store, dir) = temp_store("rt");
        store
            .append(&rec("203.0.113.7:5000", "new", "nat-gate:tcp:25565", None))
            .unwrap();
        store
            .append(&rec(
                "203.0.113.8:5001",
                "end",
                "nat-gate:udp:19132",
                Some(500),
            ))
            .unwrap();

        let all = store.query(&LogQuery::default()).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].client, "203.0.113.7:5000"); // newest last → reversed first
        assert_eq!(all[0].client, "203.0.113.8:5001");

        let ends = store
            .query(&LogQuery {
                event: Some("end".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].bytes, Some(500));

        let by_client = store
            .query(&LogQuery {
                client: Some("203.0.113.7".parse().unwrap()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_client.len(), 1);

        let by_port = store
            .query(&LogQuery {
                port: Some(19132),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_port.len(), 1);
        assert_eq!(by_port[0].client, "203.0.113.8:5001");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn torn_final_line_is_skipped() {
        let (store, dir) = temp_store("torn");
        store
            .append(&rec("203.0.113.7:5000", "new", "nat-gate:tcp:25565", None))
            .unwrap();
        // Simulate a crash mid-write
        let mut f = OpenOptions::new()
            .append(true)
            .open(dir.join(super::super::LOG_FILE))
            .unwrap();
        write!(f, "{{\"ts\":\"2026-").unwrap();

        let all = store.query(&LogQuery::default()).unwrap();
        assert_eq!(all.len(), 1, "torn line skipped, good line kept");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rotation_keeps_recent_data() {
        let (base, dir) = temp_store("rot");
        let store = base.with_rotation(600, 2); // tiny threshold

        for i in 0..50 {
            store
                .append(&rec(
                    &format!("203.0.113.{i}:5000"),
                    "new",
                    "nat-gate:tcp:25565",
                    None,
                ))
                .unwrap();
        }

        // Rotations exist and the current file is small again
        assert!(dir.join(format!("{}.1", super::super::LOG_FILE)).exists());
        assert!(dir.join(format!("{}.2", super::super::LOG_FILE)).exists());

        let all = store.query(&LogQuery::default()).unwrap();
        assert!(!all.is_empty());
        // The very first client (oldest) must have been rotated away
        assert!(!all.iter().any(|r| r.client == "203.0.113.0:5000"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn query_orders_across_rotated_files() {
        // Regression: with rotations present, results must remain globally
        // most-recent-first — records from the current file must all come
        // before records from .1, which must all come before .2.
        let (base, dir) = temp_store("order");
        let store = base.with_rotation(600, 3);

        // 30 records with strictly increasing timestamps; rotation size
        // 600 bytes forces several files.
        let base_time = Utc::now() - chrono::Duration::minutes(60);
        for i in 0..30 {
            let mut r = rec(
                &format!("203.0.113.{}:5000", i % 256),
                "new",
                "nat-gate:tcp:25565",
                None,
            );
            r.ts = base_time + chrono::Duration::seconds(i);
            store.append(&r).unwrap();
        }

        let all = store.query(&LogQuery::default()).unwrap();
        assert!(all.len() > 1);
        // Strictly descending timestamps across the whole result set.
        for w in all.windows(2) {
            assert!(
                w[0].ts > w[1].ts,
                "records out of order across rotation boundary: {} then {}",
                w[0].ts,
                w[1].ts
            );
        }
        // And the very newest record must be first.
        assert_eq!(
            all[0].client, "203.0.113.29:5000",
            "newest record must lead"
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn top_aggregates_by_client() {
        let (store, dir) = temp_store("top");
        store
            .append(&rec(
                "203.0.113.7:5000",
                "end",
                "nat-gate:tcp:25565",
                Some(1000),
            ))
            .unwrap();
        store
            .append(&rec(
                "203.0.113.7:5001",
                "end",
                "nat-gate:tcp:25565",
                Some(3000),
            ))
            .unwrap();
        store
            .append(&rec(
                "203.0.113.8:5002",
                "end",
                "nat-gate:tcp:25565",
                Some(50),
            ))
            .unwrap();
        store
            .append(&rec("203.0.113.8:5003", "new", "nat-gate:tcp:25565", None))
            .unwrap();

        let top = store.top_clients(None).unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].client, "203.0.113.7", "sorted by bytes");
        assert_eq!(top[0].bytes, 4000);
        assert_eq!(top[0].sessions, 2);
        assert_eq!(top[1].bytes, 50, "new events contribute nothing");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn limit_returns_most_recent() {
        let (store, dir) = temp_store("limit");
        for i in 0..10 {
            let mut r = rec(
                &format!("203.0.113.{i}:5000"),
                "new",
                "nat-gate:tcp:25565",
                None,
            );
            r.ts = Utc::now() + chrono::Duration::seconds(i);
            store.append(&r).unwrap();
        }
        let last3 = store
            .query(&LogQuery {
                limit: Some(3),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(last3.len(), 3);
        // Most recent first
        assert_eq!(last3[0].client, "203.0.113.9:5000");
        assert_eq!(last3[2].client, "203.0.113.7:5000");

        fs::remove_dir_all(dir).unwrap();
    }

    /// Build an end record with explicit fields for rollup tests. The
    /// module-level `rec()` helper pins `ts` to "now", which can't express
    /// multi-day spans deterministically, so tests set the timestamp after.
    fn end_rec(rule: &str, bytes: u64, packets: u64, duration_s: u64) -> LogRecord {
        LogRecord {
            ts: Utc::now(),
            event: "end".to_string(),
            proto: "tcp".to_string(),
            client: "203.0.113.7:5000".to_string(),
            rule: rule.to_string(),
            target: "100.64.0.5".to_string(),
            verdict: "forwarded".to_string(),
            duration_s: Some(duration_s),
            packets: Some(packets),
            bytes: Some(bytes),
        }
    }

    /// UTC-day bucketing closure for deterministic rollup tests. The
    /// command path localizes to the host tz; tests pin to UTC so day
    /// boundaries don't shift with the runner's timezone.
    fn utc_day(ts: &DateTime<Utc>) -> NaiveDate {
        ts.naive_utc().date()
    }

    #[test]
    fn rollup_aggregates_two_rules_across_two_days() {
        let (store, dir) = temp_store("rollup2");
        // Day A = 2026-09-13, Day B = 2026-09-14 (later → sorts first).
        let day_a = chrono::NaiveDate::from_ymd_opt(2026, 9, 13).unwrap();
        let day_b = chrono::NaiveDate::from_ymd_opt(2026, 9, 14).unwrap();

        // Day A: rule1 twice (1000+2000=3000 bytes), rule2 once (500).
        let mut a1 = end_rec("nat-gate:tcp:25565", 1000, 10, 60);
        a1.ts = day_a.and_hms_opt(1, 0, 0).unwrap().and_utc();
        let mut a2 = end_rec("nat-gate:tcp:25565", 2000, 20, 120);
        a2.ts = day_a.and_hms_opt(2, 0, 0).unwrap().and_utc();
        let mut a3 = end_rec("nat-gate:udp:19132", 500, 5, 30);
        a3.ts = day_a.and_hms_opt(3, 0, 0).unwrap().and_utc();
        // Day B: rule1 once (7000).
        let mut b1 = end_rec("nat-gate:tcp:25565", 7000, 70, 600);
        b1.ts = day_b.and_hms_opt(1, 0, 0).unwrap().and_utc();
        // A "new" event that must be ignored by the rollup.
        let mut n1 = rec("203.0.113.9:5000", "new", "nat-gate:tcp:25565", None);
        n1.ts = day_b.and_hms_opt(2, 0, 0).unwrap().and_utc();

        for r in [a1, a2, a3, b1, n1] {
            store.append(&r).unwrap();
        }

        let rows = store.rollup(None, utc_day).unwrap();
        // Most recent day first; within a day, rule marker ascending.
        assert_eq!(rows.len(), 3, "two rules on day A + one on day B");
        // Day B first.
        assert_eq!(rows[0].day, day_b);
        assert_eq!(rows[0].rule, "nat-gate:tcp:25565");
        assert_eq!(rows[0].connections, 1);
        assert_eq!(rows[0].bytes, 7000);
        assert_eq!(rows[0].packets, 70);
        assert_eq!(rows[0].duration_s, 600);
        // Day A, rule1 aggregated across both events.
        assert_eq!(rows[1].day, day_a);
        assert_eq!(rows[1].rule, "nat-gate:tcp:25565");
        assert_eq!(rows[1].connections, 2);
        assert_eq!(rows[1].bytes, 3000, "byte sums aggregate");
        assert_eq!(rows[1].packets, 30);
        assert_eq!(rows[1].duration_s, 180);
        // Day A, rule2 (sorts after rule1 by marker).
        assert_eq!(rows[2].day, day_a);
        assert_eq!(rows[2].rule, "nat-gate:udp:19132");
        assert_eq!(rows[2].bytes, 500);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rollup_day_boundary_is_localized() {
        // A record at 23:30 UTC and one at 00:30 UTC-next-day share the
        // same day under a +02:00 offset but straddle under UTC. The
        // bucketing closure decides the boundary — this pins the contract.
        let (store, dir) = temp_store("rollupb");
        let d = chrono::NaiveDate::from_ymd_opt(2026, 9, 14).unwrap();
        let mut late = end_rec("nat-gate:tcp:443", 100, 1, 1);
        late.ts = d.and_hms_opt(23, 30, 0).unwrap().and_utc();
        let mut early = end_rec("nat-gate:tcp:443", 200, 2, 2);
        early.ts = (d + chrono::Duration::days(1))
            .and_hms_opt(0, 30, 0)
            .unwrap()
            .and_utc();

        store.append(&late).unwrap();
        store.append(&early).unwrap();

        // UTC bucketing → two separate days.
        let utc_rows = store.rollup(None, utc_day).unwrap();
        assert_eq!(utc_rows.len(), 2);

        // +02:00 bucketing → same calendar day, aggregated into one row.
        let offset = chrono::FixedOffset::east_opt(2 * 3600).unwrap();
        let offset_rows = store
            .rollup(None, |ts: &DateTime<Utc>| {
                ts.with_timezone(&offset).date_naive()
            })
            .unwrap();
        assert_eq!(offset_rows.len(), 1, "+02:00 collapses 23:30/00:30 Z");
        assert_eq!(offset_rows[0].connections, 2);
        assert_eq!(offset_rows[0].bytes, 300);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rollup_since_cutoff_drops_old_days() {
        let (store, dir) = temp_store("rollups");
        // Two records 3 days apart; a 1-day cutoff keeps only the newer.
        let now = Utc::now();
        let mut old = end_rec("nat-gate:tcp:443", 100, 1, 1);
        old.ts = now - chrono::Duration::days(3);
        let mut recent = end_rec("nat-gate:tcp:443", 200, 2, 2);
        recent.ts = now - chrono::Duration::hours(1);

        store.append(&old).unwrap();
        store.append(&recent).unwrap();

        let rows = store
            .rollup(Some(Duration::from_secs(86_400)), utc_day)
            .unwrap();
        assert_eq!(rows.len(), 1, "only the within-1-day record survives");
        assert_eq!(rows[0].bytes, 200);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rollup_empty_log_yields_no_rows() {
        let (store, dir) = temp_store("rollupe");
        let rows = store.rollup(None, utc_day).unwrap();
        assert!(rows.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
