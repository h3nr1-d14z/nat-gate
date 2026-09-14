//! `nat-gate metrics` — Prometheus exposition of rule and session state.
//!
//! `--once` renders the exposition text to stdout; without it the command
//! serves HTTP on the given port (default 9110) for Prometheus scrapes.
//!
//! Exposition follows the Prometheus text format, version 0.0.4. The
//! renderer ([`render`]) is a pure function of its inputs so it is fully
//! unit-testable with no kernel, network, or privilege requirements.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use colored::Colorize;

use crate::backend;

/// Default port for the HTTP scrape endpoint.
const DEFAULT_PORT: u16 = 9110;

/// One rule-counter sample ready for Prometheus exposition.
/// Carries the rule identity, its address family, and the matched counters
/// harvested from `RuleStore::stats()`.
struct RuleSample {
    proto: String,
    port: String,
    target: String,
    family: &'static str,
    packets: u64,
    bytes: u64,
}

/// Render the Prometheus exposition and print it once (`--once`), or serve
/// it over HTTP on `port` (default 9110).
pub fn run(port: Option<u16>, once: bool) -> Result<(), String> {
    if once {
        print!("{}", build_exposition());
        return Ok(());
    }

    let port = port.unwrap_or(DEFAULT_PORT);
    let listener = TcpListener::bind(("0.0.0.0", port))
        .map_err(|e| format!("metrics: failed to bind 0.0.0.0:{port}: {e}"))?;
    let local_addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| format!("0.0.0.0:{port}"));
    eprintln!(
        "{} scraping at http://{local_addr}/metrics",
        "nat-gate metrics".cyan().bold(),
    );

    // Serial, single-threaded accept loop: each connection is served to
    // completion before the next is accepted.
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        let _ = serve(&mut stream);
    }

    Ok(())
}

/// Gather live state (both rule families + session count) and render the
/// exposition. Degrades gracefully: a rule-family load failure yields no
/// samples for that family; a conntrack failure yields
/// `nat_gate_sessions_available = 0`. The exposition is always valid.
fn build_exposition() -> String {
    let mut samples = Vec::new();
    for (ipv6, family) in [(false, "ipv4"), (true, "ipv6")] {
        if let Ok(store) = backend::load_rules(ipv6) {
            for s in store.stats() {
                samples.push(RuleSample {
                    proto: s.proto,
                    port: s.port,
                    target: s.target,
                    family,
                    packets: s.packets,
                    bytes: s.bytes,
                });
            }
        }
    }

    let (session_count, sessions_available) = match crate::commands::sessions::fetch_live() {
        Ok(sessions) => (sessions.len(), true),
        Err(_) => (0, false),
    };

    render(
        &samples,
        session_count,
        sessions_available,
        env!("CARGO_PKG_VERSION"),
    )
}

/// Pure renderer: maps inputs to a Prometheus text exposition (format
/// version 0.0.4). No I/O — the unit tests exercise every metric family,
/// label quoting, counter formatting, the empty-rules case, and both
/// address families.
fn render(
    samples: &[RuleSample],
    session_count: usize,
    sessions_available: bool,
    version: &str,
) -> String {
    let mut out = String::new();

    out.push_str(
        "# HELP nat_gate_rule_packets_total Total packets matched by nat-gate managed rules.\n",
    );
    out.push_str("# TYPE nat_gate_rule_packets_total counter\n");
    for s in samples {
        out.push_str(&format!(
            "nat_gate_rule_packets_total{labels} {value}\n",
            labels = rule_labels(s),
            value = s.packets,
        ));
    }

    out.push_str(
        "# HELP nat_gate_rule_bytes_total Total bytes matched by nat-gate managed rules.\n",
    );
    out.push_str("# TYPE nat_gate_rule_bytes_total counter\n");
    for s in samples {
        out.push_str(&format!(
            "nat_gate_rule_bytes_total{labels} {value}\n",
            labels = rule_labels(s),
            value = s.bytes,
        ));
    }

    out.push_str("# HELP nat_gate_sessions_current Current number of live forwarded sessions tracked by conntrack.\n");
    out.push_str("# TYPE nat_gate_sessions_current gauge\n");
    out.push_str(&format!("nat_gate_sessions_current {session_count}\n"));

    out.push_str(
        "# HELP nat_gate_sessions_available Whether conntrack session data is available (1) or not (0).\n",
    );
    out.push_str("# TYPE nat_gate_sessions_available gauge\n");
    out.push_str(&format!(
        "nat_gate_sessions_available {}\n",
        if sessions_available { '1' } else { '0' }
    ));

    out.push_str("# HELP nat_gate_build_info Build information for nat-gate.\n");
    out.push_str("# TYPE nat_gate_build_info gauge\n");
    out.push_str(&format!(
        "nat_gate_build_info{{version=\"{}\"}} 1\n",
        escape_label_value(version)
    ));

    out
}

/// Build the label set for a rule counter sample, in the canonical order:
/// proto, port, target, family, rule. Values are Prometheus-escaped.
fn rule_labels(s: &RuleSample) -> String {
    format!(
        "{{proto=\"{proto}\",port=\"{port}\",target=\"{target}\",family=\"{family}\",rule=\"nat-gate:{proto}:{port}\"}}",
        proto = escape_label_value(&s.proto),
        port = escape_label_value(&s.port),
        target = escape_label_value(&s.target),
        family = escape_label_value(s.family),
    )
}

/// Escape a Prometheus label value: backslash, double-quote, newline.
fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Handle one scrape connection: read the request line and headers (up to
/// the blank line), reply 200 on `GET /` or `GET /metrics`, 404 otherwise.
/// Always halves the connection with `Connection: close`.
fn serve(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Drain headers until the blank line (or EOF) so pipelined scrapes that
    // carry headers do not leak into the next parse.
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header)?;
        if n == 0 || header == "\r\n" || header == "\n" {
            break;
        }
    }

    let response = match parse_request_line(&request_line) {
        Some((method, "/")) | Some((method, "/metrics")) if method.eq_ignore_ascii_case("GET") => {
            let body = build_exposition();
            http_response(
                "200",
                "OK",
                "text/plain; version=0.0.4; charset=utf-8",
                &body,
            )
        }
        _ => http_response(
            "404",
            "Not Found",
            "text/plain; charset=utf-8",
            "404 Not Found\n",
        ),
    };

    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}

/// Build a minimal HTTP/1.1 response. `Content-Length` reflects `body.len()`
/// (byte length, not char count).
fn http_response(status: &str, reason: &str, content_type: &str, body: &str) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("HTTP/1.1 ");
    out.push_str(status);
    out.push(' ');
    out.push_str(reason);
    out.push_str("\r\n");
    out.push_str("Content-Type: ");
    out.push_str(content_type);
    out.push_str("\r\n");
    out.push_str("Content-Length: ");
    out.push_str(&body.len().to_string());
    out.push_str("\r\n");
    out.push_str("Connection: close\r\n");
    out.push_str("\r\n");
    out.push_str(body);
    out.into_bytes()
}

/// Parse `METHOD PATH HTTP/1.1` into `(method, path)`.
fn parse_request_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        proto: &str,
        port: &str,
        target: &str,
        family: &'static str,
        packets: u64,
        bytes: u64,
    ) -> RuleSample {
        RuleSample {
            proto: proto.into(),
            port: port.into(),
            target: target.into(),
            family,
            packets,
            bytes,
        }
    }

    #[test]
    fn help_and_type_present_for_every_metric() {
        let out = render(&[], 0, true, "1.2.3");
        for metric in [
            "nat_gate_rule_packets_total",
            "nat_gate_rule_bytes_total",
            "nat_gate_sessions_current",
            "nat_gate_sessions_available",
            "nat_gate_build_info",
        ] {
            assert!(
                out.contains(&format!("# HELP {metric} ")),
                "missing HELP for {metric}"
            );
            assert!(
                out.contains(&format!("# TYPE {metric} ")),
                "missing TYPE for {metric}"
            );
        }
    }

    #[test]
    fn empty_rules_still_emit_help_and_type_header() {
        let out = render(&[], 0, true, "0.0.0");
        assert!(out.contains("# TYPE nat_gate_rule_packets_total counter\n"));
        assert!(out.contains("# TYPE nat_gate_rule_bytes_total counter\n"));
        // No data lines when there are no samples.
        assert!(!out.contains("nat_gate_rule_packets_total{"));
        assert!(!out.contains("nat_gate_rule_bytes_total{"));
    }

    #[test]
    fn counter_sample_has_exact_labels_and_integer_value() {
        let samples = vec![sample("tcp", "443", "100.64.0.5", "ipv4", 1234, 56789)];
        let out = render(&samples, 0, true, "1.0.0");
        let expected_packets =
            "nat_gate_rule_packets_total{proto=\"tcp\",port=\"443\",target=\"100.64.0.5\",family=\"ipv4\",rule=\"nat-gate:tcp:443\"} 1234";
        assert!(
            out.contains(expected_packets),
            "missing/incorrect packets line:\n{out}"
        );
        let expected_bytes =
            "nat_gate_rule_bytes_total{proto=\"tcp\",port=\"443\",target=\"100.64.0.5\",family=\"ipv4\",rule=\"nat-gate:tcp:443\"} 56789";
        assert!(
            out.contains(expected_bytes),
            "missing/incorrect bytes line:\n{out}"
        );
    }

    #[test]
    fn counter_values_have_no_thousands_separators() {
        let samples = vec![sample(
            "tcp", "443", "10.0.0.1", "ipv4", 1_234_567, 9_876_543,
        )];
        let out = render(&samples, 0, true, "1.0.0");
        assert!(
            out.contains("} 1234567\n"),
            "bytes not formatted as plain integer:\n{out}"
        );
    }

    #[test]
    fn both_address_families_are_rendered() {
        let samples = vec![
            sample("tcp", "443", "100.64.0.5", "ipv4", 10, 100),
            sample("udp", "53", "fd7a::5", "ipv6", 5, 50),
        ];
        let out = render(&samples, 0, true, "1.0.0");
        assert!(out.contains("family=\"ipv4\""));
        assert!(out.contains("family=\"ipv6\""));
        assert!(out.contains("target=\"fd7a::5\""));
        assert!(out.contains("rule=\"nat-gate:udp:53\""));
    }

    #[test]
    fn session_gauges_reflect_count_and_availability() {
        let avail = render(&[], 7, true, "1.0.0");
        assert!(avail.contains("nat_gate_sessions_current 7\n"));
        assert!(avail.contains("nat_gate_sessions_available 1\n"));
        let unavail = render(&[], 0, false, "1.0.0");
        assert!(unavail.contains("nat_gate_sessions_current 0\n"));
        assert!(unavail.contains("nat_gate_sessions_available 0\n"));
    }

    #[test]
    fn build_info_carries_version() {
        let out = render(&[], 0, true, "9.8.7");
        assert!(out.contains("nat_gate_build_info{version=\"9.8.7\"} 1\n"));
    }

    #[test]
    fn label_values_in_samples_are_escaped() {
        // \" in port, backslash and newline in target.
        let samples = vec![sample("tcp", "4\"43", "1\\0\n", "ipv4", 1, 2)];
        let out = render(&samples, 0, true, "1.0.0");
        assert!(
            out.contains("port=\"4\\\"43\""),
            "double-quote not escaped:\n{out}"
        );
        assert!(
            out.contains("target=\"1\\\\0\\n\""),
            "backslash/newline not escaped:\n{out}"
        );
    }

    #[test]
    fn escape_label_value_pure_function() {
        assert_eq!(escape_label_value("plain"), "plain");
        assert_eq!(escape_label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn http_response_well_formed() {
        let bytes = http_response("200", "OK", "text/plain", "body\n");
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("body\n"));
    }

    #[test]
    fn parse_request_line_basic() {
        assert_eq!(
            parse_request_line("GET /metrics HTTP/1.1\r\n"),
            Some(("GET", "/metrics"))
        );
        assert_eq!(parse_request_line("POST / HTTP/1.1"), Some(("POST", "/")));
        assert_eq!(parse_request_line(""), None);
        assert_eq!(parse_request_line("GET\r\n"), None);
    }
}
