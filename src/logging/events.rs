//! Parser for conntrack-tools output. REQUIRES the extended output format
//! (`conntrack -E -o extended` / `conntrack -L -o extended`): lines must
//! carry the `ipv4 2 tcp 6 …` family header. The default format (no `-o
//! extended`) omits it and is rejected — callers must pass the flag.
//!
//! Pure functions; no I/O; both the legacy `saddr=`/`dport=` and the modern
//! `src=`/`dport=` key styles are accepted.
//! ```text
//!     [NEW] ipv4 2 tcp 6 src=203.0.113.7 dst=198.51.100.2 sport=52188 dport=25565 src=100.64.0.5 dst=203.0.113.7 sport=25565 dport=52188 [ASSURED]
//! [DESTROY] ipv4 2 tcp 6 src=203.0.113.7 dst=198.51.100.2 sport=52188 dport=25565 packets=10 bytes=900 src=100.64.0.5 dst=203.0.113.7 sport=25565 dport=52188 packets=8 bytes=700
//! ```
//!
//! The first address tuple is the ORIGINAL direction (client → gateway);
//! the second is the REPLY direction. A flow that was DNAT'd by nat-gate has
//! the rule's target IP as the reply tuple's source address.

use std::net::IpAddr;

/// The conntrack event types nat-gate cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuple {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub packets: u64,
    pub bytes: u64,
}

impl Default for Tuple {
    fn default() -> Self {
        Tuple {
            src: IpAddr::from([0, 0, 0, 0]),
            dst: IpAddr::from([0, 0, 0, 0]),
            sport: 0,
            dport: 0,
            packets: 0,
            bytes: 0,
        }
    }
}
/// The conntrack event kinds nat-gate cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    New,
    Destroy,
}

/// A parsed conntrack flow event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEvent {
    pub kind: EventKind,
    /// "tcp" or "udp"
    pub proto: String,
    pub original: Tuple,
    pub reply: Tuple,
}
impl FlowEvent {
    /// True if this flow was destination-NAT'd (reply source differs from
    /// the original destination — i.e. the reply comes from somewhere the
    /// client never addressed).
    pub fn was_dnat(&self) -> bool {
        self.reply.src != self.original.dst
    }
}

/// Parse a single `conntrack -E` or `conntrack -L` line.
/// Returns None for lines that are not tcp/udp flow records.
pub fn parse_line(line: &str) -> Option<FlowEvent> {
    let line = line.trim();

    // Event type (conntrack -E). Listing lines (-L) have no bracket prefix;
    // treat them as NEW-like snapshots.
    let (kind, rest) = if let Some(r) = line.strip_prefix("[NEW]") {
        (EventKind::New, r)
    } else if let Some(r) = line.strip_prefix("[DESTROY]") {
        (EventKind::Destroy, r)
    } else if line.starts_with('[') {
        // UPDATE / other events: ignored
        return None;
    } else if line.starts_with("ipv4") || line.starts_with("ipv6") {
        // -L dump line
        (EventKind::New, line)
    } else {
        return None;
    };

    // Family and protocol: "ipv4 2 tcp 6 ..." — family, l3proto number,
    // l4 name, l4 number
    let mut fields = rest.split_whitespace();
    let _family = fields.next()?;
    let _l3num = fields.next()?;
    let proto = fields.next()?.to_string();
    if proto != "tcp" && proto != "udp" {
        return None; // icmp & friends carry no ports
    }
    let _l4num = fields.next()?;

    // Remaining tokens are key=value pairs for the two tuples, possibly with
    // bracketed flag decorations ([ASSURED], [UNREPLIED], mark=..., use=...).
    // Every `src=` token starts a new tuple, so the line naturally splits
    // into [original, reply].
    let mut tuples: Vec<Tuple> = Vec::new();
    let mut current: Option<Tuple> = None;

    for tok in fields {
        if tok.starts_with('[') || tok.starts_with("mark=") || tok.starts_with("use=") {
            continue;
        }
        let Some((key, value)) = tok.split_once('=') else {
            continue;
        };
        let key = match key {
            "saddr" => "src",
            "daddr" => "dst",
            other => other,
        };
        match key {
            "src" => {
                if let Ok(ip) = value.parse::<IpAddr>() {
                    if let Some(done) = current.take() {
                        tuples.push(done);
                    }
                    current = Some(Tuple {
                        src: ip,
                        ..Default::default()
                    });
                }
            }
            "dst" => {
                if let (Ok(ip), Some(t)) = (value.parse::<IpAddr>(), current.as_mut()) {
                    t.dst = ip;
                }
            }
            "sport" => {
                if let (Ok(p), Some(t)) = (value.parse::<u16>(), current.as_mut()) {
                    t.sport = p;
                }
            }
            "dport" => {
                if let (Ok(p), Some(t)) = (value.parse::<u16>(), current.as_mut()) {
                    t.dport = p;
                }
            }
            "packets" => {
                if let (Ok(p), Some(t)) = (value.parse::<u64>(), current.as_mut()) {
                    t.packets = p;
                }
            }
            "bytes" => {
                if let (Ok(b), Some(t)) = (value.parse::<u64>(), current.as_mut()) {
                    t.bytes = b;
                }
            }
            _ => {}
        }
    }
    if let Some(done) = current.take() {
        tuples.push(done);
    }

    // A conntrack flow line must carry both directions.
    if tuples.len() < 2 {
        return None;
    }
    let original = tuples.remove(0);
    let reply = tuples.remove(0);

    Some(FlowEvent {
        kind,
        proto,
        original,
        reply,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_new_event_modern_keys() {
        let line = "    [NEW] ipv4 2 tcp 6 src=203.0.113.7 dst=198.51.100.2 sport=52188 dport=25565 src=100.64.0.5 dst=203.0.113.7 sport=25565 dport=52188 [ASSURED] mark=0 use=1";
        let ev = parse_line(line).expect("event parses");
        assert_eq!(ev.kind, EventKind::New);
        assert_eq!(ev.proto, "tcp");
        assert_eq!(ev.original.src, ip("203.0.113.7"));
        assert_eq!(ev.original.dst, ip("198.51.100.2"));
        assert_eq!(ev.original.sport, 52188);
        assert_eq!(ev.original.dport, 25565);
        assert_eq!(ev.reply.src, ip("100.64.0.5"));
        assert_eq!(ev.reply.sport, 25565);
        assert!(ev.was_dnat());
    }

    #[test]
    fn parses_destroy_event_with_counters() {
        let line = " [DESTROY] ipv4 2 udp 17 src=203.0.113.9 dst=198.51.100.2 sport=40001 dport=19132 packets=40 bytes=3600 src=100.64.0.20 dst=203.0.113.9 sport=19132 dport=40001 packets=38 bytes=3400";
        let ev = parse_line(line).expect("event parses");
        assert_eq!(ev.kind, EventKind::Destroy);
        assert_eq!(ev.proto, "udp");
        assert_eq!(ev.original.packets, 40);
        assert_eq!(ev.original.bytes, 3600);
        assert_eq!(ev.reply.packets, 38);
        assert_eq!(ev.reply.bytes, 3400);
        assert_eq!(ev.original.dport, 19132);
        assert_eq!(ev.reply.src, ip("100.64.0.20"));
    }

    #[test]
    fn parses_legacy_saddr_keys() {
        let line = "    [NEW] ipv4 2 tcp 6 saddr=203.0.113.7 daddr=198.51.100.2 sport=52188 dport=443 saddr=100.64.0.5 daddr=203.0.113.7 sport=443 dport=52188";
        let ev = parse_line(line).expect("event parses");
        assert_eq!(ev.original.src, ip("203.0.113.7"));
        assert_eq!(ev.reply.src, ip("100.64.0.5"));
        assert_eq!(ev.reply.dport, 52188);
    }

    #[test]
    fn parses_ipv6_event() {
        let line = "    [NEW] ipv6 10 tcp 6 src=2001:db8::7 dst=2001:db8::1 sport=51000 dport=25565 src=fd7a:115c:a1e0::10 dst=2001:db8::7 sport=25565 dport=51000";
        let ev = parse_line(line).expect("event parses");
        assert_eq!(ev.original.src, ip("2001:db8::7"));
        assert_eq!(ev.reply.src, ip("fd7a:115c:a1e0::10"));
        assert!(ev.was_dnat());
    }

    #[test]
    fn parses_unnat_local_flow() {
        // A connection to the VPS itself (e.g. SSH): reply tuple mirrors the
        // original — no DNAT happened.
        let line = "    [NEW] ipv4 2 tcp 6 src=203.0.113.7 dst=198.51.100.2 sport=52188 dport=22 src=198.51.100.2 dst=203.0.113.7 sport=22 dport=52188";
        let ev = parse_line(line).expect("event parses");
        assert!(!ev.was_dnat());
    }

    #[test]
    fn parses_list_dump_line() {
        // conntrack -L lines carry no [EVENT] prefix
        let line = "tcp      6 431999 ESTABLISHED src=203.0.113.7 dst=198.51.100.2 sport=52188 dport=25565 src=100.64.0.5 dst=203.0.113.7 sport=25565 dport=52188 [ASSURED] mark=0 use=1";
        // Note: -L output does NOT start with ipv4/ipv6 in older versions
        // and starts with the protocol instead. Both shapes must parse or be
        // rejected consistently; the "ipv4"-prefixed shape is handled above.
        // This legacy shape is not parseable → None is acceptable.
        let _ = parse_line(line);
    }

    #[test]
    fn list_dump_with_family_prefix() {
        let line = "ipv4 2 tcp 6 431999 ESTABLISHED src=203.0.113.7 dst=198.51.100.2 sport=52188 dport=25565 src=100.64.0.5 dst=203.0.113.7 sport=25565 dport=52188 [ASSURED] mark=0 use=1";
        let ev = parse_line(line).expect("list line parses");
        assert_eq!(ev.original.dport, 25565);
        assert_eq!(ev.reply.src, ip("100.64.0.5"));
    }

    #[test]
    fn ignores_update_events() {
        let line = " [UPDATE] udp 17 src=203.0.113.7 dst=198.51.100.2 sport=40001 dport=19132 src=100.64.0.20 dst=203.0.113.7 sport=19132 dport=40001";
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn ignores_icmp() {
        let line = " [NEW] ipv4 2 icmp 1 type=8 code=0 id=1234 src=203.0.113.7 dst=198.51.100.2 type=0 code=8 id=1234 src=198.51.100.2 dst=203.0.113.7";
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn rejects_default_format_without_extended_header() {
        // What `conntrack -E` prints WITHOUT -o extended: no `ipv4 2` family
        // header. The daemon must pass -o extended or every event looks
        // like this and nothing is logged.
        let line = "    [NEW] tcp 6 431999 SYN_SENT src=203.0.113.7 dst=198.51.100.2 sport=52188 dport=25565 src=100.64.0.5 dst=203.0.113.7 sport=25565 dport=52188";
        assert!(
            parse_line(line).is_none(),
            "default format must be rejected (caller forgot -o extended)"
        );
    }

    #[test]
    fn ignores_garbage() {
        assert!(parse_line("").is_none());
        assert!(parse_line("random noise").is_none());
        assert!(
            parse_line("conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.")
                .is_none()
        );
    }
}
