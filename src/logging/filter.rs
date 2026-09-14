//! Flow classification: decides which conntrack events belong to nat-gate
//! rules and what happened to them.
//!
//! The filter is keyed on the DNAT outcome, never on the destination port
//! alone. Matching by dport would misattribute the gateway's own outbound
//! connections (e.g. the VPS fetching updates over :443) as player traffic.
//!
//! - **forwarded**: the reply tuple's source is exactly one of our rule
//!   targets — the kernel rewrote the destination, so this flow went through
//!   nat-gate. (A v4 target can never equal a v6 reply address, so families
//!   separate naturally.)
//! - **not_forwarded**: no rewrite happened (`reply.src == original.dst`,
//!   i.e. delivered locally) *and* the original destination is one of the
//!   host's own addresses *and* the port matches an active rule — the
//!   classic rate-limited or nothing-listening case.

use std::collections::HashSet;
use std::net::IpAddr;

use super::events::FlowEvent;

/// What happened to a flow that arrived on a nat-gate port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Forwarded,
    NotForwarded,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Forwarded => "forwarded",
            Verdict::NotForwarded => "not_forwarded",
        }
    }
}

/// A port range from a rule (single ports are start == end).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    /// Parse "443" or "8000-8080" (dash or colon separated).
    pub fn parse(spec: &str) -> Option<PortRange> {
        let spec = spec.replace(':', "-");
        if let Some((a, b)) = spec.split_once('-') {
            let start = a.parse().ok()?;
            let end = b.parse().ok()?;
            if start == 0 || end == 0 || start > end {
                return None;
            }
            Some(PortRange { start, end })
        } else {
            let p = spec.parse().ok()?;
            if p == 0 {
                return None;
            }
            Some(PortRange { start: p, end: p })
        }
    }
}

/// One matchable rule: protocol, forwarded-to target, and the port range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchRule {
    pub proto: String,
    pub target: IpAddr,
    pub ports: PortRange,
    /// "nat-gate:tcp:25565"
    pub marker: String,
}

/// Classifies conntrack events against the active rule set and the host's
/// own addresses.
#[derive(Debug, Clone)]
pub struct FlowFilter {
    rules: Vec<MatchRule>,
    local_addrs: HashSet<IpAddr>,
}

impl FlowFilter {
    pub fn new(rules: Vec<MatchRule>, local_addrs: HashSet<IpAddr>) -> Self {
        FlowFilter { rules, local_addrs }
    }

    /// Classify a flow event. Returns None when the flow is unrelated to
    /// nat-gate (the common case — keep it cheap).
    pub fn classify(&self, ev: &FlowEvent) -> Option<(Verdict, &MatchRule)> {
        if ev.was_dnat() {
            // Forwarded: the reply comes from one of our targets, on a port
            // that rule owns.
            for rule in &self.rules {
                if rule.proto == ev.proto
                    && rule.target == ev.reply.src
                    && rule.ports.contains(ev.reply.sport)
                {
                    return Some((Verdict::Forwarded, rule));
                }
            }
            // DNAT'd by something else (docker, other tools) — not ours.
            return None;
        }

        // No rewrite: only interesting if it landed on a local address on a
        // port one of our rules owns — i.e. it should have been forwarded.
        if !self.local_addrs.contains(&ev.original.dst) {
            return None;
        }
        for rule in &self.rules {
            if rule.proto == ev.proto && rule.ports.contains(ev.original.dport) {
                return Some((Verdict::NotForwarded, rule));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::events::{EventKind, Tuple};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn tcp_rule(target: &str, port: u16) -> MatchRule {
        MatchRule {
            proto: "tcp".to_string(),
            target: ip(target),
            ports: PortRange {
                start: port,
                end: port,
            },
            marker: format!("nat-gate:tcp:{port}"),
        }
    }

    fn local_ips(ips: &[&str]) -> HashSet<IpAddr> {
        ips.iter().map(|s| ip(s)).collect()
    }

    /// A DNAT'd flow: client -> VPS:25565, reply from the game server.
    fn dnat_flow() -> FlowEvent {
        FlowEvent {
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
        }
    }

    #[test]
    fn forwarded_flow_matches_by_reply_target() {
        let filter = FlowFilter::new(
            vec![tcp_rule("100.64.0.5", 25565)],
            local_ips(&["198.51.100.2"]),
        );
        let (verdict, rule) = filter.classify(&dnat_flow()).expect("classified");
        assert_eq!(verdict, Verdict::Forwarded);
        assert_eq!(rule.marker, "nat-gate:tcp:25565");
    }

    #[test]
    fn vps_outbound_is_not_logged() {
        // The advisory case: the VPS itself connects out to some other
        // server's :25565. No rewrite, and the destination is NOT local.
        let ev = FlowEvent {
            kind: EventKind::New,
            proto: "tcp".to_string(),
            original: Tuple {
                src: ip("198.51.100.2"),
                dst: ip("93.184.216.34"),
                sport: 41000,
                dport: 25565,
                ..Default::default()
            },
            reply: Tuple {
                src: ip("93.184.216.34"),
                dst: ip("198.51.100.2"),
                sport: 25565,
                dport: 41000,
                ..Default::default()
            },
        };
        let filter = FlowFilter::new(
            vec![tcp_rule("100.64.0.5", 25565)],
            local_ips(&["198.51.100.2"]),
        );
        assert!(
            filter.classify(&ev).is_none(),
            "outbound must not be logged"
        );
    }

    #[test]
    fn rate_limited_connection_is_not_forwarded() {
        // SYN arrived at local :25565 but was not DNAT'd (limit exceeded):
        // reply tuple mirrors the original, destination is the VPS itself.
        let ev = FlowEvent {
            kind: EventKind::New,
            proto: "tcp".to_string(),
            original: Tuple {
                src: ip("203.0.113.7"),
                dst: ip("198.51.100.2"),
                sport: 52189,
                dport: 25565,
                ..Default::default()
            },
            reply: Tuple {
                src: ip("198.51.100.2"),
                dst: ip("203.0.113.7"),
                sport: 25565,
                dport: 52189,
                ..Default::default()
            },
        };
        let filter = FlowFilter::new(
            vec![tcp_rule("100.64.0.5", 25565)],
            local_ips(&["198.51.100.2"]),
        );
        let (verdict, _) = filter.classify(&ev).expect("classified");
        assert_eq!(verdict, Verdict::NotForwarded);
    }

    #[test]
    fn local_service_on_other_port_is_ignored() {
        // SSH to the VPS: local, but no nat-gate rule on :22.
        let ev = FlowEvent {
            kind: EventKind::New,
            proto: "tcp".to_string(),
            original: Tuple {
                src: ip("203.0.113.7"),
                dst: ip("198.51.100.2"),
                sport: 52190,
                dport: 22,
                ..Default::default()
            },
            reply: Tuple {
                src: ip("198.51.100.2"),
                dst: ip("203.0.113.7"),
                sport: 22,
                dport: 52190,
                ..Default::default()
            },
        };
        let filter = FlowFilter::new(
            vec![tcp_rule("100.64.0.5", 25565)],
            local_ips(&["198.51.100.2"]),
        );
        assert!(filter.classify(&ev).is_none());
    }

    #[test]
    fn foreign_dnat_is_ignored() {
        // Docker DNAT'd a flow to 172.17.0.2 — not one of our targets.
        let ev = FlowEvent {
            kind: EventKind::New,
            proto: "tcp".to_string(),
            original: Tuple {
                src: ip("203.0.113.7"),
                dst: ip("198.51.100.2"),
                sport: 52191,
                dport: 8080,
                ..Default::default()
            },
            reply: Tuple {
                src: ip("172.17.0.2"),
                dst: ip("203.0.113.7"),
                sport: 80,
                dport: 52191,
                ..Default::default()
            },
        };
        let filter = FlowFilter::new(
            vec![tcp_rule("100.64.0.5", 25565)],
            local_ips(&["198.51.100.2"]),
        );
        assert!(filter.classify(&ev).is_none());
    }

    #[test]
    fn ipv6_flow_never_matches_v4_target() {
        let ev = FlowEvent {
            kind: EventKind::New,
            proto: "tcp".to_string(),
            original: Tuple {
                src: ip("2001:db8::7"),
                dst: ip("2001:db8::1"),
                sport: 51000,
                dport: 25565,
                ..Default::default()
            },
            reply: Tuple {
                src: ip("fd7a:115c:a1e0::5"),
                dst: ip("2001:db8::7"),
                sport: 25565,
                dport: 51000,
                ..Default::default()
            },
        };
        // Only a v4 rule exists; the v6 flow must not match it.
        let filter = FlowFilter::new(vec![tcp_rule("100.64.0.5", 25565)], HashSet::new());
        assert!(filter.classify(&ev).is_none());

        // With the v6 rule present it matches.
        let v6 = MatchRule {
            proto: "tcp".to_string(),
            target: ip("fd7a:115c:a1e0::5"),
            ports: PortRange {
                start: 25565,
                end: 25565,
            },
            marker: "nat-gate:tcp:25565".to_string(),
        };
        let filter = FlowFilter::new(vec![v6], HashSet::new());
        let (verdict, _) = filter.classify(&ev).expect("v6 classified");
        assert_eq!(verdict, Verdict::Forwarded);
    }

    #[test]
    fn port_ranges() {
        let r = PortRange::parse("25565").unwrap();
        assert_eq!((r.start, r.end), (25565, 25565));
        let r = PortRange::parse("8000-8080").unwrap();
        assert!(r.contains(8000));
        assert!(r.contains(8080));
        assert!(r.contains(8050));
        assert!(!r.contains(7999));
        assert!(!r.contains(8081));
        assert_eq!(PortRange::parse("8080-8000"), None);
        assert_eq!(PortRange::parse("0"), None);
        assert_eq!(PortRange::parse("abc"), None);
        let r = PortRange::parse("8000:8080").unwrap();
        assert!(r.contains(8001));
    }
}
