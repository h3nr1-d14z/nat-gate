//! Single source of truth for nat-gate's view of live iptables state.
//!
//! Everything is parsed from `iptables-save -c -t nat` output: one rule per
//! line, stable token order, exact counters. This replaces the six drifting
//! copies of `iptables -L` column parsing that previously lived in the
//! command modules and the TUI.
//!
//! Rule identity is the comment marker `nat-gate:<proto>:<port>` and is
//! always matched as a whole token — never by substring — so a rule for
//! port 443 can never collide with one for port 4430.

use crate::iptables::executor::IptablesExecutor;

/// Chain a nat-gate entry lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Prerouting,
    Postrouting,
}

impl Chain {
    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Prerouting => "PREROUTING",
            Chain::Postrouting => "POSTROUTING",
        }
    }
}

/// A nat-gate managed forwarding rule (one PREROUTING/POSTROUTING pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatRule {
    /// "tcp" or "udp"
    pub proto: String,
    /// Single port "443" or range "8000-8080" (dash form)
    pub port: String,
    /// Target IP only (no port, no brackets)
    pub target: String,
    /// Input interface constraint, if any
    pub interface: Option<String>,
    /// Rate limit in iptables canonical form ("100/minute"), if any
    pub limit: Option<String>,
}

impl NatRule {
    /// Exact identity of this rule: the iptables comment marker.
    pub fn marker(&self) -> String {
        format!("nat-gate:{}:{}", self.proto, self.port)
    }
}

/// One iptables entry belonging to a nat-gate rule.
#[derive(Debug, Clone)]
pub struct RuleEntry {
    pub chain: Chain,
    pub rule: NatRule,
    /// Packet counter for this entry
    pub packets: u64,
    /// Byte counter for this entry
    pub bytes: u64,
    /// Argument tokens after `-A <chain>` in iptables-save output.
    /// Passed verbatim to `iptables -t nat -D <chain> …` for exact,
    /// line-number-free deletion.
    pub spec: Vec<String>,
}

/// Traffic statistics for one rule (from its PREROUTING entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleStats {
    pub proto: String,
    pub port: String,
    pub target: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Parsed view of the nat table's nat-gate entries.
#[derive(Debug, Clone, Default)]
pub struct RuleStore {
    entries: Vec<RuleEntry>,
}

impl RuleStore {
    /// Load the nat table from the system (`iptables-save -c -t nat`).
    pub fn load(ipv6: bool) -> Result<Self, String> {
        Ok(Self::from_save_output(&IptablesExecutor::save_nat_table(
            ipv6,
        )?))
    }

    /// Parse iptables-save output. Foreign rules are ignored.
    pub fn from_save_output(text: &str) -> Self {
        RuleStore {
            entries: text.lines().filter_map(parse_entry).collect(),
        }
    }

    /// All nat-gate entries in table order (both chains).
    pub fn entries(&self) -> &[RuleEntry] {
        &self.entries
    }

    /// Authoritative rules: the PREROUTING entries, in table order.
    pub fn rules(&self) -> impl Iterator<Item = &NatRule> {
        self.entries
            .iter()
            .filter(|e| e.chain == Chain::Prerouting)
            .map(|e| &e.rule)
    }

    /// Number of distinct managed rules.
    pub fn rule_count(&self) -> usize {
        self.rules().count()
    }

    /// Exact lookup by protocol and port. Both single ports and ranges use
    /// the dash form; `8000:8080` (iptables syntax) is canonicalized.
    pub fn find(&self, proto: &str, port: &str) -> Option<&NatRule> {
        let port = canonical_port(port);
        self.rules().find(|r| r.proto == proto && r.port == port)
    }

    /// Every entry carrying this rule's identity (both chains), for
    /// deletion. Includes orphaned POSTROUTING entries.
    pub fn entries_for(&self, proto: &str, port: &str) -> Vec<&RuleEntry> {
        let port = canonical_port(port);
        self.entries
            .iter()
            .filter(|e| e.rule.proto == proto && e.rule.port == port)
            .collect()
    }

    /// Per-rule traffic statistics, from PREROUTING entries.
    pub fn stats(&self) -> Vec<RuleStats> {
        self.entries
            .iter()
            .filter(|e| e.chain == Chain::Prerouting)
            .map(|e| RuleStats {
                proto: e.rule.proto.clone(),
                port: e.rule.port.clone(),
                target: e.rule.target.clone(),
                packets: e.packets,
                bytes: e.bytes,
            })
            .collect()
    }
}

/// Canonicalize a port spec to the dash form: "8000:8080" -> "8000-8080".
pub fn canonical_port(port: &str) -> String {
    port.replace(':', "-")
}

/// Split an iptables rule line into argument tokens, merging double-quoted
/// segments (comment values may be quoted by iptables-save).
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Find a flag with a separate value and return that value.
/// (e.g. `-p tcp`, `--comment "nat-gate:tcp:443"`)
fn flag_value<'a>(tokens: &'a [String], flag: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|t| t == flag)
        .and_then(|i| tokens.get(i + 1))
        .map(|s| s.as_str())
}

/// Parse one iptables-save line into a nat-gate entry.
/// Returns None for anything that is not a nat-gate managed rule.
fn parse_entry(line: &str) -> Option<RuleEntry> {
    let line = line.trim();

    // Strip the counter prefix emitted by `iptables-save -c`: "[pkts:bytes] -A …"
    let (counters, rule_line) = if let Some(rest) = line.strip_prefix('[') {
        match rest.split_once("] ") {
            Some((c, rule)) => {
                if !is_counter_pair(c) {
                    return None;
                }
                (parse_counters(c), rule)
            }
            None => return None,
        }
    } else {
        (None, line)
    };

    let tokens = tokenize(rule_line);
    if tokens.first().map(|t| t.as_str()) != Some("-A") {
        return None;
    }

    let chain = match tokens.get(1).map(|t| t.as_str()) {
        Some("PREROUTING") => Chain::Prerouting,
        Some("POSTROUTING") => Chain::Postrouting,
        _ => return None,
    };

    // Identity: the comment marker. Matched structurally, never by substring.
    let comment = flag_value(&tokens, "--comment")?;

    // Chain-specific fields. PREROUTING lines are authoritative for the rule.
    let target = match chain {
        Chain::Prerouting => flag_value(&tokens, "--to-destination").map(ip_from_to_destination),
        Chain::Postrouting => flag_value(&tokens, "-d").map(ip_from_destination_match),
    }
    .unwrap_or_default();

    let rule = NatRule {
        interface: flag_value(&tokens, "-i").map(str::to_string),
        limit: flag_value(&tokens, "--limit").map(str::to_string),
        target,
        ..parse_comment(comment)?
    };

    // Cross-check the protocol flag against the comment (defense in depth).
    if let Some(p) = flag_value(&tokens, "-p") {
        if p != rule.proto {
            return None;
        }
    }

    // Deletion spec: everything after "-A <chain>", verbatim.
    let spec = tokens[2..].to_vec();
    let (packets, bytes) = counters.unwrap_or((0, 0));

    Some(RuleEntry {
        chain,
        rule,
        packets,
        bytes,
        spec,
    })
}

/// Parse the comment marker `nat-gate:<proto>:<port>`.
/// Rejects anything that is not exactly this shape.
fn parse_comment(comment: &str) -> Option<NatRule> {
    let mut parts = comment.split(':');
    if parts.next()? != "nat-gate" {
        return None;
    }
    let proto = parts.next()?.to_string();
    let port = parts.next()?.to_string();
    if parts.next().is_some() {
        return None; // extra segments: not our marker
    }
    if proto != "tcp" && proto != "udp" {
        return None;
    }
    if port.is_empty() {
        return None;
    }

    Some(NatRule {
        proto,
        port: canonical_port(&port),
        target: String::new(),
        interface: None,
        limit: None,
    })
}

/// Extract the IP from a DNAT target: "100.64.0.5:443" or "[fd7a::5]:8000-8080".
fn ip_from_to_destination(spec: &str) -> String {
    if let Some(rest) = spec.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest).to_string()
    } else {
        match spec.rsplit_once(':') {
            Some((ip, _)) => ip.to_string(),
            None => spec.to_string(),
        }
    }
}

/// Extract the IP from a destination match: "100.64.0.5/32" or "fd7a::5/128".
fn ip_from_destination_match(d: &str) -> String {
    match d.strip_suffix("/32").or_else(|| d.strip_suffix("/128")) {
        Some(ip) => ip.to_string(),
        None => d.to_string(),
    }
}

fn is_counter_pair(s: &str) -> bool {
    !s.is_empty() && s.contains(':') && s.chars().all(|c| c.is_ascii_digit() || c == ':')
}

fn parse_counters(s: &str) -> Option<(u64, u64)> {
    let (pkts, bytes) = s.split_once(':')?;
    Some((pkts.parse().ok()?, bytes.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_SAVE: &str = r#"# Generated by iptables-save
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
[1234:56789] -A PREROUTING -p tcp -m tcp --dport 443 -m comment --comment "nat-gate:tcp:443" -j DNAT --to-destination 100.64.0.5:443
[567:128000] -A PREROUTING -p udp -m udp --dport 51820 -m comment --comment "nat-gate:udp:51820" -j DNAT --to-destination 100.64.0.10:51820
[0:0] -A PREROUTING -i eth0 -p tcp -m tcp --dport 8000:8080 -m limit --limit 100/minute --limit-burst 150 -m comment --comment "nat-gate:tcp:8000-8080" -j DNAT --to-destination 100.64.0.5:8000-8080
[1234:56789] -A POSTROUTING -d 100.64.0.5/32 -p tcp -m tcp --dport 443 -m comment --comment "nat-gate:tcp:443" -j MASQUERADE
[567:128000] -A POSTROUTING -d 100.64.0.10/32 -p udp -m udp --dport 51820 -m comment --comment "nat-gate:udp:51820" -j MASQUERADE
[0:0] -A POSTROUTING -d 100.64.0.5/32 -p tcp -m tcp --dport 8000:8080 -m comment --comment "nat-gate:tcp:8000-8080" -j MASQUERADE
[99:9999] -A PREROUTING -d 172.17.0.2/32 -p tcp -m tcp --dport 443 -j DOCKER
[5:500] -A PREROUTING -p tcp -m tcp --dport 443 -m comment --comment "someone-else:tcp:443" -j DNAT --to-destination 10.0.0.9:443
COMMIT
"#;

    #[test]
    fn parses_rules_from_both_chains() {
        let store = RuleStore::from_save_output(V4_SAVE);
        assert_eq!(store.entries().len(), 6);
        assert_eq!(store.rule_count(), 3);
    }

    #[test]
    fn ignores_foreign_rules() {
        let store = RuleStore::from_save_output(V4_SAVE);
        let markers: Vec<String> = store.entries().iter().map(|e| e.rule.marker()).collect();
        assert!(!markers.iter().any(|m| m == "someone-else:tcp:443"));
        for m in &markers {
            assert!(m.starts_with("nat-gate:"), "foreign rule leaked: {m}");
        }
    }

    #[test]
    fn extracts_rule_details() {
        let store = RuleStore::from_save_output(V4_SAVE);
        let rule = store.find("tcp", "443").expect("tcp:443 must be found");
        assert_eq!(rule.target, "100.64.0.5");
        assert_eq!(rule.interface, None);
        assert_eq!(rule.limit, None);

        let ranged = store.find("tcp", "8000-8080").expect("range rule");
        assert_eq!(ranged.target, "100.64.0.5");
        assert_eq!(ranged.interface.as_deref(), Some("eth0"));
        assert_eq!(ranged.limit.as_deref(), Some("100/minute"));
    }

    #[test]
    fn exact_match_no_prefix_collisions() {
        // Bug regression: `nat-gate:tcp:443` must not match port 4430.
        let save = r#"-A PREROUTING -p tcp -m tcp --dport 443 -m comment --comment "nat-gate:tcp:443" -j DNAT --to-destination 100.64.0.5:443
-A PREROUTING -p tcp -m tcp --dport 4430 -m comment --comment "nat-gate:tcp:4430" -j DNAT --to-destination 100.64.0.6:4430
-A POSTROUTING -d 100.64.0.5/32 -p tcp -m tcp --dport 443 -m comment --comment "nat-gate:tcp:443" -j MASQUERADE
-A POSTROUTING -d 100.64.0.6/32 -p tcp -m tcp --dport 4430 -m comment --comment "nat-gate:tcp:4430" -j MASQUERADE
"#;
        let store = RuleStore::from_save_output(save);

        let rule = store.find("tcp", "443").expect("exact rule found");
        assert_eq!(rule.target, "100.64.0.5", "must not pick up 4430");

        let to_delete = store.entries_for("tcp", "443");
        assert_eq!(to_delete.len(), 2, "only the two tcp:443 entries");
        assert!(to_delete
            .iter()
            .all(|e| e.rule.port == "443" && e.rule.target == "100.64.0.5"));
    }

    #[test]
    fn parses_ipv6_rules() {
        let save = r#"-A PREROUTING -p tcp -m tcp --dport 25565 -m comment --comment "nat-gate:tcp:25565" -j DNAT --to-destination [fd7a:115c:a1e0::5]:25565
-A POSTROUTING -d fd7a:115c:a1e0::5/128 -p tcp -m tcp --dport 25565 -m comment --comment "nat-gate:tcp:25565" -j MASQUERADE
"#;
        let store = RuleStore::from_save_output(save);
        assert_eq!(store.rule_count(), 1);
        let rule = store.find("tcp", "25565").expect("v6 rule found");
        assert_eq!(rule.target, "fd7a:115c:a1e0::5");
    }

    #[test]
    fn parses_counters() {
        let store = RuleStore::from_save_output(V4_SAVE);
        let stats = store.stats();
        assert_eq!(stats.len(), 3);
        assert_eq!(stats[0].packets, 1234);
        assert_eq!(stats[0].bytes, 56789);
        assert_eq!(stats[1].packets, 567);
        assert_eq!(stats[1].bytes, 128000);
        assert_eq!(stats[2].packets, 0);
    }

    #[test]
    fn handles_lines_without_counters() {
        let save = r#"-A PREROUTING -p tcp -m tcp --dport 443 -m comment --comment "nat-gate:tcp:443" -j DNAT --to-destination 100.64.0.5:443
"#;
        let store = RuleStore::from_save_output(save);
        assert_eq!(store.rule_count(), 1);
        assert_eq!(store.stats()[0].packets, 0);
    }

    #[test]
    fn finds_orphaned_postrouting_entries() {
        // POSTROUTING without PREROUTING: not an active rule, but del/flush
        // must still be able to clean it up.
        let save = r#"-A POSTROUTING -d 100.64.0.5/32 -p tcp -m tcp --dport 443 -m comment --comment "nat-gate:tcp:443" -j MASQUERADE
"#;
        let store = RuleStore::from_save_output(save);
        assert_eq!(store.rule_count(), 0, "orphan is not an active rule");
        assert!(store.find("tcp", "443").is_none());
        assert_eq!(
            store.entries_for("tcp", "443").len(),
            1,
            "orphan still deletable"
        );
    }

    #[test]
    fn keeps_deletion_spec_verbatim() {
        let store = RuleStore::from_save_output(V4_SAVE);
        let entry = store
            .entries_for("tcp", "8000-8080")
            .into_iter()
            .find(|e| e.chain == Chain::Prerouting)
            .expect("prerouting entry");
        assert_eq!(entry.spec[0], "-i");
        assert_eq!(entry.spec[1], "eth0");
        assert!(entry
            .spec
            .windows(2)
            .any(|w| w[0] == "--comment" && w[1] == "nat-gate:tcp:8000-8080"));
        assert!(entry
            .spec
            .windows(2)
            .any(|w| w[0] == "--to-destination" && w[1] == "100.64.0.5:8000-8080"));
    }

    #[test]
    fn canonicalizes_port_forms() {
        assert_eq!(canonical_port("443"), "443");
        assert_eq!(canonical_port("8000:8080"), "8000-8080");
        assert_eq!(canonical_port("8000-8080"), "8000-8080");
    }
}
