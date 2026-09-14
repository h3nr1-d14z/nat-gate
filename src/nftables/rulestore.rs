//! Parser for `nft -j list table` output into the shared [`RuleStore`].
//!
//! Real output shape (nftables 1.1.6, kernel-verified fixtures in tests):
//! top-level `nftables` array of objects; rules carry a rule-level
//! `comment` (the `nat-gate:<proto>:<port>` marker) and `handle`,
//! with statement objects in `expr`:
//!
//! ```json
//! {"rule":{"chain":"prerouting","handle":3,
//!   "comment":"nat-gate:tcp:443",
//!   "expr":[
//!     {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
//!     {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
//!     {"counter":{"packets":0,"bytes":0}},
//!     {"limit":{"rate":100,"burst":150,"per":"minute"}},
//!     {"dnat":{"addr":"192.0.2.99","port":443}}]}}
//! ```
//!
//! Port ranges serialize as `{"range":[8000,8080]}`; the postrouting
//! masquerade rule matches `ip`/`ip6 daddr` plus transport dport.

use serde_json::Value;

use crate::iptables::rulestore::{parse_comment, Chain, NatRule, RuleEntry, RuleStore};

/// Parse `nft -j list table` output. Foreign rules (no nat-gate comment
/// marker) are ignored, matching the iptables rulestore's semantics.
pub fn parse_table_json(text: &str) -> RuleStore {
    let json: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return RuleStore::from_entries(Vec::new()),
    };
    let Some(arr) = json["nftables"].as_array() else {
        return RuleStore::from_entries(Vec::new());
    };
    let entries = arr
        .iter()
        .filter(|o| o.get("rule").is_some())
        .filter_map(|o| parse_rule(&o["rule"]))
        .collect();
    RuleStore::from_entries(entries)
}

/// Parse one rule object. Returns None for anything not a nat-gate rule.
fn parse_rule(rule: &Value) -> Option<RuleEntry> {
    let comment = rule["comment"].as_str()?;
    let parsed = parse_comment(comment)?;
    let chain = match rule["chain"].as_str()? {
        "prerouting" => Chain::Prerouting,
        "postrouting" => Chain::Postrouting,
        _ => return None,
    };

    let expr = rule["expr"].as_array()?;
    let handle = rule["handle"].as_u64();

    // The transport dport match (payload protocol tcp/udp, field dport),
    // cross-checked against the comment marker — defense in depth.
    let dport_match = expr.iter().find_map(|e| {
        let p = &e["match"]["left"]["payload"];
        match p["protocol"].as_str() {
            Some(pr @ ("tcp" | "udp")) if p["field"].as_str() == Some("dport") => {
                Some((pr, e["match"]["right"].clone()))
            }
            _ => None,
        }
    });
    if let Some((pr, right)) = &dport_match {
        if *pr != parsed.proto {
            return None;
        }
        if let Some(port) = value_to_port(right) {
            if port != parsed.port {
                return None;
            }
        }
    }

    let (interface, target, limit) = match chain {
        Chain::Prerouting => {
            let iface = expr
                .iter()
                .find(|e| e["match"]["left"]["meta"]["key"].as_str() == Some("iifname"))
                .and_then(|e| e["match"]["right"].as_str())
                .map(str::to_string);
            let target = expr
                .iter()
                .find(|e| e.get("dnat").is_some())
                .and_then(|e| e["dnat"]["addr"].as_str())
                .unwrap_or_default()
                .to_string();
            let limit = expr
                .iter()
                .find(|e| e.get("limit").is_some())
                .and_then(|e| {
                    let l = &e["limit"];
                    let rate = l["rate"].as_u64()?;
                    let per = l["per"].as_str()?;
                    Some(format!("{rate}/{per}"))
                });
            (iface, target, limit)
        }
        Chain::Postrouting => {
            let target = expr
                .iter()
                .find(|e| {
                    matches!(
                        e["match"]["left"]["payload"]["field"].as_str(),
                        Some("daddr")
                    )
                })
                .and_then(|e| e["match"]["right"].as_str())
                .unwrap_or_default()
                .to_string();
            (None, target, None)
        }
    };

    let (packets, bytes) = expr
        .iter()
        .find(|e| e.get("counter").is_some())
        .map(|e| {
            let c = &e["counter"];
            (
                c["packets"].as_u64().unwrap_or(0),
                c["bytes"].as_u64().unwrap_or(0),
            )
        })
        .unwrap_or((0, 0));

    Some(RuleEntry {
        chain,
        rule: NatRule {
            proto: parsed.proto,
            port: parsed.port,
            target,
            interface,
            limit,
        },
        packets,
        bytes,
        spec: Vec::new(),
        handle,
    })
}

/// A dport match right side: plain number or `{"range":[lo,hi]}`.
fn value_to_port(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::Object(_) => {
            let r = &v["range"];
            let lo = r[0].as_u64()?;
            let hi = r[1].as_u64()?;
            Some(format!("{lo}-{hi}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `nft -j list table` output captured from nftables 1.1.6:
    /// iifname+limit dnat rule, range dnat rule, masquerade rule.
    const V4_JSON: &str = r#"{"nftables":[{"metainfo":{"version":"1.1.6","release_name":"Commodore Bullmoose #7","json_schema_version":1}},{"table":{"family":"ip","name":"natgate_fx","handle":10}},{"chain":{"family":"ip","table":"natgate_fx","name":"prerouting","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},{"chain":{"family":"ip","table":"natgate_fx","name":"postrouting","handle":2,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},{"rule":{"family":"ip","table":"natgate_fx","chain":"prerouting","handle":3,"comment":"nat-gate:tcp:443","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"counter":{"packets":0,"bytes":0}},{"limit":{"rate":100,"burst":150,"per":"minute"}},{"dnat":{"addr":"192.0.2.99","port":443}}]}},{"rule":{"family":"ip","table":"natgate_fx","chain":"prerouting","handle":4,"comment":"nat-gate:udp:8000-8080","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[8000,8080]}}},{"counter":{"packets":0,"bytes":0}},{"dnat":{"addr":"192.0.2.99","port":{"range":[8000,8080]}}}]}},{"rule":{"family":"ip","table":"natgate_fx","chain":"postrouting","handle":5,"comment":"nat-gate:udp:8000-8080","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.99"}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[8000,8080]}}},{"counter":{"packets":0,"bytes":0}},{"masquerade":null}]}}]}"#;

    /// Real `nft -j list table` output, ip6 family.
    const V6_JSON: &str = r#"{"nftables":[{"metainfo":{"version":"1.1.6","release_name":"Commodore Bullmoose #7","json_schema_version":1}},{"table":{"family":"ip6","name":"natgate_fx","handle":11}},{"chain":{"family":"ip6","table":"natgate_fx","name":"prerouting","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},{"chain":{"family":"ip6","table":"natgate_fx","name":"postrouting","handle":2,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},{"rule":{"family":"ip6","table":"natgate_fx","chain":"prerouting","handle":3,"comment":"nat-gate:tcp:25565","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":25565}},{"counter":{"packets":0,"bytes":0}},{"dnat":{"addr":"fd7a:115c:a1e0::5","port":25565}}]}},{"rule":{"family":"ip6","table":"natgate_fx","chain":"postrouting","handle":4,"comment":"nat-gate:tcp:25565","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":"fd7a:115c:a1e0::5"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":25565}},{"counter":{"packets":0,"bytes":0}},{"masquerade":null}]}}]}"#;

    #[test]
    fn parses_v4_details_from_real_output() {
        let store = parse_table_json(V4_JSON);
        assert_eq!(store.entries().len(), 3);
        assert_eq!(store.rule_count(), 2);

        let rule = store.find("tcp", "443").expect("tcp:443 found");
        assert_eq!(rule.target, "192.0.2.99");
        assert_eq!(rule.interface.as_deref(), Some("eth0"));
        assert_eq!(rule.limit.as_deref(), Some("100/minute"));

        let range = store.find("udp", "8000-8080").expect("range found");
        assert_eq!(range.target, "192.0.2.99");
        assert_eq!(range.interface, None);
        assert_eq!(range.limit, None);
    }

    #[test]
    fn parses_handles_and_chains() {
        let store = parse_table_json(V4_JSON);
        let pre = store
            .entries()
            .iter()
            .find(|e| e.rule.proto == "tcp")
            .expect("tcp entry");
        assert_eq!(pre.chain, Chain::Prerouting);
        assert_eq!(pre.handle, Some(3));
        assert!(pre.spec.is_empty(), "nft entries carry no iptables spec");

        let post = store
            .entries()
            .iter()
            .find(|e| e.chain == Chain::Postrouting)
            .expect("postrouting entry");
        assert_eq!(post.handle, Some(5));
        assert_eq!(post.rule.target, "192.0.2.99");
    }

    #[test]
    fn parses_v6_rules() {
        let store = parse_table_json(V6_JSON);
        assert_eq!(store.rule_count(), 1);
        let rule = store.find("tcp", "25565").expect("v6 rule found");
        assert_eq!(rule.target, "fd7a:115c:a1e0::5");
        assert_eq!(store.entries()[0].handle, Some(3));
    }

    #[test]
    fn ignores_foreign_rules() {
        let json = r#"{"nftables":[
            {"rule":{"chain":"prerouting","handle":1,"expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},
                {"counter":{"packets":9,"bytes":900}},
                {"dnat":{"addr":"10.0.0.1","port":22}}]}},
            {"rule":{"chain":"prerouting","handle":2,"comment":"someone-else:tcp:443","expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
                {"dnat":{"addr":"10.0.0.2","port":443}}]}}
        ]}"#;
        let store = parse_table_json(json);
        assert_eq!(store.entries().len(), 0, "no comment marker = not ours");
    }

    #[test]
    fn cross_check_rejects_mismatched_marker() {
        // Comment says udp but the rule matches tcp.
        let json = r#"{"nftables":[
            {"rule":{"chain":"prerouting","handle":1,"comment":"nat-gate:udp:443","expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
                {"dnat":{"addr":"10.0.0.1","port":443}}]}}
        ]}"#;
        let store = parse_table_json(json);
        assert_eq!(store.entries().len(), 0);
    }

    #[test]
    fn garbage_input_yields_empty_store() {
        let store = parse_table_json("not json at all");
        assert_eq!(store.entries().len(), 0);
        let store = parse_table_json(r#"{"nftables":"unexpected"}"#);
        assert_eq!(store.entries().len(), 0);
    }

    #[test]
    fn counters_parsed_from_real_output() {
        let json = r#"{"nftables":[
            {"rule":{"chain":"prerouting","handle":7,"comment":"nat-gate:tcp:443","expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
                {"counter":{"packets":1234,"bytes":567890}},
                {"dnat":{"addr":"192.0.2.99","port":443}}]}}
        ]}"#;
        let store = parse_table_json(json);
        let e = &store.entries()[0];
        assert_eq!((e.packets, e.bytes), (1234, 567890));
    }
}
