//! nftables backend: builds and executes `nft` commands for nat-gate rules.
//!
//! nat-gate owns a dedicated table per family (`nat-gate` in `ip`/`ip6`)
//! with two base chains mirroring the iptables layout. Rules carry the same
//! `nat-gate:<proto>:<port>` comment marker, so both backends share the
//! `RuleStore` model. Deletion is handle-based (`nft delete rule … handle N`)
//! — nft's native equivalent of iptables spec-deletion, immune to
//! line-number shifts.
//!
//! All command forms in this module were validated against nftables 1.1.6:
//! statements cannot be chained in one argv (parse is all-or-nothing), so
//! table/chain creation issues three separate invocations, each a silent
//! no-op when its object already exists.

use std::process::Command;

use crate::iptables::rulestore::{Chain, RuleStore};

/// The nftables family keyword for an IP version.
fn family(ipv6: bool) -> &'static str {
    if ipv6 {
        "ip6"
    } else {
        "ip"
    }
}

/// Table nat-gate manages exclusively.
pub const TABLE: &str = "nat-gate";

/// Chain names inside the table (nft identifiers, not hooks).
fn chain_name(chain: Chain) -> &'static str {
    match chain {
        Chain::Prerouting => "prerouting",
        Chain::Postrouting => "postrouting",
    }
}

/// Create the managed table and its two base chains if missing.
/// Each `nft add` is a silent no-op when the object already exists.
pub fn ensure_table(ipv6: bool) -> Result<(), String> {
    let f = family(ipv6);
    run(&["add", "table", f, TABLE], "create nft table")?;
    run(
        &[
            "add",
            "chain",
            f,
            TABLE,
            "prerouting",
            "{ type nat hook prerouting priority dstnat; policy accept; }",
        ],
        "create prerouting chain",
    )?;
    run(
        &[
            "add",
            "chain",
            f,
            TABLE,
            "postrouting",
            "{ type nat hook postrouting priority srcnat; policy accept; }",
        ],
        "create postrouting chain",
    )?;
    Ok(())
}

/// Does the managed table exist in this family?
/// `nft list table` fails with a message-less echo for absent tables, so
/// existence is decided from `nft -j list tables` instead.
pub fn table_exists(ipv6: bool) -> Result<bool, String> {
    let output = Command::new("nft")
        .args(["-j", "list", "tables"])
        .output()
        .map_err(|e| format!("Failed to execute nft: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to list nft tables: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("Invalid nft JSON: {e}"))?;
    let want_family = if ipv6 { "ip6" } else { "ip" };
    Ok(json["nftables"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .any(|t| t["table"]["family"] == want_family && t["table"]["name"] == TABLE)
        })
        .unwrap_or(false))
}

/// Format a port or range for nft ("8000-8080" passes through; nft uses
/// the same dash form nat-gate's model does).
fn port_spec(port: &str) -> String {
    port.replace(':', "-")
}

/// Format a DNAT destination: `addr:port`, `[addr]:port` for IPv6.
fn dnat_target(target: &str, port: &str, ipv6: bool) -> String {
    let ports = port_spec(port);
    if ipv6 && target.contains(':') {
        format!("[{target}]:{ports}")
    } else {
        format!("{target}:{ports}")
    }
}

/// Build the argv for a prerouting DNAT rule.
/// Exposed so `--dry-run` can print the exact command.
pub fn prerouting_args(
    proto: &str,
    port: &str,
    target: &str,
    interface: Option<&str>,
    ipv6: bool,
    limit: Option<&str>,
) -> Result<Vec<String>, String> {
    let comment = crate::iptables::IptablesExecutor::comment_marker(proto, port);
    let mut stmt = String::new();
    if let Some(iface) = interface {
        stmt.push_str(&format!("iifname \"{iface}\" "));
    }
    stmt.push_str(&format!("{proto} dport {} ", port_spec(port)));
    stmt.push_str("counter ");
    if let Some(l) = limit {
        let (rate, burst) = crate::iptables::IptablesExecutor::parse_rate_limit(l)?;
        stmt.push_str(&format!("limit rate {rate} burst {burst} packets "));
    }
    stmt.push_str(&format!("dnat to {} ", dnat_target(target, port, ipv6)));
    stmt.push_str(&format!("comment \"{comment}\""));

    Ok(vec![
        "add".into(),
        "rule".into(),
        family(ipv6).into(),
        TABLE.into(),
        chain_name(Chain::Prerouting).into(),
        stmt,
    ])
}

/// Build the argv for a postrouting MASQUERADE rule.
/// Exposed so `--dry-run` can print the exact command.
pub fn postrouting_args(proto: &str, port: &str, target: &str, ipv6: bool) -> Vec<String> {
    let comment = crate::iptables::IptablesExecutor::comment_marker(proto, port);
    let addr_kw = if ipv6 { "ip6 daddr" } else { "ip daddr" };
    let stmt = format!(
        "{addr_kw} {target} {proto} dport {} counter masquerade comment \"{comment}\"",
        port_spec(port)
    );
    vec![
        "add".into(),
        "rule".into(),
        family(ipv6).into(),
        TABLE.into(),
        chain_name(Chain::Postrouting).into(),
        stmt,
    ]
}

/// Create the table and chains if missing, then add the prerouting rule.
pub fn add_prerouting_rule(
    proto: &str,
    port: &str,
    target: &str,
    interface: Option<&str>,
    ipv6: bool,
    limit: Option<&str>,
) -> Result<(), String> {
    ensure_table(ipv6)?;
    let args = prerouting_args(proto, port, target, interface, ipv6, limit)?;
    run(
        &args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "add prerouting rule",
    )
}

/// Create the table and chains if missing, then add the postrouting rule.
pub fn add_postrouting_rule(
    proto: &str,
    port: &str,
    target: &str,
    ipv6: bool,
) -> Result<(), String> {
    ensure_table(ipv6)?;
    let args = postrouting_args(proto, port, target, ipv6);
    run(
        &args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "add postrouting rule",
    )
}

/// Delete a rule by its stable kernel handle.
pub fn delete_rule_handle(chain: Chain, handle: u64, ipv6: bool) -> Result<(), String> {
    run(
        &[
            "delete",
            "rule",
            family(ipv6),
            TABLE,
            chain_name(chain),
            "handle",
            &handle.to_string(),
        ],
        "delete rule",
    )
}

/// Delete the entire managed table (flush's clean slate).
/// Absent table is success.
pub fn delete_table(ipv6: bool) -> Result<(), String> {
    if !table_exists(ipv6)? {
        return Ok(());
    }
    run(
        &["delete", "table", family(ipv6), TABLE],
        "delete nft table",
    )
}

/// Read the managed table as JSON (`nft -j list table`).
/// Empty string when the table does not exist yet.
pub fn list_table_json(ipv6: bool) -> Result<String, String> {
    if !table_exists(ipv6)? {
        return Ok(String::new());
    }
    let output = Command::new("nft")
        .args(["-j", "list", "table", family(ipv6), TABLE])
        .output()
        .map_err(|e| format!("Failed to execute nft: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to list nft table: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Load the nat-gate rules from the nftables table.
pub fn load_rules(ipv6: bool) -> Result<RuleStore, String> {
    let json = list_table_json(ipv6)?;
    if json.is_empty() {
        return Ok(RuleStore::from_entries(Vec::new()));
    }
    Ok(crate::nftables::rulestore::parse_table_json(&json))
}

fn run(args: &[&str], action: &str) -> Result<(), String> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute nft: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to {action}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prerouting_argv_matches_kernel_validated_form() {
        let args = prerouting_args(
            "tcp",
            "443",
            "192.0.2.99",
            Some("eth0"),
            false,
            Some("100/min"),
        )
        .unwrap();
        assert_eq!(
            args,
            vec![
                "add".to_string(),
                "rule".into(),
                "ip".into(),
                TABLE.into(),
                "prerouting".into(),
                "iifname \"eth0\" tcp dport 443 counter limit rate 100/minute burst 150 packets dnat to 192.0.2.99:443 comment \"nat-gate:tcp:443\"".into(),
            ]
        );
    }

    #[test]
    fn prerouting_v6_brackets_target() {
        let args = prerouting_args("tcp", "25565", "fd7a:115c:a1e0::5", None, true, None).unwrap();
        assert_eq!(
            args[5],
            "tcp dport 25565 counter dnat to [fd7a:115c:a1e0::5]:25565 comment \"nat-gate:tcp:25565\""
        );
    }

    #[test]
    fn prerouting_range_and_no_limit() {
        let args = prerouting_args("udp", "8000-8080", "192.0.2.99", None, false, None).unwrap();
        assert_eq!(
            args[5],
            "udp dport 8000-8080 counter dnat to 192.0.2.99:8000-8080 comment \"nat-gate:udp:8000-8080\""
        );
    }

    #[test]
    fn postrouting_argv_matches_kernel_validated_form() {
        let args = postrouting_args("udp", "8000-8080", "192.0.2.99", false);
        assert_eq!(
            args,
            vec![
                "add".to_string(),
                "rule".into(),
                "ip".into(),
                TABLE.into(),
                "postrouting".into(),
                "ip daddr 192.0.2.99 udp dport 8000-8080 counter masquerade comment \"nat-gate:udp:8000-8080\"".into(),
            ]
        );
    }

    #[test]
    fn postrouting_v6_uses_ip6_daddr() {
        let args = postrouting_args("tcp", "25565", "fd7a:115c:a1e0::5", true);
        assert!(args[5].starts_with("ip6 daddr fd7a:115c:a1e0::5"));
    }

    #[test]
    fn delete_rule_handle_argv() {
        // Shape only; execution needs root.
        assert_eq!(chain_name(Chain::Prerouting), "prerouting");
        assert_eq!(chain_name(Chain::Postrouting), "postrouting");
        assert_eq!(family(false), "ip");
        assert_eq!(family(true), "ip6");
    }
}
