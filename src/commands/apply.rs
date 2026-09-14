use std::collections::HashSet;

use colored::Colorize;
use serde::Serialize;
use serde_json;

use crate::backend;
use crate::config::{load_config_from_path_or_default, RuleConfig};
use crate::iptables::rulestore::{canonical_port, NatRule};
use crate::output;
use crate::utils::check_root;

pub fn run(config_path: Option<&str>, dry_run: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks (skip if dry-run)
    if !dry_run {
        check_root()?;
        backend::check_dependencies()?;
    }

    // Load config file
    let (path, config) = load_config_from_path_or_default(config_path)?;

    if !json_output && !dry_run {
        println!("{}", format!("Applying rules from {path:?}").blue().bold());
    }

    if config.rules.is_empty() {
        if json_output {
            output::print_error("No rules defined in config file");
        } else {
            println!("{}", "No rules defined in config file.".yellow());
        }
        return Ok(());
    }

    if !json_output && !dry_run {
        println!("  Found {} rule(s) in config", config.rules.len());
    }

    // Validate all rules first
    for rule in &config.rules {
        rule.validate()?;
    }

    let mut dry_run_actions = Vec::new();
    let mut success_count = 0;
    let mut skipped_count = 0;

    for rule in &config.rules {
        let result = apply_rule(rule, dry_run, json_output, &mut dry_run_actions)?;
        match result {
            ApplyResult::Added => success_count += 1,
            ApplyResult::Skipped => skipped_count += 1,
            ApplyResult::DryRun => {}
        }
    }

    if dry_run {
        if json_output {
            output::print_dry_run_actions(dry_run_actions);
        } else {
            println!(
                "\n{}",
                format!("[DRY-RUN] Would apply {} rule(s)", config.rules.len())
                    .yellow()
                    .bold()
            );
        }
        return Ok(());
    }

    // Save rules
    if success_count > 0 {
        if !json_output {
            print!("  Saving rules... ");
        }
        match backend::save_rules() {
            Ok(_) => {
                if !json_output {
                    println!("{}", "OK".green());
                }
            }
            Err(e) => {
                if !json_output {
                    println!("{}", "WARNING".yellow());
                    println!("    {}", e.yellow());
                }
            }
        }
    }

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "applied": success_count,
            "skipped": skipped_count,
            "total": config.rules.len(),
            "config_file": path.to_string_lossy()
        }));
    } else {
        println!(
            "\n{}",
            format!("Applied {success_count} rule(s), skipped {skipped_count} (already existed)")
                .green()
                .bold()
        );
    }

    Ok(())
}

enum ApplyResult {
    Added,
    Skipped,
    DryRun,
}

fn apply_rule(
    rule: &RuleConfig,
    dry_run: bool,
    json_output: bool,
    dry_run_actions: &mut Vec<serde_json::Value>,
) -> Result<ApplyResult, String> {
    let ip_version = if rule.ipv6 { "IPv6" } else { "IPv4" };
    let iface_info = rule
        .interface
        .as_ref()
        .map(|i| format!(" on {i}"))
        .unwrap_or_default();

    if dry_run {
        let action = serde_json::json!({
            "action": "add_rule",
            "protocol": rule.protocol,
            "port": rule.port,
            "target": rule.target,
            "interface": rule.interface,
            "ipv6": rule.ipv6,
            "limit": rule.limit
        });
        dry_run_actions.push(action);

        if !json_output {
            println!(
                "{} Would add: {} {} {} -> {}{}",
                "[DRY-RUN]".yellow(),
                ip_version,
                rule.protocol.to_uppercase(),
                rule.port,
                rule.target,
                iface_info
            );
        }
        return Ok(ApplyResult::DryRun);
    }

    // Check if rule already exists (exact marker match)
    let store = backend::load_rules(rule.ipv6)?;
    if store.find(&rule.protocol, &rule.port).is_some() {
        if !json_output {
            println!(
                "  {} {} {} {} (already exists)",
                "Skipping".yellow(),
                ip_version,
                rule.protocol.to_uppercase(),
                rule.port
            );
        }
        return Ok(ApplyResult::Skipped);
    }

    // Add the rules
    if !json_output {
        print!(
            "  Adding {} {} {} -> {}{}... ",
            ip_version,
            rule.protocol.to_uppercase(),
            rule.port,
            rule.target,
            iface_info
        );
    }

    backend::add_prerouting_rule(
        &rule.protocol,
        &rule.port,
        &rule.target,
        rule.interface.as_deref(),
        rule.ipv6,
        rule.limit.as_deref(),
    )?;

    backend::add_postrouting_rule(&rule.protocol, &rule.port, &rule.target, rule.ipv6)?;

    if !json_output {
        println!("{}", "OK".green());
    }

    Ok(ApplyResult::Added)
}

/// `nat-gate apply --check` — compare the YAML config against live rules
/// and report drift. Read-only: never adds, deletes, or saves rules.
/// Exits 1 when the config and live state diverge (mirrors `doctor`);
/// `Ok(())` means the two are in sync.
pub fn check_drift(config_path: Option<&str>, json_output: bool) -> Result<(), String> {
    let (path, config) = load_config_from_path_or_default(config_path)?;

    // Validate all rules first (same loop as `run`).
    for rule in &config.rules {
        rule.validate()?;
    }

    // Load live state from both address families — read-only.
    let v4 = backend::load_rules(false)?;
    let v6 = backend::load_rules(true)?;
    let mut live_rules: Vec<NatRule> = v4.rules().cloned().collect();
    live_rules.extend(v6.rules().cloned());

    let report = compute_drift(&config.rules, &live_rules);
    let in_sync = report.missing_in_live.is_empty() && report.missing_in_config.is_empty();

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "in_sync": in_sync,
                "missing_in_live": report.missing_in_live,
                "missing_in_config": report.missing_in_config,
                "matched": report.matched
            }
        }));
        // Ok(()) means clean; drift is signaled by exit 1 in both modes,
        // mirroring `doctor` after it has printed its JSON report.
        if !in_sync {
            std::process::exit(1);
        }
        return Ok(());
    }

    let add = report.missing_in_live.len();
    let rem = report.missing_in_config.len();

    println!(
        "{}",
        format!("Drift check against config: {}", path.display())
            .blue()
            .bold()
    );
    println!();

    // In-config-but-missing-live: these rules the system lacks (would be added).
    println!(
        "  {} ({add})",
        "Missing in live (would be added)".yellow().bold()
    );
    for id in &report.missing_in_live {
        println!("    {} {}", "+".yellow(), format_identity(id));
    }
    println!();

    // In-live-but-missing-config: these rules are orphaned (would be removed).
    println!(
        "  {} ({rem})",
        "Missing in config (would be removed)".red().bold()
    );
    for id in &report.missing_in_config {
        println!("    {} {}", "-".red(), format_identity(id));
    }
    println!();

    println!("  Matched: {}", report.matched.to_string().green());
    println!();

    if in_sync {
        println!(
            "{}",
            format!("In sync: {} rule(s) match", report.matched)
                .green()
                .bold()
        );
        Ok(())
    } else {
        println!(
            "{}",
            format!("Drift detected: {add} to add, {rem} to remove")
                .red()
                .bold()
        );
        // Ok(()) means clean; drift is signaled by a non-zero exit, just
        // like `doctor` after it has printed its report.
        std::process::exit(1);
    }
}

// ── drift comparison core ────────────────────────────────────────────────
//
// The comparison is a pure set-diff over normalized identity tuples so it
// carries no kernel/IO and tests for free. The IO wrapper above feeds it
// `RuleConfig` (config side) and `NatRule` (live side); each is projected
// through the same normalizer so the config and live shapes reconcile.

/// One rule's identity as a comparable key: the 5-tuple the live store
/// records. Fields are in canonical form (proto lowercase, port dash form,
/// target IP-only without brackets, limit as `rate/unit`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
struct RuleIdentity {
    proto: String,
    port: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<String>,
}

/// Normalize one rule's fields into a `RuleIdentity`. Applied to both the
/// config and live sides so the two shapes line up: config ports may use
/// dash ranges, protocols may be any case, IPv6 targets may be bracketed,
/// and limits arrive in user shorthand. This mirrors exactly what an
/// applied config rule becomes in the live store (`apply_rule` →
/// `backend::add_prerouting_rule` → `parse_rate_limit`), not a second guess.
fn make_identity(
    proto: String,
    port: String,
    target: String,
    interface: Option<String>,
    limit: Option<String>,
) -> RuleIdentity {
    RuleIdentity {
        proto: proto.to_lowercase(),
        port: canonical_port(&port),
        target: target.trim_matches(|c| c == '[' || c == ']').to_string(),
        interface,
        limit: limit.map(|l| canonical_limit(&l)),
    }
}

/// Project a config rule into its live-equivalent identity.
fn project_config(rule: &RuleConfig) -> RuleIdentity {
    make_identity(
        rule.protocol.clone(),
        rule.port.clone(),
        rule.target.clone(),
        rule.interface.clone(),
        rule.limit.clone(),
    )
}

/// Project an already-parsed live rule into the same identity shape. Live
/// rules are canonical on parse; this re-normalizes defensively (all ops
/// are idempotent) so the two sides pass through one code path.
fn project_live(rule: &NatRule) -> RuleIdentity {
    make_identity(
        rule.proto.clone(),
        rule.port.clone(),
        rule.target.clone(),
        rule.interface.clone(),
        rule.limit.clone(),
    )
}

/// Canonicalize a rate-limit string using the single shared mapping
/// (`IptablesExecutor::parse_rate_limit`): both backends emit the identical
/// `rate/unit` form, so `100/min`, `100/m`, `100/minute` all collapse to
/// `100/minute`. On any parse failure the input is passed through lowercased
/// rather than dropped, since `RuleConfig::validate` already gated bad input.
fn canonical_limit(limit: &str) -> String {
    crate::iptables::IptablesExecutor::parse_rate_limit(limit)
        .map(|(rate, _)| rate)
        .unwrap_or_else(|_| limit.to_lowercase())
}

/// Drift between the config and live rule sets.
#[derive(Debug)]
struct DriftReport {
    /// In config but missing from live (would be added by `apply`).
    missing_in_live: Vec<RuleIdentity>,
    /// In live but missing from config (would be removed by `flush`/`del`).
    missing_in_config: Vec<RuleIdentity>,
    /// Rules whose normalized identities appear on both sides.
    matched: usize,
}

/// Pure set-diff: compare normalized config rules against normalized live
/// rules. Takes the raw config and live rule types and does no IO, so it is
/// directly unit-testable. Results are sorted for stable output and tests.
fn compute_drift(config_rules: &[RuleConfig], live_rules: &[NatRule]) -> DriftReport {
    let config_set: HashSet<RuleIdentity> = config_rules.iter().map(project_config).collect();
    let live_set: HashSet<RuleIdentity> = live_rules.iter().map(project_live).collect();

    let matched = config_set.intersection(&live_set).count();

    let mut missing_in_live: Vec<RuleIdentity> =
        config_set.difference(&live_set).cloned().collect();
    missing_in_live.sort();

    let mut missing_in_config: Vec<RuleIdentity> =
        live_set.difference(&config_set).cloned().collect();
    missing_in_config.sort();

    DriftReport {
        missing_in_live,
        missing_in_config,
        matched,
    }
}

/// Render one identity for human output: `TCP 443 -> 100.64.0.5 iface eth0`.
fn format_identity(id: &RuleIdentity) -> String {
    let mut s = format!("{} {} -> {}", id.proto.to_uppercase(), id.port, id.target);
    if let Some(iface) = &id.interface {
        s.push_str(&format!(" iface {iface}"));
    }
    if let Some(limit) = &id.limit {
        s.push_str(&format!(" limit {limit}"));
    }
    s
}

#[cfg(test)]
mod drift_tests {
    use super::*;
    use crate::config::RuleConfig;

    fn cfg(proto: &str, port: &str, target: &str) -> RuleConfig {
        RuleConfig {
            protocol: proto.to_string(),
            port: port.to_string(),
            target: target.to_string(),
            interface: None,
            ipv6: false,
            limit: None,
        }
    }

    fn live(proto: &str, port: &str, target: &str) -> NatRule {
        NatRule {
            proto: proto.to_string(),
            port: port.to_string(),
            target: target.to_string(),
            interface: None,
            limit: None,
        }
    }

    #[test]
    fn identical_sets_are_in_sync() {
        let config = vec![cfg("tcp", "443", "100.64.0.5")];
        let live = vec![live("tcp", "443", "100.64.0.5")];
        let r = compute_drift(&config, &live);
        assert!(r.missing_in_live.is_empty());
        assert!(r.missing_in_config.is_empty());
        assert_eq!(r.matched, 1);
    }

    #[test]
    fn config_rule_missing_in_live_would_be_added() {
        // set-diff config -> live: a config rule not present live.
        let config = vec![cfg("tcp", "443", "100.64.0.5")];
        let r = compute_drift(&config, &[]);
        assert_eq!(r.missing_in_live.len(), 1);
        assert!(r.missing_in_config.is_empty());
        assert_eq!(r.matched, 0);
    }

    #[test]
    fn live_rule_missing_in_config_would_be_removed() {
        // set-diff live -> config: a live rule not present in config.
        let live = vec![live("udp", "51820", "100.64.0.10")];
        let r = compute_drift(&[], &live);
        assert!(r.missing_in_live.is_empty());
        assert_eq!(r.missing_in_config.len(), 1);
        assert_eq!(r.matched, 0);
    }

    #[test]
    fn drift_runs_both_directions_at_once() {
        let config = vec![cfg("tcp", "443", "100.64.0.5")];
        let live = vec![live("udp", "53", "10.0.0.1")];
        let r = compute_drift(&config, &live);
        assert_eq!(r.missing_in_live.len(), 1);
        assert_eq!(r.missing_in_config.len(), 1);
        assert_eq!(r.matched, 0);
    }

    #[test]
    fn port_range_config_matches_live_single_projection() {
        // A config range "8000-8080" applies as one NatRule whose port is
        // the dash form; drift must treat them as the same rule.
        let config = vec![cfg("tcp", "8000-8080", "100.64.0.5")];
        let live = vec![live("tcp", "8000-8080", "100.64.0.5")];
        let r = compute_drift(&config, &live);
        assert_eq!(r.matched, 1);
        assert!(r.missing_in_live.is_empty());
        assert!(r.missing_in_config.is_empty());
    }

    #[test]
    fn limit_user_shorthand_matches_canonical_live_form() {
        // Config stores user shorthand "100/min"; the live store records the
        // canonical "100/minute" both backends emit. They are the same rule.
        let mut config = cfg("tcp", "443", "100.64.0.5");
        config.limit = Some("100/min".to_string());
        let live = vec![NatRule {
            proto: "tcp".to_string(),
            port: "443".to_string(),
            target: "100.64.0.5".to_string(),
            interface: None,
            limit: Some("100/minute".to_string()),
        }];
        let r = compute_drift(&[config], &live);
        assert_eq!(r.matched, 1);
        assert!(r.missing_in_live.is_empty());
        assert!(r.missing_in_config.is_empty());
    }

    #[test]
    fn interface_difference_is_drift() {
        let mut config = cfg("tcp", "443", "100.64.0.5");
        config.interface = Some("eth0".to_string());
        let live = vec![live("tcp", "443", "100.64.0.5")];
        let r = compute_drift(&[config], &live);
        assert_eq!(r.matched, 0);
        // Tuples differ both ways -> surfaces in both buckets.
        assert_eq!(r.missing_in_live.len(), 1);
        assert_eq!(r.missing_in_config.len(), 1);
    }

    #[test]
    fn target_difference_is_drift() {
        let config = vec![cfg("tcp", "443", "100.64.0.5")];
        let live = vec![live("tcp", "443", "100.64.0.6")];
        let r = compute_drift(&config, &live);
        assert_eq!(r.matched, 0);
        assert_eq!(r.missing_in_live.len(), 1);
        assert_eq!(r.missing_in_config.len(), 1);
    }

    #[test]
    fn proto_case_and_bracketed_ipv6_target_normalize() {
        // Defensive: a config written with uppercase proto and bracketed
        // IPv6 must match its live counterpart, which is stored lowercase
        // and bracket-free.
        let mut config = cfg("TCP", "443", "[fd7a::5]");
        config.ipv6 = true;
        let live = vec![NatRule {
            proto: "tcp".to_string(),
            port: "443".to_string(),
            target: "fd7a::5".to_string(),
            interface: None,
            limit: None,
        }];
        let r = compute_drift(&[config], &live);
        assert_eq!(r.matched, 1);
        assert!(r.missing_in_live.is_empty());
        assert!(r.missing_in_config.is_empty());
    }

    #[test]
    fn empty_config_and_empty_live_is_in_sync() {
        let r = compute_drift(&[], &[]);
        assert!(r.missing_in_live.is_empty());
        assert!(r.missing_in_config.is_empty());
        assert_eq!(r.matched, 0);
    }
}
