//! Backend selection and dispatch.
//!
//! nat-gate supports two netfilter backends: classic iptables (the
//! default, rules in the built-in nat chains) and native nftables
//! (rules in a dedicated `nat-gate` table). Both share the `RuleStore`
//! model, so every command works identically against either; this
//! module is the single point that decides which executor runs.
//!
//! Selection order: `--backend` CLI flag, then `NAT_GATE_BACKEND`
//! environment variable, then `iptables` (zero behavior change for
//! existing users).

use crate::iptables::rulestore::{Chain, RuleEntry, RuleStore};
use crate::iptables::IptablesExecutor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Iptables = 0,
    Nftables = 1,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Iptables => "iptables",
            Backend::Nftables => "nftables",
        }
    }
}

/// The pinned backend for this process, stored as its discriminant.
/// 0 (iptables) is the default before anything pins a value.
static ACTIVE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn set_active(backend: Backend) {
    ACTIVE.store(backend as u8, std::sync::atomic::Ordering::Relaxed);
}

/// Resolve the backend from an optional `--backend` value and the
/// `NAT_GATE_BACKEND` environment variable, then pin it for the
pub fn configure(cli_value: Option<&str>) -> Result<Backend, String> {
    let raw = match cli_value
        .map(str::to_string)
        .or_else(|| std::env::var("NAT_GATE_BACKEND").ok())
    {
        Some(v) => v,
        None => {
            set_active(Backend::Iptables);
            return Ok(Backend::Iptables);
        }
    };
    let backend = match raw.to_lowercase().as_str() {
        "iptables" | "legacy" => Backend::Iptables,
        "nftables" | "nft" => Backend::Nftables,
        other => {
            return Err(format!(
                "Unknown backend '{other}'. Use 'iptables' or 'nftables'."
            ))
        }
    };

    set_active(backend);
    Ok(backend)
}

/// The pinned backend for this process. Defaults to iptables when
/// [`configure`] was never called.
pub fn active() -> Backend {
    match ACTIVE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => Backend::Nftables,
        _ => Backend::Iptables,
    }
}

/// Load all nat-gate rules for a family.
pub fn load_rules(ipv6: bool) -> Result<RuleStore, String> {
    match active() {
        Backend::Iptables => RuleStore::load(ipv6),
        Backend::Nftables => crate::nftables::executor::load_rules(ipv6),
    }
}

/// Add the PREROUTING (DNAT) half of a rule.
pub fn add_prerouting_rule(
    proto: &str,
    port: &str,
    target: &str,
    interface: Option<&str>,
    ipv6: bool,
    limit: Option<&str>,
) -> Result<(), String> {
    match active() {
        Backend::Iptables => {
            IptablesExecutor::add_prerouting_rule(proto, port, target, interface, ipv6, limit)
        }
        Backend::Nftables => crate::nftables::executor::add_prerouting_rule(
            proto, port, target, interface, ipv6, limit,
        ),
    }
}

/// Add the POSTROUTING (MASQUERADE) half of a rule.
pub fn add_postrouting_rule(
    proto: &str,
    port: &str,
    target: &str,
    ipv6: bool,
) -> Result<(), String> {
    match active() {
        Backend::Iptables => IptablesExecutor::add_postrouting_rule(proto, port, target, ipv6),
        Backend::Nftables => {
            crate::nftables::executor::add_postrouting_rule(proto, port, target, ipv6)
        }
    }
}

/// Post-flush cleanup: nftables drops the now-empty managed table so a
/// flushed system leaves no nat-gate footprint. iptables needs nothing
/// extra (its chains are kernel built-ins).
pub fn finish_flush(ipv6: bool) -> Result<(), String> {
    match active() {
        Backend::Iptables => Ok(()),
        Backend::Nftables => crate::nftables::executor::delete_table(ipv6),
    }
}

/// Delete one parsed entry by its backend-native identity: the exact
/// iptables-save spec, or the stable nftables handle.
pub fn delete_entry(entry: &RuleEntry, ipv6: bool) -> Result<(), String> {
    match active() {
        Backend::Iptables => {
            IptablesExecutor::delete_rule_spec(entry.chain.as_str(), &entry.spec, ipv6)
        }
        Backend::Nftables => match entry.handle {
            Some(handle) => {
                crate::nftables::executor::delete_rule_handle(entry.chain, handle, ipv6)
            }
            None => Err("nftables entry has no rule handle".to_string()),
        },
    }
}

/// The exact commands `--dry-run` should print for adding a rule pair.
pub fn add_rule_commands(
    proto: &str,
    port: &str,
    target: &str,
    interface: Option<&str>,
    ipv6: bool,
    limit: Option<&str>,
) -> Result<Vec<String>, String> {
    match active() {
        Backend::Iptables => {
            let cmd = if ipv6 { "ip6tables" } else { "iptables" };
            let pre =
                IptablesExecutor::prerouting_args(proto, port, target, interface, ipv6, limit)?;
            let post = IptablesExecutor::postrouting_args(proto, port, target)?;
            Ok(vec![
                format_args_command(cmd, &pre),
                format_args_command(cmd, &post),
            ])
        }
        Backend::Nftables => {
            let pre = crate::nftables::executor::prerouting_args(
                proto, port, target, interface, ipv6, limit,
            )?;
            let post = crate::nftables::executor::postrouting_args(proto, port, target, ipv6);
            Ok(vec![format_nft_command(&pre), format_nft_command(&post)])
        }
    }
}

/// The exact command `--dry-run` should print for deleting one entry.
pub fn deletion_command(entry: &RuleEntry, ipv6: bool) -> Option<String> {
    match active() {
        Backend::Iptables => {
            if entry.spec.is_empty() {
                return None;
            }
            let mut args = vec!["-t", "nat", "-D", entry.chain.as_str()];
            args.extend(entry.spec.iter().map(|s| s.as_str()));
            let cmd = if ipv6 { "ip6tables" } else { "iptables" };
            Some(format!("{cmd} {}", args.join(" ")))
        }
        Backend::Nftables => entry.handle.map(|handle| {
            let family = if ipv6 { "ip6" } else { "ip" };
            format!(
                "nft delete rule {family} {} {} handle {handle}",
                crate::nftables::executor::TABLE,
                chain_name(entry.chain)
            )
        }),
    }
}

/// Persist the current ruleset so it survives reboot.
/// iptables: netfilter-persistent / rules.v4+rules.v6.
/// nftables: the managed tables are saved to /etc/nat-gate/nftables.conf
/// in `include`-compatible syntax for /etc/nftables.conf.
pub fn save_rules() -> Result<(), String> {
    match active() {
        Backend::Iptables => crate::utils::save_iptables_rules(),
        Backend::Nftables => save_nft_rules(),
    }
}

/// Probe that the active backend's tooling is installed.
pub fn check_dependencies() -> Result<(), String> {
    match active() {
        Backend::Iptables => crate::utils::check_iptables(),
        Backend::Nftables => {
            if !crate::utils::probe_binary("nft") {
                return Err("nft (nftables) is not installed".to_string());
            }
            Ok(())
        }
    }
}

fn chain_name(chain: Chain) -> &'static str {
    match chain {
        Chain::Prerouting => "prerouting",
        Chain::Postrouting => "postrouting",
    }
}

fn format_args_command(cmd: &str, args: &[String]) -> String {
    format!("{cmd} {}", args.join(" "))
}

fn format_nft_command(args: &[String]) -> String {
    format!("nft {}", args.join(" "))
}

/// Save both families' managed tables to /etc/nat-gate/nftables.conf in
/// `include`-compatible syntax (add `include "/etc/nat-gate/nftables.conf"`
/// to /etc/nftables.conf to restore at boot). Families without a table
/// are skipped; when nothing is managed, a stale conf is removed so it
/// cannot resurrect deleted rules.
fn save_nft_rules() -> Result<(), String> {
    use std::fs;
    use std::process::Command;

    let mut out = String::new();
    out.push_str("# Managed by nat-gate; include from /etc/nftables.conf to restore at boot.\n");

    let mut wrote_any = false;
    for (ipv6, family) in [(false, "ip"), (true, "ip6")] {
        if !crate::nftables::executor::table_exists(ipv6)? {
            continue;
        }
        let output = Command::new("nft")
            .args([
                "-s",
                "list",
                "table",
                family,
                crate::nftables::executor::TABLE,
            ])
            .output()
            .map_err(|e| format!("Failed to execute nft: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "Failed to export nft table: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        out.push_str(&String::from_utf8_lossy(&output.stdout));
        out.push('\n');
        wrote_any = true;
    }

    if !wrote_any {
        // No managed tables: any saved conf is stale and would resurrect
        // deleted rules at boot. Remove it.
        let _ = fs::remove_file("/etc/nat-gate/nftables.conf");
        return Ok(());
    }

    fs::create_dir_all("/etc/nat-gate")
        .map_err(|e| format!("Failed to create /etc/nat-gate: {e}"))?;
    fs::write("/etc/nat-gate/nftables.conf", out)
        .map_err(|e| format!("Failed to write /etc/nat-gate/nftables.conf: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configure_parses_names() {
        assert_eq!(configure(Some("iptables")).unwrap(), Backend::Iptables);
        assert_eq!(configure(Some("NFTABLES")).unwrap(), Backend::Nftables);
        assert!(configure(Some("pfsense")).is_err());
    }

    /// The active backend is process-global (OnceLock), so every test
    /// that touches it runs sequentially inside this one function.
    /// It also pins the iptables default first, covering the
    /// no-configuration case.
    #[test]
    fn deletion_command_dispatches_by_active_backend() {
        let rule = crate::iptables::rulestore::NatRule {
            proto: "tcp".into(),
            port: "443".into(),
            target: "192.0.2.99".into(),
            interface: None,
            limit: None,
        };

        // Default with no configuration: iptables.
        set_active(Backend::Iptables);
        assert_eq!(active(), Backend::Iptables);

        // iptables: exact spec deletion.
        let entry = RuleEntry {
            chain: Chain::Prerouting,
            rule: rule.clone(),
            packets: 0,
            bytes: 0,
            spec: vec!["-p".into(), "tcp".into(), "--dport".into(), "443".into()],
            handle: None,
        };
        assert_eq!(
            deletion_command(&entry, false).unwrap(),
            "iptables -t nat -D PREROUTING -p tcp --dport 443"
        );

        // nftables: handle-based deletion.
        set_active(Backend::Nftables);
        let entry = RuleEntry {
            chain: Chain::Prerouting,
            rule,
            packets: 0,
            bytes: 0,
            spec: Vec::new(),
            handle: Some(7),
        };
        assert_eq!(
            deletion_command(&entry, false).unwrap(),
            "nft delete rule ip nat-gate prerouting handle 7"
        );

        // Reset so later tests see the default.
        set_active(Backend::Iptables);
    }
}
