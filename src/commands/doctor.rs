//! System-level diagnostics for the nat-gate forwarding path.
//!
//! `nat-gate doctor` inspects the preconditions a forward needs to work:
//! backend tooling, kernel forwarding, the Tailscale interface, loaded
//! rules, installed-unit/backend consistency, boot persistence, and
//! conntrack availability for session tracking. It is read-only and
//! exits non-zero when any check fails, so it can gate scripts.

use crate::backend;
use crate::output;
use colored::Colorize;
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::process::Command;

const TS_IFACE: &str = "tailscale0";
const MAIN_UNIT: &str = "/etc/systemd/system/nat-gate.service";
const LOGGER_UNIT: &str = "/etc/systemd/system/nat-gate-logger.service";
const NFT_CONF: &str = "/etc/nat-gate/nftables.conf";
const SYSTEM_NFT_CONF: &str = "/etc/nftables.conf";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Serialize)]
struct Check {
    name: String,
    status: Status,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

impl Check {
    fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Pass,
            detail: detail.into(),
            hint: None,
        }
    }

    fn warn(name: &str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Warn,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }

    fn fail(name: &str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }
}

pub fn run(json: bool) -> Result<(), String> {
    let root = is_root();
    let checks = collect_checks();

    let passes = checks.iter().filter(|c| c.status == Status::Pass).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();

    if json {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "backend": backend::active().as_str(),
                "root": root,
                "checks": checks,
                "summary": {
                    "passed": passes,
                    "warnings": warns,
                    "failures": fails,
                },
            }
        }));
    } else {
        println!("{}", "nat-gate doctor".blue().bold());
        println!("  Backend: {}", backend::active().as_str().cyan().bold());
        if !root {
            println!(
                "  {}",
                "Note: not running as root — rule inspection may be limited.".yellow()
            );
        }
        println!();

        for check in &checks {
            print_check(check);
        }
        println!();

        if fails > 0 {
            println!(
                "{}",
                format!("{fails} check(s) failed. Review the issues above.")
                    .red()
                    .bold()
            );
        } else if warns > 0 {
            println!(
                "{}",
                format!("All critical checks passed; {warns} warning(s).").yellow()
            );
        } else {
            println!("{}", "All checks passed!".green().bold());
        }
    }

    if fails > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn print_check(check: &Check) {
    let tag = match check.status {
        Status::Pass => " OK ".green(),
        Status::Warn => "WARN".yellow(),
        Status::Fail => "FAIL".red().bold(),
    };
    let label = format!("{:<24}", check.name).bold();
    println!("  [{tag}] {label} {}", check.detail);
    if let Some(hint) = &check.hint {
        println!("         {} {}", "fix:".cyan(), hint);
    }
}

fn collect_checks() -> Vec<Check> {
    let mut checks = Vec::new();

    checks.push(match backend::check_dependencies() {
        Ok(()) => Check::pass(
            "Backend tooling",
            format!("{} backend tools present", backend::active().as_str()),
        ),
        Err(e) => Check::fail(
            "Backend tooling",
            e,
            "install iptables or nftables (see your distribution's packages)",
        ),
    });

    // Load rule counts once: they feed the rules check and decide
    // whether the IPv6 forwarding check is relevant at all.
    let v4_rules = backend::load_rules(false).map(|s| s.rule_count());
    let v6_rules = backend::load_rules(true).map(|s| s.rule_count());

    match (&v4_rules, &v6_rules) {
        (Ok(a), Ok(b)) if a + b == 0 => checks.push(Check::warn(
            "Forwarding rules",
            "none configured",
            "nat-gate add tcp <port> <target-ip>",
        )),
        (Ok(a), Ok(b)) => checks.push(Check::pass(
            "Forwarding rules",
            format!("{a} IPv4, {b} IPv6 rule(s) loaded"),
        )),
        _ => checks.push(Check::warn(
            "Forwarding rules",
            "could not read rules — run as root",
            "sudo nat-gate doctor",
        )),
    }

    checks.push(if read_flag("/proc/sys/net/ipv4/ip_forward") {
        Check::pass("IP forwarding (IPv4)", "enabled")
    } else {
        Check::fail(
            "IP forwarding (IPv4)",
            "disabled — no IPv4 forward can work",
            "sudo nat-gate init",
        )
    });

    if matches!(&v6_rules, Ok(n) if *n > 0) {
        checks.push(if read_flag("/proc/sys/net/ipv6/conf/all/forwarding") {
            Check::pass("IP forwarding (IPv6)", "enabled")
        } else {
            Check::fail(
                "IP forwarding (IPv6)",
                "disabled but IPv6 rules are present",
                "sudo nat-gate init -6",
            )
        });
    }

    checks.push(check_tailscale());
    checks.extend(check_unit_backend(MAIN_UNIT, "Service unit backend"));
    checks.extend(check_unit_backend(LOGGER_UNIT, "Logger unit backend"));
    checks.extend(check_persistence(&v4_rules, &v6_rules));
    checks.extend(check_service_enabled());

    checks.push(if crate::utils::probe_binary("conntrack") {
        Check::pass("Conntrack", "present (sessions and logging can work)")
    } else {
        Check::warn(
            "Conntrack",
            "conntrack not installed — sessions and the log daemon cannot work",
            "apt install conntrack / pacman -S conntrack-tools",
        )
    });

    checks
}

fn read_flag(path: &str) -> bool {
    fs::read_to_string(path)
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn is_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .map(|uid| uid == "0")
        })
        .unwrap_or(false)
}

fn check_tailscale() -> Check {
    let operstate = fs::read_to_string(format!("/sys/class/net/{TS_IFACE}/operstate"))
        .map(|s| s.trim().to_string())
        .ok();
    match operstate {
        // TUN devices legitimately report "unknown" while up.
        Some(state) if state == "up" || state == "unknown" => Check::pass(
            "Tailscale interface",
            format!("{TS_IFACE} present (state: {state})"),
        ),
        Some(state) => Check::warn(
            "Tailscale interface",
            format!("{TS_IFACE} is {state}"),
            "tailscale up",
        ),
        None => Check::warn(
            "Tailscale interface",
            format!("{TS_IFACE} not found — forwards target Tailscale peers"),
            "start Tailscale (tailscale up)",
        ),
    }
}

/// Extract the baked `Environment=NAT_GATE_BACKEND=` value from a unit's
/// text. Returns `Some(None)` when the unit exists but carries no line.
fn unit_backend_env_from_str(unit: &str) -> Option<Option<String>> {
    Some(unit.lines().find_map(|l| {
        l.trim()
            .strip_prefix("Environment=")
            .map(|v| v.trim_matches('"'))
            .and_then(|v| v.strip_prefix("NAT_GATE_BACKEND="))
            .map(str::to_string)
    }))
}

fn unit_backend_env(path: &str) -> Option<Option<String>> {
    unit_backend_env_from_str(&fs::read_to_string(path).ok()?)
}

fn check_unit_backend(path: &str, name: &str) -> Option<Check> {
    let env = unit_backend_env(path)?;
    let active = backend::active().as_str();
    Some(match env.as_deref() {
        Some(b) if b == active => {
            Check::pass(name, format!("unit uses {b} (matches active backend)"))
        }
        Some(b) => Check::warn(
            name,
            format!("unit uses {b} but the active backend is {active}"),
            format!("sudo nat-gate --backend {active} service install"),
        ),
        // The pre-2.1.1 silent-no-op bug: a unit without the line
        // defaults to iptables, which is only right when iptables
        // is the active backend.
        None if active == "nftables" => Check::warn(
            name,
            "no Environment line — the unit defaults to iptables",
            "sudo nat-gate --backend nftables service install",
        ),
        None => Check::pass(name, "defaults to iptables (no Environment line)"),
    })
}

fn check_persistence(
    v4_rules: &Result<usize, String>,
    v6_rules: &Result<usize, String>,
) -> Vec<Check> {
    let have_rules = matches!(v4_rules, Ok(n) if *n > 0) || matches!(v6_rules, Ok(n) if *n > 0);
    let mut out = Vec::new();

    if backend::active().as_str() == "nftables" {
        if Path::new(NFT_CONF).exists() {
            out.push(Check::pass(
                "Boot persistence",
                format!("{NFT_CONF} present"),
            ));
            match fs::read_to_string(SYSTEM_NFT_CONF) {
                Ok(sys) if sys.contains("nat-gate/nftables.conf") => {}
                Ok(_) => out.push(Check::warn(
                    "Boot restore",
                    format!("{SYSTEM_NFT_CONF} does not include nat-gate's rules"),
                    format!("add `include \"{NFT_CONF}\"` to {SYSTEM_NFT_CONF}"),
                )),
                Err(_) => out.push(Check::warn(
                    "Boot restore",
                    format!("{SYSTEM_NFT_CONF} not found — nothing restores the tables at boot"),
                    format!(
                        "create it containing `include \"{NFT_CONF}\"` and enable nftables.service"
                    ),
                )),
            }
        } else if have_rules {
            out.push(Check::warn(
                "Boot persistence",
                format!("{NFT_CONF} missing though rules are loaded"),
                "re-apply or re-add a rule so nat-gate re-saves the tables",
            ));
        }
    } else if have_rules {
        let persisted = Path::new("/etc/iptables/rules.v4").exists()
            || Path::new("/etc/iptables/rules.v6").exists()
            || crate::utils::probe_binary("netfilter-persistent");
        if persisted {
            out.push(Check::pass(
                "Boot persistence",
                "iptables save file present",
            ));
        } else {
            out.push(Check::warn(
                "Boot persistence",
                "no iptables save file and netfilter-persistent absent",
                "install iptables-persistent, then re-run a rule change",
            ));
        }
    }

    out
}

fn check_service_enabled() -> Option<Check> {
    if !Path::new(MAIN_UNIT).exists() || !Path::new("/run/systemd/system").exists() {
        return None;
    }
    let enabled = Command::new("systemctl")
        .args(["is-enabled", "nat-gate.service"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    Some(if enabled {
        Check::pass("Boot service", "nat-gate.service enabled")
    } else {
        Check::warn(
            "Boot service",
            "nat-gate.service installed but not enabled",
            "sudo systemctl enable nat-gate",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_env_matches_service_install_writer() {
        // Pins the reader to the exact format `service install` bakes
        // (see commands::service::with_env_line); drift between the
        // writer and this parser would silently disable the check.
        let baked = crate::commands::service::with_env_line(
            crate::commands::service::EMBEDDED_SERVICE,
            "Environment=NAT_GATE_BACKEND=nftables\n",
        );
        assert_eq!(
            unit_backend_env_from_str(&baked),
            Some(Some("nftables".to_string()))
        );
    }

    #[test]
    fn unit_env_absent_and_quoted_forms() {
        let plain = "[Unit]\nDescription=t\n\n[Service]\nExecStart=/bin/true\n";
        assert_eq!(unit_backend_env_from_str(plain), Some(None));

        let quoted = "[Service]\nEnvironment=\"NAT_GATE_BACKEND=iptables\"\n";
        assert_eq!(
            unit_backend_env_from_str(quoted),
            Some(Some("iptables".to_string()))
        );
    }
}
