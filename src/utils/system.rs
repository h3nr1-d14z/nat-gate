use std::fs;
use std::process::Command;

/// Check if a binary is installed and executable by probing `--version`.
/// More reliable than `which`: works when PATH is minimal (cron, systemd),
/// and verifies the binary actually runs, not just exists.
pub fn probe_binary(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if iptables is installed and accessible
pub fn check_iptables() -> Result<(), String> {
    if !probe_binary("iptables") {
        return Err(
            "iptables is not installed or not executable. Please install it first.".to_string(),
        );
    }

    Ok(())
}

/// Enable IPv4 forwarding via sysctl
pub fn enable_ip_forwarding() -> Result<(), String> {
    // Enable immediately
    let output = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output()
        .map_err(|e| format!("Failed to enable IP forwarding: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to enable IP forwarding: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Make persistent by writing to sysctl.d
    let sysctl_conf = "/etc/sysctl.d/99-nat-gate.conf";

    // Read existing content or start fresh
    let existing = fs::read_to_string(sysctl_conf).unwrap_or_default();

    if !existing.contains("net.ipv4.ip_forward=1") {
        let content = if existing.is_empty() {
            "# Enabled by nat-gate for port forwarding\nnet.ipv4.ip_forward=1\n".to_string()
        } else {
            format!("{}\nnet.ipv4.ip_forward=1\n", existing.trim_end())
        };

        fs::write(sysctl_conf, content)
            .map_err(|e| format!("Failed to write sysctl config: {e}"))?;
    }

    Ok(())
}

/// Enable IPv6 forwarding via sysctl
pub fn enable_ipv6_forwarding() -> Result<(), String> {
    // Enable immediately
    let output = Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.forwarding=1"])
        .output()
        .map_err(|e| format!("Failed to enable IPv6 forwarding: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to enable IPv6 forwarding: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Make persistent by writing to sysctl.d
    let sysctl_conf = "/etc/sysctl.d/99-nat-gate.conf";

    // Read existing content
    let existing = fs::read_to_string(sysctl_conf).unwrap_or_default();

    if !existing.contains("net.ipv6.conf.all.forwarding=1") {
        let content = if existing.is_empty() {
            "# Enabled by nat-gate for port forwarding\nnet.ipv6.conf.all.forwarding=1\n"
                .to_string()
        } else {
            format!("{}\nnet.ipv6.conf.all.forwarding=1\n", existing.trim_end())
        };

        fs::write(sysctl_conf, content)
            .map_err(|e| format!("Failed to write sysctl config: {e}"))?;
    }

    Ok(())
}

/// Save iptables rules (both IPv4 and IPv6) to persist across reboots.
/// netfilter-persistent saves both families itself; the manual fallback
/// must save rules.v4 and rules.v6 separately.
pub fn save_iptables_rules() -> Result<(), String> {
    // Try netfilter-persistent first (Debian/Ubuntu with iptables-persistent).
    // It saves all tables for both families.
    if let Ok(output) = Command::new("netfilter-persistent").arg("save").output() {
        if output.status.success() {
            return Ok(());
        }
    }

    // Fallback: save both families directly to the rules files
    if save_family("iptables-save", "/etc/iptables/rules.v4")
        && save_family("ip6tables-save", "/etc/iptables/rules.v6")
    {
        return Ok(());
    }

    // Retry after ensuring the directory exists (first boot)
    let _ = Command::new("sh")
        .args(["-c", "mkdir -p /etc/iptables"])
        .status();
    let v4_ok = save_family("iptables-save", "/etc/iptables/rules.v4");
    let v6_ok = save_family("ip6tables-save", "/etc/iptables/rules.v6");

    if v4_ok && v6_ok {
        Ok(())
    } else {
        let failed = match (v4_ok, v6_ok) {
            (false, true) => "IPv4",
            (true, false) => "IPv6",
            _ => "IPv4 and IPv6",
        };
        Err(format!(
            "Failed to save {failed} iptables rules. Rules may not persist after reboot."
        ))
    }
}

/// Save one family's rules to a file via shell redirection.
/// Returns success; failures are surfaced by the caller.
fn save_family(save_cmd: &str, dest: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("{save_cmd} > {dest}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if iptables-persistent is installed
pub fn check_iptables_persistent() -> bool {
    Command::new("which")
        .arg("netfilter-persistent")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Suggest installing iptables-persistent
pub fn suggest_install_persistent() -> &'static str {
    "Consider installing iptables-persistent for automatic rule loading:\n  sudo apt install iptables-persistent"
}
