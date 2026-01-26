use std::fs;
use std::process::Command;

/// Check if iptables is installed and accessible
pub fn check_iptables() -> Result<(), String> {
    let output = Command::new("which")
        .arg("iptables")
        .output()
        .map_err(|e| format!("Failed to check for iptables: {e}"))?;

    if !output.status.success() {
        return Err("iptables is not installed. Please install it first.".to_string());
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
            "# Enabled by nat-gate for port forwarding\nnet.ipv6.conf.all.forwarding=1\n".to_string()
        } else {
            format!("{}\nnet.ipv6.conf.all.forwarding=1\n", existing.trim_end())
        };

        fs::write(sysctl_conf, content)
            .map_err(|e| format!("Failed to write sysctl config: {e}"))?;
    }

    Ok(())
}

/// Save iptables rules to persist across reboots
pub fn save_iptables_rules() -> Result<(), String> {
    // Try netfilter-persistent first (Debian/Ubuntu with iptables-persistent)
    let netfilter_result = Command::new("netfilter-persistent")
        .arg("save")
        .output();

    if let Ok(output) = netfilter_result {
        if output.status.success() {
            return Ok(());
        }
    }

    // Fallback: save directly to rules file
    let output = Command::new("sh")
        .args(["-c", "iptables-save > /etc/iptables/rules.v4"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            return Ok(());
        }
    }

    // Try alternative location
    let output = Command::new("sh")
        .args(["-c", "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4"])
        .output()
        .map_err(|e| format!("Failed to save iptables rules: {e}"))?;

    if !output.status.success() {
        return Err("Failed to save iptables rules. Rules may not persist after reboot.".to_string());
    }

    Ok(())
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
