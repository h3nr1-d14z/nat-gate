use std::process::{Command, Output};

/// Abstraction for executing iptables commands
pub struct IptablesExecutor;

impl IptablesExecutor {
    /// Generate the comment marker for nat-gate rules
    pub fn comment_marker(proto: &str, port: u16) -> String {
        format!("nat-gate:{}:{}", proto, port)
    }

    /// Add PREROUTING DNAT rule
    pub fn add_prerouting_rule(proto: &str, port: u16, target: &str) -> Result<(), String> {
        let comment = Self::comment_marker(proto, port);

        let output = Command::new("iptables")
            .args([
                "-t", "nat",
                "-A", "PREROUTING",
                "-p", proto,
                "--dport", &port.to_string(),
                "-j", "DNAT",
                "--to-destination", &format!("{}:{}", target, port),
                "-m", "comment",
                "--comment", &comment,
            ])
            .output()
            .map_err(|e| format!("Failed to execute iptables: {}", e))?;

        Self::check_output(output, "add PREROUTING rule")
    }

    /// Add POSTROUTING MASQUERADE rule
    pub fn add_postrouting_rule(proto: &str, port: u16, target: &str) -> Result<(), String> {
        let comment = Self::comment_marker(proto, port);

        let output = Command::new("iptables")
            .args([
                "-t", "nat",
                "-A", "POSTROUTING",
                "-p", proto,
                "-d", target,
                "--dport", &port.to_string(),
                "-j", "MASQUERADE",
                "-m", "comment",
                "--comment", &comment,
            ])
            .output()
            .map_err(|e| format!("Failed to execute iptables: {}", e))?;

        Self::check_output(output, "add POSTROUTING rule")
    }

    /// Delete a rule by chain, line number
    pub fn delete_rule_by_line(chain: &str, line_number: u32) -> Result<(), String> {
        let output = Command::new("iptables")
            .args([
                "-t", "nat",
                "-D", chain,
                &line_number.to_string(),
            ])
            .output()
            .map_err(|e| format!("Failed to execute iptables: {}", e))?;

        Self::check_output(output, &format!("delete rule from {}", chain))
    }

    /// List NAT rules with line numbers
    pub fn list_nat_rules() -> Result<String, String> {
        let output = Command::new("iptables")
            .args(["-t", "nat", "-L", "-n", "-v", "--line-numbers"])
            .output()
            .map_err(|e| format!("Failed to execute iptables: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Failed to list NAT rules: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Get raw iptables-save output for parsing
    #[allow(dead_code)]
    pub fn get_raw_rules() -> Result<String, String> {
        let output = Command::new("iptables-save")
            .args(["-t", "nat"])
            .output()
            .map_err(|e| format!("Failed to execute iptables-save: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Failed to get iptables rules: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn check_output(output: Output, action: &str) -> Result<(), String> {
        if !output.status.success() {
            return Err(format!(
                "Failed to {}: {}",
                action,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
}
