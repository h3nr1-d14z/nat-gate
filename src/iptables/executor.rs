use std::process::{Command, Output};

/// Abstraction for executing iptables commands
pub struct IptablesExecutor;

impl IptablesExecutor {
    /// Get the iptables command name based on IP version
    fn cmd(ipv6: bool) -> &'static str {
        if ipv6 {
            "ip6tables"
        } else {
            "iptables"
        }
    }

    /// Generate the comment marker for nat-gate rules
    pub fn comment_marker(proto: &str, port: &str) -> String {
        format!("nat-gate:{proto}:{port}")
    }

    /// Format port for iptables (handles ranges)
    fn format_port(port: &str) -> String {
        // iptables uses : for port ranges, but we accept - for user convenience
        port.replace('-', ":")
    }

    /// Format destination for iptables
    fn format_destination(target: &str, port: &str, ipv6: bool) -> String {
        let port_spec = Self::format_port(port);
        if ipv6 {
            // IPv6 requires brackets around address
            if target.contains(':') && !target.starts_with('[') {
                format!("[{target}]:{port_spec}")
            } else {
                format!("{target}:{port_spec}")
            }
        } else {
            format!("{target}:{port_spec}")
        }
    }

    /// Parse rate limit string (e.g., "100/min", "10/sec") into iptables format
    fn parse_rate_limit(limit: &str) -> Result<(String, String), String> {
        let parts: Vec<&str> = limit.split('/').collect();
        if parts.len() != 2 {
            return Err(
                "Rate limit must be in format: <number>/<unit> (e.g., 100/min, 10/sec)".to_string(),
            );
        }

        let rate: u32 = parts[0].parse().map_err(|_| "Invalid rate limit number")?;

        let unit = match parts[1].to_lowercase().as_str() {
            "s" | "sec" | "second" => "second",
            "m" | "min" | "minute" => "minute",
            "h" | "hour" => "hour",
            "d" | "day" => "day",
            _ => return Err("Invalid rate limit unit. Use: sec, min, hour, or day".to_string()),
        };

        // Calculate burst as 150% of rate (minimum 5)
        let burst = std::cmp::max(5, (rate as f64 * 1.5) as u32);

        Ok((format!("{rate}/{unit}"), burst.to_string()))
    }

    /// Build the iptables argv for a PREROUTING DNAT rule.
    /// Exposed so --dry-run can print the exact command.
    pub fn prerouting_args(
        proto: &str,
        port: &str,
        target: &str,
        interface: Option<&str>,
        ipv6: bool,
        limit: Option<&str>,
    ) -> Result<Vec<String>, String> {
        let comment = Self::comment_marker(proto, port);
        let port_spec = Self::format_port(port);
        let dest = Self::format_destination(target, port, ipv6);

        let mut args: Vec<String> = vec!["-t", "nat", "-A", "PREROUTING"]
            .into_iter()
            .map(String::from)
            .collect();

        if let Some(iface) = interface {
            args.extend(["-i".to_string(), iface.to_string()]);
        }

        args.extend(["-p".to_string(), proto.to_string()]);
        args.extend(["--dport".to_string(), port_spec]);

        if let Some(limit_str) = limit {
            let (rate, burst) = Self::parse_rate_limit(limit_str)?;
            args.extend(["-m".to_string(), "limit".to_string()]);
            args.extend(["--limit".to_string(), rate]);
            args.extend(["--limit-burst".to_string(), burst]);
        }

        args.extend(["-j".to_string(), "DNAT".to_string()]);
        args.extend(["--to-destination".to_string(), dest]);
        args.extend(["-m".to_string(), "comment".to_string()]);
        args.extend(["--comment".to_string(), comment]);
        Ok(args)
    }

    /// Add PREROUTING DNAT rule
    pub fn add_prerouting_rule(
        proto: &str,
        port: &str,
        target: &str,
        interface: Option<&str>,
        ipv6: bool,
        limit: Option<&str>,
    ) -> Result<(), String> {
        let args = Self::prerouting_args(proto, port, target, interface, ipv6, limit)?;

        let output = Command::new(Self::cmd(ipv6))
            .args(&args)
            .output()
            .map_err(|e| format!("Failed to execute {}: {}", Self::cmd(ipv6), e))?;

        Self::check_output(output, "add PREROUTING rule")
    }

    /// Build the iptables argv for a POSTROUTING MASQUERADE rule.
    /// Exposed so --dry-run can print the exact command.
    pub fn postrouting_args(proto: &str, port: &str, target: &str) -> Result<Vec<String>, String> {
        let comment = Self::comment_marker(proto, port);
        let port_spec = Self::format_port(port);

        Ok(vec![
            "-t".into(),
            "nat".into(),
            "-A".into(),
            "POSTROUTING".into(),
            "-p".into(),
            proto.into(),
            "-d".into(),
            target.into(),
            "--dport".into(),
            port_spec,
            "-j".into(),
            "MASQUERADE".into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            comment,
        ])
    }

    /// Add POSTROUTING MASQUERADE rule
    pub fn add_postrouting_rule(
        proto: &str,
        port: &str,
        target: &str,
        ipv6: bool,
    ) -> Result<(), String> {
        let args = Self::postrouting_args(proto, port, target)?;

        let output = Command::new(Self::cmd(ipv6))
            .args(&args)
            .output()
            .map_err(|e| format!("Failed to execute {}: {}", Self::cmd(ipv6), e))?;

        Self::check_output(output, "add POSTROUTING rule")
    }

    /// Delete a rule by its exact iptables-save spec (line-number-free).
    /// `spec` is the token list after `-A <chain>` in iptables-save output,
    /// passed verbatim so the kernel matches the rule exactly.
    pub fn delete_rule_spec(chain: &str, spec: &[String], ipv6: bool) -> Result<(), String> {
        let mut args: Vec<&str> = vec!["-t", "nat", "-D", chain];
        args.extend(spec.iter().map(|s| s.as_str()));

        let output = Command::new(Self::cmd(ipv6))
            .args(&args)
            .output()
            .map_err(|e| format!("Failed to execute {}: {}", Self::cmd(ipv6), e))?;

        Self::check_output(output, &format!("delete rule from {chain}"))
    }

    /// Dump the nat table via `iptables-save -c -t nat` (with counters).
    /// This is the single machine-readable source nat-gate reads state from.
    pub fn save_nat_table(ipv6: bool) -> Result<String, String> {
        let cmd = if ipv6 {
            "ip6tables-save"
        } else {
            "iptables-save"
        };
        let output = Command::new(cmd)
            .args(["-c", "-t", "nat"])
            .output()
            .map_err(|e| format!("Failed to execute {cmd}: {e}"))?;

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
