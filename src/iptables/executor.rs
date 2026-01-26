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

        Ok((format!("{}/{}", rate, unit), burst.to_string()))
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
        let comment = Self::comment_marker(proto, port);
        let port_spec = Self::format_port(port);
        let dest = Self::format_destination(target, port, ipv6);

        let mut args = vec!["-t", "nat", "-A", "PREROUTING"];

        // Add interface if specified
        if let Some(iface) = interface {
            args.extend(["-i", iface]);
        }

        args.extend(["-p", proto, "--dport", &port_spec]);

        // Parse and apply rate limiting if specified
        let (limit_rate, limit_burst);
        if let Some(limit_str) = limit {
            let (rate, burst) = Self::parse_rate_limit(limit_str)?;
            limit_rate = rate;
            limit_burst = burst;
            args.extend([
                "-m",
                "limit",
                "--limit",
                &limit_rate,
                "--limit-burst",
                &limit_burst,
            ]);
        }

        args.extend([
            "-j",
            "DNAT",
            "--to-destination",
            &dest,
            "-m",
            "comment",
            "--comment",
            &comment,
        ]);

        let output = Command::new(Self::cmd(ipv6))
            .args(&args)
            .output()
            .map_err(|e| format!("Failed to execute {}: {}", Self::cmd(ipv6), e))?;

        Self::check_output(output, "add PREROUTING rule")
    }

    /// Add POSTROUTING MASQUERADE rule
    pub fn add_postrouting_rule(
        proto: &str,
        port: &str,
        target: &str,
        ipv6: bool,
    ) -> Result<(), String> {
        let comment = Self::comment_marker(proto, port);
        let port_spec = Self::format_port(port);

        let output = Command::new(Self::cmd(ipv6))
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-p",
                proto,
                "-d",
                target,
                "--dport",
                &port_spec,
                "-j",
                "MASQUERADE",
                "-m",
                "comment",
                "--comment",
                &comment,
            ])
            .output()
            .map_err(|e| format!("Failed to execute {}: {}", Self::cmd(ipv6), e))?;

        Self::check_output(output, "add POSTROUTING rule")
    }

    /// Delete a rule by chain, line number
    pub fn delete_rule_by_line(chain: &str, line_number: u32, ipv6: bool) -> Result<(), String> {
        let output = Command::new(Self::cmd(ipv6))
            .args(["-t", "nat", "-D", chain, &line_number.to_string()])
            .output()
            .map_err(|e| format!("Failed to execute {}: {}", Self::cmd(ipv6), e))?;

        Self::check_output(output, &format!("delete rule from {chain}"))
    }

    /// List NAT rules with line numbers
    pub fn list_nat_rules(ipv6: bool) -> Result<String, String> {
        let output = Command::new(Self::cmd(ipv6))
            .args(["-t", "nat", "-L", "-n", "-v", "--line-numbers"])
            .output()
            .map_err(|e| format!("Failed to execute {}: {}", Self::cmd(ipv6), e))?;

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
    pub fn get_raw_rules(ipv6: bool) -> Result<String, String> {
        let cmd = if ipv6 {
            "ip6tables-save"
        } else {
            "iptables-save"
        };
        let output = Command::new(cmd)
            .args(["-t", "nat"])
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

    /// Count nat-gate rules
    pub fn count_rules(ipv6: bool) -> Result<usize, String> {
        let output = Self::list_nat_rules(ipv6)?;
        Ok(output.matches("nat-gate:").count() / 2) // Divide by 2 because each rule has PREROUTING and POSTROUTING
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
