use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for nat-gate rules from YAML config file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatGateConfig {
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

/// A single forwarding rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Protocol: tcp or udp
    pub protocol: String,

    /// Port or port range (e.g., "443" or "8000-8080")
    pub port: String,

    /// Target IP address (Tailscale IP)
    pub target: String,

    /// Optional network interface (e.g., "eth0")
    #[serde(default)]
    pub interface: Option<String>,

    /// Use IPv6 instead of IPv4
    #[serde(default)]
    pub ipv6: bool,
}

/// Backup file format for exporting/importing rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupData {
    /// Version of nat-gate that created this backup
    pub version: String,

    /// Timestamp when backup was created
    pub exported_at: DateTime<Utc>,

    /// List of rules in the backup
    pub rules: Vec<RuleConfig>,
}

impl BackupData {
    /// Create a new backup with the current version and timestamp
    pub fn new(rules: Vec<RuleConfig>) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            exported_at: Utc::now(),
            rules,
        }
    }
}

impl RuleConfig {
    /// Validate the rule configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate protocol
        match self.protocol.to_lowercase().as_str() {
            "tcp" | "udp" => {}
            _ => {
                return Err(format!(
                    "Invalid protocol '{}'. Must be 'tcp' or 'udp'",
                    self.protocol
                ))
            }
        }

        // Validate port/port range
        if self.port.contains('-') {
            let parts: Vec<&str> = self.port.split('-').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid port range format: {}", self.port));
            }
            let start: u16 = parts[0]
                .parse()
                .map_err(|_| format!("Invalid start port: {}", parts[0]))?;
            let end: u16 = parts[1]
                .parse()
                .map_err(|_| format!("Invalid end port: {}", parts[1]))?;
            if start == 0 || end == 0 {
                return Err("Port numbers must be between 1 and 65535".to_string());
            }
            if start > end {
                return Err("Start port must be less than or equal to end port".to_string());
            }
        } else {
            let port: u16 = self
                .port
                .parse()
                .map_err(|_| format!("Invalid port: {}", self.port))?;
            if port == 0 {
                return Err("Port number must be between 1 and 65535".to_string());
            }
        }

        // Validate IP address
        if self.target.contains(':') {
            // IPv6 validation
            let target = self.target.trim_matches(|c| c == '[' || c == ']');
            if target.split(':').count() < 3 {
                return Err(format!("Invalid IPv6 address: {}", self.target));
            }
        } else {
            // IPv4 validation
            let parts: Vec<&str> = self.target.split('.').collect();
            if parts.len() != 4 {
                return Err(format!("Invalid IPv4 address: {}", self.target));
            }
            for part in parts {
                part.parse::<u8>()
                    .map_err(|_| format!("Invalid IPv4 address: {}", self.target))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_config_validate_valid() {
        let rule = RuleConfig {
            protocol: "tcp".to_string(),
            port: "443".to_string(),
            target: "100.64.0.5".to_string(),
            interface: None,
            ipv6: false,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_rule_config_validate_port_range() {
        let rule = RuleConfig {
            protocol: "tcp".to_string(),
            port: "8000-8080".to_string(),
            target: "100.64.0.5".to_string(),
            interface: Some("eth0".to_string()),
            ipv6: false,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_rule_config_validate_invalid_protocol() {
        let rule = RuleConfig {
            protocol: "icmp".to_string(),
            port: "443".to_string(),
            target: "100.64.0.5".to_string(),
            interface: None,
            ipv6: false,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_rule_config_validate_invalid_ip() {
        let rule = RuleConfig {
            protocol: "tcp".to_string(),
            port: "443".to_string(),
            target: "invalid".to_string(),
            interface: None,
            ipv6: false,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_backup_data_new() {
        let rules = vec![RuleConfig {
            protocol: "tcp".to_string(),
            port: "443".to_string(),
            target: "100.64.0.5".to_string(),
            interface: None,
            ipv6: false,
        }];
        let backup = BackupData::new(rules);
        assert_eq!(backup.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(backup.rules.len(), 1);
    }
}
