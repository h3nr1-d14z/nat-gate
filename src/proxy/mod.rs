//! PROXY-protocol userspace TCP proxy: config model.
//!
//! Stored at `/etc/nat-gate/proxy.yaml`. The config has no fallback
//! location (unlike rules.yaml): only root writes it and the daemon
//! always runs under root.

pub mod daemon;
pub mod protocol;

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Default config location (root-writable, read by the daemon and CLI).
pub const PROXY_CONFIG_PATH: &str = "/etc/nat-gate/proxy.yaml";

/// One PROXY forwarding rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRule {
    /// Protocol — always "tcp" (validity enforced on add).
    pub proto: String,
    /// Listen port.
    pub port: u16,
    /// Target host (IP address string).
    pub target: String,
    /// Target port (defaults to the listen port if unspecified on add).
    pub target_port: u16,
    /// "v1", "v2", or "none".
    pub proxy_protocol: String,
}

/// Full proxy config (a list of rules).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub rules: Vec<ProxyRule>,
}

impl ProxyConfig {
    /// Load from the default path. Missing file = empty config (not an error),
    /// so `proxy list` works before anything has been added.
    pub fn load() -> Result<Self, String> {
        Self::load_from(Path::new(PROXY_CONFIG_PATH))
    }

    /// Load from an arbitrary path.
    pub fn load_from(path: &Path) -> Result<Self, String> {
        match fs::read_to_string(path) {
            Ok(content) => {
                if content.trim().is_empty() {
                    return Ok(Self::default());
                }
                serde_yaml::from_str(&content)
                    .map_err(|e| format!("Failed to parse proxy config {path:?}: {e}"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("Failed to read proxy config {path:?}: {e}")),
        }
    }

    /// Atomically save to the default path, creating the parent directory.
    pub fn save(&self) -> Result<(), String> {
        self.save_to(Path::new(PROXY_CONFIG_PATH))
    }

    /// Save to an arbitrary path.
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create proxy config dir: {e}"))?;
        }
        let yaml = serde_yaml::to_string(self)
            .map_err(|e| format!("Failed to serialize proxy config: {e}"))?;
        fs::write(path, yaml).map_err(|e| format!("Failed to write proxy config: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let cfg = ProxyConfig {
            rules: vec![
                ProxyRule {
                    proto: "tcp".into(),
                    port: 25565,
                    target: "100.64.0.5".into(),
                    target_port: 25565,
                    proxy_protocol: "v2".into(),
                },
                ProxyRule {
                    proto: "tcp".into(),
                    port: 25566,
                    target: "100.64.0.5".into(),
                    target_port: 25567,
                    proxy_protocol: "none".into(),
                },
            ],
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let back: ProxyConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg.rules, back.rules);
    }

    #[test]
    fn empty_rules_default() {
        let yaml = "rules: []\n";
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn missing_file_is_empty_config() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "nat-gate-proxy-nonexistent-{}.yaml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let cfg = ProxyConfig::load_from(&path).unwrap();
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn save_load_file_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "nat-gate-proxy-save-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proxy.yaml");

        let cfg = ProxyConfig {
            rules: vec![ProxyRule {
                proto: "tcp".into(),
                port: 25565,
                target: "100.64.0.5".into(),
                target_port: 25565,
                proxy_protocol: "v2".into(),
            }],
        };
        cfg.save_to(&path).unwrap();
        let back = ProxyConfig::load_from(&path).unwrap();
        assert_eq!(cfg.rules, back.rules);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
