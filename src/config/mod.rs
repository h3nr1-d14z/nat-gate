pub mod types;

pub use types::{BackupData, NatGateConfig, RuleConfig};

use std::fs;
use std::path::PathBuf;

/// Default config file paths in order of precedence
const CONFIG_PATHS: &[&str] = &[
    "~/.config/nat-gate/rules.yaml",
    "/etc/nat-gate/rules.yaml",
];

/// Find and load the config file
pub fn find_config_file() -> Option<PathBuf> {
    for path in CONFIG_PATHS {
        let expanded = expand_path(path);
        if expanded.exists() {
            return Some(expanded);
        }
    }
    None
}

/// Load config from a file path
pub fn load_config(path: &PathBuf) -> Result<NatGateConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file {path:?}: {e}"))?;

    serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse config file {path:?}: {e}"))
}

/// Load config from default locations or specified path
pub fn load_config_from_path_or_default(config_path: Option<&str>) -> Result<(PathBuf, NatGateConfig), String> {
    let path = match config_path {
        Some(p) => PathBuf::from(p),
        None => find_config_file().ok_or_else(|| {
            format!(
                "No config file found. Create one at {} or {}",
                CONFIG_PATHS[0], CONFIG_PATHS[1]
            )
        })?,
    };

    if !path.exists() {
        return Err(format!("Config file not found: {path:?}"));
    }

    let config = load_config(&path)?;
    Ok((path, config))
}

/// Expand ~ to home directory
fn expand_path(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_path_home() {
        let path = "~/.config/nat-gate/rules.yaml";
        let expanded = expand_path(path);
        assert!(!expanded.to_string_lossy().starts_with('~'));
    }

    #[test]
    fn test_expand_path_absolute() {
        let path = "/etc/nat-gate/rules.yaml";
        let expanded = expand_path(path);
        assert_eq!(expanded.to_string_lossy(), path);
    }
}
