use std::process::Command;

/// Check if the current process is running as root
pub fn check_root() -> Result<(), String> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| format!("Failed to check user ID: {e}"))?;

    let uid: u32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|_| "Failed to parse user ID")?;

    if uid != 0 {
        return Err("This command must be run as root (use sudo)".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_root_returns_result() {
        // This test just verifies the function doesn't panic
        // Actual root check depends on environment
        let _ = check_root();
    }
}
