use colored::Colorize;
use std::fs;
use std::process::Command;

use crate::output;
use crate::utils::check_root;

const SERVICE_NAME: &str = "nat-gate";
const SERVICE_FILE: &str = "/etc/systemd/system/nat-gate.service";
const EMBEDDED_SERVICE: &str = include_str!("../../dist/nat-gate.service");

/// Install the systemd service
pub fn install(json_output: bool) -> Result<(), String> {
    check_root()?;

    // Check if systemd is available
    if !is_systemd_available() {
        return Err("systemd is not available on this system".to_string());
    }

    if !json_output {
        println!("{}", "Installing nat-gate systemd service...".blue().bold());
    }

    // Write service file
    if !json_output {
        print!("  Writing service file... ");
    }
    fs::write(SERVICE_FILE, EMBEDDED_SERVICE)
        .map_err(|e| format!("Failed to write service file: {e}"))?;
    if !json_output {
        println!("{}", "OK".green());
    }

    // Reload systemd daemon
    if !json_output {
        print!("  Reloading systemd daemon... ");
    }
    run_systemctl(&["daemon-reload"])?;
    if !json_output {
        println!("{}", "OK".green());
    }

    // Enable the service
    if !json_output {
        print!("  Enabling service... ");
    }
    run_systemctl(&["enable", SERVICE_NAME])?;
    if !json_output {
        println!("{}", "OK".green());
    }

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "message": "Service installed and enabled",
            "data": {
                "service_file": SERVICE_FILE,
                "enabled": true
            }
        }));
    } else {
        println!("\n{}", "Service installed successfully!".green().bold());
        println!();
        println!("To start the service now:");
        println!("  {}", "sudo systemctl start nat-gate".cyan());
        println!();
        println!("To check service status:");
        println!("  {}", "sudo systemctl status nat-gate".cyan());
        println!();
        println!("The service will automatically start on boot and apply");
        println!("rules from your config file (~/.config/nat-gate/rules.yaml)");
    }

    Ok(())
}

/// Uninstall the systemd service
pub fn uninstall(json_output: bool) -> Result<(), String> {
    check_root()?;

    if !is_systemd_available() {
        return Err("systemd is not available on this system".to_string());
    }

    if !json_output {
        println!(
            "{}",
            "Uninstalling nat-gate systemd service...".blue().bold()
        );
    }

    // Stop service if running
    if !json_output {
        print!("  Stopping service... ");
    }
    let _ = run_systemctl(&["stop", SERVICE_NAME]); // Ignore error if not running
    if !json_output {
        println!("{}", "OK".green());
    }

    // Disable the service
    if !json_output {
        print!("  Disabling service... ");
    }
    let _ = run_systemctl(&["disable", SERVICE_NAME]); // Ignore error if not enabled
    if !json_output {
        println!("{}", "OK".green());
    }

    // Remove service file
    if !json_output {
        print!("  Removing service file... ");
    }
    if std::path::Path::new(SERVICE_FILE).exists() {
        fs::remove_file(SERVICE_FILE).map_err(|e| format!("Failed to remove service file: {e}"))?;
    }
    if !json_output {
        println!("{}", "OK".green());
    }

    // Reload systemd daemon
    if !json_output {
        print!("  Reloading systemd daemon... ");
    }
    run_systemctl(&["daemon-reload"])?;
    if !json_output {
        println!("{}", "OK".green());
    }

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "message": "Service uninstalled"
        }));
    } else {
        println!("\n{}", "Service uninstalled successfully!".green().bold());
    }

    Ok(())
}

/// Show service status
pub fn status(json_output: bool) -> Result<(), String> {
    if !is_systemd_available() {
        return Err("systemd is not available on this system".to_string());
    }

    let installed = std::path::Path::new(SERVICE_FILE).exists();
    let enabled = is_service_enabled();
    let active = is_service_active();

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "installed": installed,
                "enabled": enabled,
                "active": active,
                "service_file": SERVICE_FILE
            }
        }));
    } else {
        println!("{}", "nat-gate systemd service status:".blue().bold());
        println!();
        println!(
            "  Installed: {}",
            if installed {
                "Yes".green()
            } else {
                "No".yellow()
            }
        );
        println!(
            "  Enabled:   {}",
            if enabled {
                "Yes".green()
            } else {
                "No".yellow()
            }
        );
        println!(
            "  Active:    {}",
            if active {
                "Running".green()
            } else {
                "Stopped".yellow()
            }
        );

        if !installed {
            println!();
            println!(
                "To install the service, run: {}",
                "sudo nat-gate service install".cyan()
            );
        }
    }

    Ok(())
}

/// Check if systemd is available
fn is_systemd_available() -> bool {
    Command::new("systemctl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a systemctl command
fn run_systemctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run systemctl: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Check if service is enabled
fn is_service_enabled() -> bool {
    Command::new("systemctl")
        .args(["is-enabled", SERVICE_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if service is active
fn is_service_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", SERVICE_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
