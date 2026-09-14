use colored::Colorize;
use std::fs;
use std::process::Command;

use crate::output;
use crate::utils::check_root;

const SERVICE_NAME: &str = "nat-gate";
const SERVICE_FILE: &str = "/etc/systemd/system/nat-gate.service";
pub(crate) const EMBEDDED_SERVICE: &str = include_str!("../../dist/nat-gate.service");

const LOGGER_NAME: &str = "nat-gate-logger";
const LOGGER_FILE: &str = "/etc/systemd/system/nat-gate-logger.service";
const EMBEDDED_LOGGER: &str = include_str!("../../dist/nat-gate-logger.service");
const PROXY_NAME: &str = "nat-gate-proxy";
const PROXY_FILE: &str = "/etc/systemd/system/nat-gate-proxy.service";
const EMBEDDED_PROXY: &str = include_str!("../../dist/nat-gate-proxy.service");

/// Install the systemd service
pub fn install(with_logging: bool, with_proxy: bool, json_output: bool) -> Result<(), String> {
    check_root()?;

    // Check if systemd is available
    if !is_systemd_available() {
        return Err("systemd is not available on this system".to_string());
    }

    if !json_output {
        println!("{}", "Installing nat-gate systemd service...".blue().bold());
    }

    // Write service file. The units run in a bare systemd environment, so
    // the active backend (resolved from --backend / NAT_GATE_BACKEND) is
    // baked in as an Environment= line — otherwise apply/flush and the
    // logger would default to iptables on an nftables system and the
    // logger would silently classify nothing.
    let backend_env = format!(
        "Environment=NAT_GATE_BACKEND={}\n",
        crate::backend::active().as_str()
    );
    if !json_output {
        print!("  Writing service file... ");
    }
    fs::write(SERVICE_FILE, with_env_line(EMBEDDED_SERVICE, &backend_env))
        .map_err(|e| format!("Failed to write service file: {e}"))?;
    if !json_output {
        println!("{}", "OK".green());
    }

    if with_logging {
        if !json_output {
            print!("  Writing logger service file... ");
        }
        fs::write(LOGGER_FILE, with_env_line(EMBEDDED_LOGGER, &backend_env))
            .map_err(|e| format!("Failed to write logger service file: {e}"))?;
        // Ensure the log directory exists (the daemon also creates it)
        let _ = fs::create_dir_all(crate::logging::LOG_DIR);
        if !json_output {
            println!("{}", "OK".green());
        }
    }

    if with_proxy {
        if !json_output {
            print!("  Writing PROXY service file... ");
        }
        fs::write(PROXY_FILE, EMBEDDED_PROXY)
            .map_err(|e| format!("Failed to write PROXY service file: {e}"))?;
        // Ensure the log directory exists (the proxy daemon also writes here)
        let _ = fs::create_dir_all(crate::logging::LOG_DIR);
        if !json_output {
            println!("{}", "OK".green());
        }
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

    if with_logging {
        if !json_output {
            print!("  Enabling logger service... ");
        }
        run_systemctl(&["enable", LOGGER_NAME])?;
        if !json_output {
            println!("{}", "OK".green());
        }
    }

    if with_proxy {
        if !json_output {
            print!("  Enabling PROXY service... ");
        }
        run_systemctl(&["enable", PROXY_NAME])?;
        if !json_output {
            println!("{}", "OK".green());
        }
    }

    if json_output {
        let mut msg = "Service installed".to_string();
        if with_logging {
            msg = format!("{msg} (with connection logging)");
        }
        if with_proxy {
            msg = format!("{msg} (with PROXY daemon)");
        }
        output::print_value(serde_json::json!({
            "success": true,
            "message": msg,
            "data": {
                "service_file": SERVICE_FILE,
                "enabled": true,
                "logging": with_logging,
                "proxy": with_proxy
            }
        }));
    } else {
        println!("\n{}", "Service installed successfully!".green().bold());
        if with_logging {
            println!(
                "{}",
                "Connection logging enabled: player IPs are recorded in /var/lib/nat-gate/connections.jsonl"
                    .dimmed()
            );
        }
        if with_proxy {
            println!(
                "{}",
                "PROXY daemon enabled: listens on your proxy.yaml ports and injects PROXY headers"
                    .dimmed()
            );
        }
        println!();
        println!("To start the service now:");
        println!("  {}", "sudo systemctl start nat-gate".cyan());
        if with_logging {
            println!("  {}", "sudo systemctl start nat-gate-logger".cyan());
        }
        if with_proxy {
            println!("  {}", "sudo systemctl start nat-gate-proxy".cyan());
        }
        println!();
        println!("The service will automatically start on boot and apply");
        println!("rules from your config file (~/.config/nat-gate/rules.yaml)");
    }

    Ok(())
}

/// Uninstall the systemd service (and the logger if present)
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

    // Stop services if running
    if !json_output {
        print!("  Stopping service... ");
    }
    let _ = run_systemctl(&["stop", SERVICE_NAME]); // Ignore error if not running
    let _ = run_systemctl(&["stop", PROXY_NAME]);
    if !json_output {
        println!("{}", "OK".green());
    }

    // Disable the services
    if !json_output {
        print!("  Disabling service... ");
    }
    let _ = run_systemctl(&["disable", SERVICE_NAME]); // Ignore error if not enabled
    let _ = run_systemctl(&["disable", PROXY_NAME]);
    if !json_output {
        println!("{}", "OK".green());
    }

    // Remove service files
    if !json_output {
        print!("  Removing service file... ");
    }
    if std::path::Path::new(SERVICE_FILE).exists() {
        fs::remove_file(SERVICE_FILE).map_err(|e| format!("Failed to remove service file: {e}"))?;
    }
    if std::path::Path::new(LOGGER_FILE).exists() {
        let _ = fs::remove_file(LOGGER_FILE);
    }
    if std::path::Path::new(PROXY_FILE).exists() {
        let _ = fs::remove_file(PROXY_FILE);
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
        println!(
            "{}",
            "Connection logs (if any) remain at /var/lib/nat-gate/".dimmed()
        );
    }

    Ok(())
}

/// Show service status
pub fn status(json_output: bool) -> Result<(), String> {
    if !is_systemd_available() {
        return Err("systemd is not available on this system".to_string());
    }

    let installed = std::path::Path::new(SERVICE_FILE).exists();
    let enabled = is_unit_enabled(SERVICE_NAME);
    let active = is_unit_active(SERVICE_NAME);

    let logger_installed = std::path::Path::new(LOGGER_FILE).exists();
    let logger_enabled = is_unit_enabled(LOGGER_NAME);
    let logger_active = is_unit_active(LOGGER_NAME);

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "installed": installed,
                "enabled": enabled,
                "active": active,
                "service_file": SERVICE_FILE,
                "logging": {
                    "installed": logger_installed,
                    "enabled": logger_enabled,
                    "active": logger_active,
                    "service_file": LOGGER_FILE
                }
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

        println!();
        println!("{}", "Connection logging (nat-gate-logger):".bold());
        println!(
            "  Installed: {}",
            if logger_installed {
                "Yes".green()
            } else {
                "No".yellow()
            }
        );
        if logger_installed {
            println!(
                "  Enabled:   {}",
                if logger_enabled {
                    "Yes".green()
                } else {
                    "No".yellow()
                }
            );
            println!(
                "  Active:    {}",
                if logger_active {
                    "Running".green()
                } else {
                    "Stopped".yellow()
                }
            );
        } else {
            println!();
            println!(
                "To install with logging, run: {}",
                "sudo nat-gate service install --with-logging".cyan()
            );
        }

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

/// Check if a unit is enabled
fn is_unit_enabled(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-enabled", unit])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if a unit is active
fn is_unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Insert an `Environment=` line into a unit's [Service] section.
/// The embedded templates never contain one, so a plain insert after
/// the section header is sufficient and keeps the units explicit
/// about which backend they were installed for.
pub(crate) fn with_env_line(unit: &str, env_line: &str) -> String {
    unit.replacen("[Service]\n", &format!("[Service]\n{env_line}"), 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_line_inserted_after_service_header() {
        let unit = "[Unit]\nDescription=t\n\n[Service]\nType=oneshot\nExecStart=/bin/true\n";
        let out = with_env_line(unit, "Environment=NAT_GATE_BACKEND=nftables\n");
        assert_eq!(
            out,
            "[Unit]\nDescription=t\n\n[Service]\nEnvironment=NAT_GATE_BACKEND=nftables\nType=oneshot\nExecStart=/bin/true\n"
        );
    }

    #[test]
    fn embedded_units_have_service_section() {
        // Guards the replacen anchor: if a template ever drops the
        // [Service] header, the env line would silently not be written.
        for unit in [EMBEDDED_SERVICE, EMBEDDED_LOGGER, EMBEDDED_PROXY] {
            assert!(unit.contains("[Service]"), "unit missing [Service]: {unit}");
        }
    }
}
