mod commands;
mod config;
mod iptables;
mod output;
mod utils;

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use colored::Colorize;

#[derive(Parser)]
#[command(name = "nat-gate")]
#[command(author = "h3nr1-d14z")]
#[command(version)]
#[command(about = "Manage iptables port forwarding through Tailscale tunnels", long_about = None)]
pub struct Cli {
    /// Preview changes without executing iptables commands
    #[arg(long, global = true)]
    dry_run: bool,

    /// Output results in JSON format for scripting
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize system for port forwarding (enables IP forwarding, checks dependencies)
    Init {
        /// Enable IPv6 forwarding as well
        #[arg(short = '6', long)]
        ipv6: bool,
    },

    /// Add a port forwarding rule
    Add {
        /// Protocol (tcp or udp)
        #[arg(value_parser = validate_protocol)]
        proto: String,

        /// Port or port range to forward (e.g., 443 or 8000-8080)
        #[arg(value_parser = validate_port_range)]
        port: String,

        /// Target IP address (IPv4 or IPv6 Tailscale IP to forward to)
        #[arg(value_parser = validate_ip)]
        target: String,

        /// Input interface to match (e.g., eth0, ens3)
        #[arg(short, long)]
        interface: Option<String>,

        /// Use IPv6 (ip6tables) instead of IPv4
        #[arg(short = '6', long)]
        ipv6: bool,

        /// Rate limit for incoming connections (e.g., 100/min, 10/sec)
        #[arg(long, value_parser = validate_rate_limit)]
        limit: Option<String>,
    },

    /// Delete a port forwarding rule
    Del {
        /// Protocol (tcp or udp)
        #[arg(value_parser = validate_protocol)]
        proto: String,

        /// Port or port range to stop forwarding
        #[arg(value_parser = validate_port_range)]
        port: String,

        /// Use IPv6 (ip6tables) instead of IPv4
        #[arg(short = '6', long)]
        ipv6: bool,
    },

    /// List all managed port forwarding rules
    List {
        /// Show IPv6 rules instead of IPv4
        #[arg(short = '6', long)]
        ipv6: bool,
    },

    /// Show system status (IP forwarding, iptables, active rules)
    Status,

    /// Export nat-gate rules to a JSON backup file
    Backup {
        /// Output file path (default: ./nat-gate-backup.json, use - for stdout)
        file: Option<String>,

        /// Export IPv6 rules instead of IPv4
        #[arg(short = '6', long)]
        ipv6: bool,
    },

    /// Restore nat-gate rules from a JSON backup file
    Restore {
        /// Backup file to restore from
        file: String,
    },

    /// Apply rules from a YAML config file
    Apply {
        /// Path to config file (default: ~/.config/nat-gate/rules.yaml or /etc/nat-gate/rules.yaml)
        #[arg(short, long)]
        config: Option<String>,
    },

    /// List available Tailscale peers and their IPs
    Tailscale,

    /// Remove all nat-gate managed rules at once
    Flush {
        /// Flush IPv6 rules instead of IPv4
        #[arg(short = '6', long)]
        ipv6: bool,
    },

    /// Check if forwarding is working correctly
    Check {
        /// Test a specific port connectivity
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Show traffic statistics per rule
    Stats {
        /// Show IPv6 rule statistics instead of IPv4
        #[arg(short = '6', long)]
        ipv6: bool,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Manage the systemd service
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install and enable the systemd service
    Install,
    /// Uninstall and disable the systemd service
    Uninstall,
    /// Show service status
    Status,
}

fn validate_protocol(s: &str) -> Result<String, String> {
    match s.to_lowercase().as_str() {
        "tcp" | "udp" => Ok(s.to_lowercase()),
        _ => Err("Protocol must be 'tcp' or 'udp'".to_string()),
    }
}

fn validate_port_range(s: &str) -> Result<String, String> {
    if s.contains('-') {
        // Port range: 8000-8080
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err("Invalid port range format. Use: start-end (e.g., 8000-8080)".to_string());
        }
        let start: u16 = parts[0].parse().map_err(|_| "Invalid start port")?;
        let end: u16 = parts[1].parse().map_err(|_| "Invalid end port")?;
        if start == 0 || end == 0 {
            return Err("Port numbers must be between 1 and 65535".to_string());
        }
        if start > end {
            return Err("Start port must be less than or equal to end port".to_string());
        }
        if end - start > 1000 {
            return Err("Port range too large (max 1000 ports)".to_string());
        }
        Ok(s.to_string())
    } else {
        // Single port
        let port: u16 = s.parse().map_err(|_| "Invalid port number")?;
        if port == 0 {
            return Err("Port number must be between 1 and 65535".to_string());
        }
        Ok(s.to_string())
    }
}

fn validate_rate_limit(s: &str) -> Result<String, String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(
            "Rate limit must be in format: <number>/<unit> (e.g., 100/min, 10/sec)".to_string(),
        );
    }

    let rate: u32 = parts[0].parse().map_err(|_| "Invalid rate limit number")?;

    if rate == 0 {
        return Err("Rate limit must be greater than 0".to_string());
    }

    let unit = parts[1].to_lowercase();
    match unit.as_str() {
        "s" | "sec" | "second" | "m" | "min" | "minute" | "h" | "hour" | "d" | "day" => {}
        _ => return Err("Invalid rate limit unit. Use: sec, min, hour, or day".to_string()),
    }

    Ok(s.to_string())
}

fn validate_ip(s: &str) -> Result<String, String> {
    // Check for IPv6
    if s.contains(':') {
        // Basic IPv6 validation
        let s = s.trim_matches(|c| c == '[' || c == ']');
        if s.split(':').count() < 3 {
            return Err("Invalid IPv6 address format".to_string());
        }
        // Check each segment is valid hex
        for part in s.split(':') {
            if part.is_empty() {
                continue; // Allow :: compression
            }
            if part.len() > 4 {
                return Err("Invalid IPv6 address format".to_string());
            }
            if !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("Invalid IPv6 address format".to_string());
            }
        }
        return Ok(s.to_string());
    }

    // IPv4 validation
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err("Invalid IP address format".to_string());
    }

    for part in parts {
        match part.parse::<u8>() {
            Ok(_) => continue,
            Err(_) => return Err("Invalid IP address format".to_string()),
        }
    }

    Ok(s.to_string())
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { ipv6 } => {
            if cli.dry_run {
                if cli.json {
                    output::print_dry_run_action("init", serde_json::json!({ "ipv6": ipv6 }));
                } else {
                    println!(
                        "{} Would initialize system (IPv6: {})",
                        "[DRY-RUN]".yellow(),
                        ipv6
                    );
                }
                Ok(())
            } else {
                commands::init::run(ipv6)
            }
        }
        Commands::Add {
            proto,
            port,
            target,
            interface,
            ipv6,
            limit,
        } => {
            if cli.dry_run {
                if cli.json {
                    output::print_dry_run_action(
                        "add",
                        serde_json::json!({
                            "protocol": proto,
                            "port": port,
                            "target": target,
                            "interface": interface,
                            "ipv6": ipv6,
                            "limit": limit
                        }),
                    );
                } else {
                    let iface_info = interface
                        .as_ref()
                        .map(|i| format!(" on {i}"))
                        .unwrap_or_default();
                    let limit_info = limit
                        .as_ref()
                        .map(|l| format!(" (limit: {l})"))
                        .unwrap_or_default();
                    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };
                    println!(
                        "{} Would add: {} {} {} -> {}{}{}",
                        "[DRY-RUN]".yellow(),
                        ip_version,
                        proto.to_uppercase(),
                        port,
                        target,
                        iface_info,
                        limit_info
                    );
                }
                Ok(())
            } else {
                commands::add::run(
                    &proto,
                    &port,
                    &target,
                    interface.as_deref(),
                    ipv6,
                    limit.as_deref(),
                )
            }
        }
        Commands::Del { proto, port, ipv6 } => {
            if cli.dry_run {
                if cli.json {
                    output::print_dry_run_action(
                        "del",
                        serde_json::json!({
                            "protocol": proto,
                            "port": port,
                            "ipv6": ipv6
                        }),
                    );
                } else {
                    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };
                    println!(
                        "{} Would delete: {} {} {}",
                        "[DRY-RUN]".yellow(),
                        ip_version,
                        proto.to_uppercase(),
                        port
                    );
                }
                Ok(())
            } else {
                commands::del::run(&proto, &port, ipv6)
            }
        }
        Commands::List { ipv6 } => commands::list::run(ipv6, cli.json),
        Commands::Status => {
            if cli.json {
                commands::status::run_json()
            } else {
                commands::status::run()
            }
        }
        Commands::Backup { file, ipv6 } => commands::backup::run(file.as_deref(), ipv6, cli.json),
        Commands::Restore { file } => commands::restore::run(&file, cli.dry_run, cli.json),
        Commands::Apply { config } => {
            commands::apply::run(config.as_deref(), cli.dry_run, cli.json)
        }
        Commands::Tailscale => commands::tailscale::run(cli.json),
        Commands::Flush { ipv6 } => commands::flush::run(ipv6, cli.dry_run, cli.json),
        Commands::Check { port } => commands::check::run(port, cli.json),
        Commands::Stats { ipv6 } => commands::stats::run(ipv6, cli.json),
        Commands::Completions { shell } => commands::completions::run(shell),
        Commands::Service { action } => match action {
            ServiceAction::Install => commands::service::install(cli.json),
            ServiceAction::Uninstall => commands::service::uninstall(cli.json),
            ServiceAction::Status => commands::service::status(cli.json),
        },
    };

    if let Err(e) = result {
        if cli.json {
            output::print_error(&e);
        } else {
            eprintln!("{} {}", "Error:".red().bold(), e);
        }
        std::process::exit(1);
    }
}
