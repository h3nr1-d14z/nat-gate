mod backend;
mod commands;
mod config;
mod iptables;
mod logging;
mod nftables;
mod output;
mod proxy;
mod tui;
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

    /// Netfilter backend: iptables (default) or nftables
    #[arg(long, global = true)]
    backend: Option<String>,

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

        /// Compare config against live rules and report drift (no changes)
        #[arg(long)]
        check: bool,
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

    /// Diagnose common forwarding problems (sysctl, Tailscale, units, persistence)
    Doctor,
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

    /// Show currently active forwarded sessions (client IPs)
    Sessions,

    /// Manage PROXY-protocol forwarding rules
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },

    /// Manage connection logging (client IP visibility)
    Log {
        #[command(subcommand)]
        action: LogAction,
    },

    /// Launch interactive TUI mode
    Tui,

    /// Serve Prometheus metrics (or render once with --once)
    Metrics {
        /// HTTP listen port (default 9110)
        #[arg(long)]
        port: Option<u16>,

        /// Render the exposition to stdout once and exit
        #[arg(long)]
        once: bool,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install and enable the systemd service
    Install {
        /// Also install the connection-logging daemon service
        #[arg(long)]
        with_logging: bool,

        /// Also install the PROXY-protocol daemon service
        #[arg(long)]
        with_proxy: bool,

        /// Also install the Prometheus metrics exporter service
        #[arg(long)]
        with_metrics: bool,
    },
    /// Uninstall and disable the systemd service
    Uninstall,
    /// Show service status
    Status,
}

#[derive(Subcommand)]
enum LogAction {
    /// Show logged connection events
    Show {
        /// Only events newer than this (e.g. 30m, 24h, 7d)
        #[arg(long)]
        since: Option<String>,
        /// Filter by client IP
        #[arg(long)]
        client: Option<String>,
        /// Filter by forwarded port
        #[arg(long)]
        port: Option<u16>,
        /// Filter by rule marker (e.g. nat-gate:tcp:25565)
        #[arg(long)]
        rule: Option<String>,
        /// Filter by event type: new or end
        #[arg(long)]
        event: Option<String>,
        /// Maximum records to show
        #[arg(long)]
        limit: Option<usize>,
        /// Log directory (default /var/lib/nat-gate)
        #[arg(long)]
        dir: Option<String>,
    },
    /// Show top clients by traffic volume
    Top {
        /// Only aggregate events newer than this (e.g. 24h, 7d)
        #[arg(long)]
        since: Option<String>,
        /// Number of clients to show
        #[arg(long, default_value_t = 10)]
        clients: usize,
        /// Log directory (default /var/lib/nat-gate)
        #[arg(long)]
        dir: Option<String>,
    },

    /// Daily per-rule traffic summaries from the connection log
    Rollup {
        /// Number of days to summarize (default 7)
        #[arg(long)]
        days: Option<u32>,
        /// Log directory (default /var/lib/nat-gate)
        #[arg(long)]
        dir: Option<String>,
    },
    /// Run the logging daemon in the foreground (used by systemd)
    Daemon {
        /// Directory for the JSONL log (default /var/lib/nat-gate)
        #[arg(long)]
        dir: Option<String>,
        /// Rotate after this many bytes (default 10485760)
        #[arg(long)]
        max_bytes: Option<u64>,
        /// Number of rotated files to keep (default 5)
        #[arg(long)]
        keep: Option<usize>,
    },
    /// Show logging configuration and state
    Status,
}

#[derive(Subcommand)]
enum ProxyAction {
    /// Add a PROXY-protocol forwarding rule
    Add {
        /// Protocol — must be "tcp"
        #[arg(value_parser = validate_protocol)]
        proto: String,

        /// Listen port
        port: String,

        /// Target IP address
        target: String,

        /// Target port (defaults to the listen port)
        target_port: Option<String>,

        /// PROXY protocol version: v1, v2, or none
        #[arg(long, default_value = "v2")]
        proxy_protocol: String,
    },
    /// Delete a PROXY-protocol forwarding rule
    Del {
        /// Listen port to remove
        port: String,
    },
    /// List all PROXY-protocol forwarding rules
    List,
    /// Run the PROXY daemon in the foreground (used by systemd)
    Daemon {
        /// Override the log directory (default /var/lib/nat-gate)
        #[arg(long)]
        dir: Option<String>,
    },
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

    if let Err(e) = backend::configure(cli.backend.as_deref()) {
        eprintln!("{e}");
        std::process::exit(2);
    }

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
                    Ok(())
                } else {
                    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };
                    println!(
                        "{} Would add: {} {} port {} -> {}",
                        "[DRY-RUN]".yellow(),
                        ip_version,
                        proto.to_uppercase(),
                        port,
                        target
                    );
                    match backend::add_rule_commands(
                        &proto,
                        &port,
                        &target,
                        interface.as_deref(),
                        ipv6,
                        limit.as_deref(),
                    ) {
                        Ok(cmds) => {
                            for cmd in cmds {
                                println!("  {cmd}");
                            }
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
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
                    Ok(())
                } else {
                    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };
                    println!(
                        "{} Would delete: {} {} port {}",
                        "[DRY-RUN]".yellow(),
                        ip_version,
                        proto.to_uppercase(),
                        port
                    );
                    match backend::load_rules(ipv6) {
                        Ok(store) => {
                            for entry in store.entries_for(&proto, &port) {
                                if let Some(cmd) = backend::deletion_command(entry, ipv6) {
                                    println!("  {cmd}");
                                }
                            }
                        }
                        Err(_) => {
                            println!(
                                "  {}",
                                "(run as root to see the exact rules that would be deleted)"
                                    .dimmed()
                            );
                        }
                    }
                    Ok(())
                }
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
        Commands::Apply { config, check } => {
            if check {
                commands::apply::check_drift(config.as_deref(), cli.json)
            } else {
                commands::apply::run(config.as_deref(), cli.dry_run, cli.json)
            }
        }
        Commands::Tailscale => commands::tailscale::run(cli.json),
        Commands::Flush { ipv6 } => commands::flush::run(ipv6, cli.dry_run, cli.json),
        Commands::Check { port } => commands::check::run(port, cli.json),
        Commands::Doctor => commands::doctor::run(cli.json),
        Commands::Stats { ipv6 } => commands::stats::run(ipv6, cli.json),
        Commands::Completions { shell } => commands::completions::run(shell),
        Commands::Service { action } => match action {
            ServiceAction::Install {
                with_logging,
                with_proxy,
                with_metrics,
            } => commands::service::install(with_logging, with_proxy, with_metrics, cli.json),
            ServiceAction::Uninstall => commands::service::uninstall(cli.json),
            ServiceAction::Status => commands::service::status(cli.json),
        },
        Commands::Sessions => commands::sessions::run(cli.json),
        Commands::Proxy { action } => match action {
            ProxyAction::Add {
                proto,
                port,
                target,
                target_port,
                proxy_protocol,
            } => commands::proxy::add(
                &proto,
                &port,
                &target,
                target_port.as_deref(),
                &proxy_protocol,
                cli.json,
            ),
            ProxyAction::Del { port } => commands::proxy::del(&port, cli.json),
            ProxyAction::List => commands::proxy::list(cli.json),
            ProxyAction::Daemon { dir } => commands::proxy::daemon(dir.as_deref()),
        },
        Commands::Log { action } => match action {
            LogAction::Show {
                since,
                client,
                port,
                rule,
                event,
                limit,
                dir,
            } => commands::log::show(
                commands::log::ShowFilters {
                    since,
                    client,
                    port,
                    rule,
                    event,
                    limit,
                },
                dir,
                cli.json,
            ),
            LogAction::Top {
                since,
                clients,
                dir,
            } => commands::log::top(since, Some(clients), dir, cli.json),
            LogAction::Rollup { days, dir } => commands::log::rollup(days, dir, cli.json),
            LogAction::Daemon {
                dir,
                max_bytes,
                keep,
            } => commands::log::run_daemon(dir, max_bytes, keep),
            LogAction::Status => commands::log::show_status(cli.json),
        },
        Commands::Tui => commands::tui::run(),
        Commands::Metrics { port, once } => commands::metrics::run(port, once),
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
