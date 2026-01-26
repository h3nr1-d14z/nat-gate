mod commands;
mod iptables;
mod utils;

use clap::{Parser, Subcommand};
use colored::Colorize;

#[derive(Parser)]
#[command(name = "nat-gate")]
#[command(author = "h3nr1-d14z")]
#[command(version)]
#[command(about = "Manage iptables port forwarding through Tailscale tunnels", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize system for port forwarding (enables IP forwarding, checks dependencies)
    Init,

    /// Add a port forwarding rule
    Add {
        /// Protocol (tcp or udp)
        #[arg(value_parser = validate_protocol)]
        proto: String,

        /// Port number to forward (1-65535)
        #[arg(value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,

        /// Target IP address (Tailscale IP to forward to)
        #[arg(value_parser = validate_ip)]
        target: String,
    },

    /// Delete a port forwarding rule
    Del {
        /// Protocol (tcp or udp)
        #[arg(value_parser = validate_protocol)]
        proto: String,

        /// Port number to stop forwarding
        #[arg(value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
    },

    /// List all managed port forwarding rules
    List,
}

fn validate_protocol(s: &str) -> Result<String, String> {
    match s.to_lowercase().as_str() {
        "tcp" | "udp" => Ok(s.to_lowercase()),
        _ => Err("Protocol must be 'tcp' or 'udp'".to_string()),
    }
}

fn validate_ip(s: &str) -> Result<String, String> {
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
        Commands::Init => commands::init::run(),
        Commands::Add { proto, port, target } => commands::add::run(&proto, port, &target),
        Commands::Del { proto, port } => commands::del::run(&proto, port),
        Commands::List => commands::list::run(),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}
