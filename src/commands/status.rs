use colored::Colorize;
use serde::Serialize;
use serde_json;
use std::fs;
use std::process::Command;

use crate::iptables::IptablesExecutor;
use crate::output;

#[derive(Debug, Serialize)]
struct SystemStatus {
    ip_forwarding: ForwardingStatus,
    iptables: IptablesStatus,
    rules: RulesStatus,
    interfaces: Vec<InterfaceInfo>,
}

#[derive(Debug, Serialize)]
struct ForwardingStatus {
    ipv4: bool,
    ipv6: bool,
}

#[derive(Debug, Serialize)]
struct IptablesStatus {
    iptables_installed: bool,
    ip6tables_installed: bool,
    persistent_installed: bool,
}

#[derive(Debug, Serialize)]
struct RulesStatus {
    ipv4_count: usize,
    ipv6_count: usize,
}

#[derive(Debug, Serialize)]
struct InterfaceInfo {
    name: String,
    state: String,
}

pub fn run() -> Result<(), String> {
    println!("{}", "nat-gate System Status".blue().bold());
    println!("{}", "═".repeat(50));
    println!();

    // IP Forwarding Status
    println!("{}", "IP Forwarding:".bold());
    print_forwarding_status();
    println!();

    // iptables Status
    println!("{}", "iptables:".bold());
    print_iptables_status();
    println!();

    // Active Rules
    println!("{}", "Active nat-gate Rules:".bold());
    print_rules_summary()?;
    println!();

    // Network Interfaces
    println!("{}", "Network Interfaces:".bold());
    print_interfaces();

    Ok(())
}

pub fn run_json() -> Result<(), String> {
    let status = get_system_status();
    output::print_value(serde_json::json!({
        "success": true,
        "data": status
    }));
    Ok(())
}

fn get_system_status() -> SystemStatus {
    SystemStatus {
        ip_forwarding: get_forwarding_status(),
        iptables: get_iptables_status(),
        rules: get_rules_status(),
        interfaces: get_interfaces(),
    }
}

fn get_forwarding_status() -> ForwardingStatus {
    let ipv4 = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    let ipv6 = fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    ForwardingStatus { ipv4, ipv6 }
}

fn get_iptables_status() -> IptablesStatus {
    let iptables_installed = Command::new("which")
        .arg("iptables")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let ip6tables_installed = Command::new("which")
        .arg("ip6tables")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let persistent_installed = Command::new("which")
        .arg("netfilter-persistent")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    IptablesStatus {
        iptables_installed,
        ip6tables_installed,
        persistent_installed,
    }
}

fn get_rules_status() -> RulesStatus {
    let ipv4_count = IptablesExecutor::count_rules(false).unwrap_or(0);
    let ipv6_count = IptablesExecutor::count_rules(true).unwrap_or(0);

    RulesStatus {
        ipv4_count,
        ipv6_count,
    }
}

fn get_interfaces() -> Vec<InterfaceInfo> {
    let mut interfaces = Vec::new();

    if let Ok(output) = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let iface = parts[1].trim().to_string();
                    if iface != "lo" {
                        let state = if line.contains("state UP") {
                            "UP".to_string()
                        } else {
                            "DOWN".to_string()
                        };
                        interfaces.push(InterfaceInfo { name: iface, state });
                    }
                }
            }
        }
    }

    interfaces
}

fn print_forwarding_status() {
    let status = get_forwarding_status();

    print!("  IPv4: ");
    if status.ipv4 {
        println!("{}", "enabled".green());
    } else {
        println!("{}", "disabled".red());
    }

    print!("  IPv6: ");
    if status.ipv6 {
        println!("{}", "enabled".green());
    } else {
        println!("{}", "disabled".yellow());
    }
}

fn print_iptables_status() {
    let status = get_iptables_status();

    print!("  iptables:   ");
    if status.iptables_installed {
        println!("{}", "installed".green());
    } else {
        println!("{}", "not found".red());
    }

    print!("  ip6tables:  ");
    if status.ip6tables_installed {
        println!("{}", "installed".green());
    } else {
        println!("{}", "not found".yellow());
    }

    print!("  persistent: ");
    if status.persistent_installed {
        println!("{}", "installed".green());
    } else {
        println!("{}", "not installed (rules may not persist)".yellow());
    }
}

fn print_rules_summary() -> Result<(), String> {
    let status = get_rules_status();

    println!("  IPv4 rules: {}", status.ipv4_count.to_string().cyan());
    println!("  IPv6 rules: {}", status.ipv6_count.to_string().cyan());

    if status.ipv4_count > 0 || status.ipv6_count > 0 {
        println!();
        println!("  Use {} to see details", "nat-gate list".cyan());
        if status.ipv6_count > 0 {
            println!("  Use {} for IPv6 rules", "nat-gate list -6".cyan());
        }
    }

    Ok(())
}

fn print_interfaces() {
    let interfaces = get_interfaces();

    if interfaces.is_empty() {
        println!("  {}", "Unable to list interfaces".yellow());
        return;
    }

    for iface in interfaces {
        let state = if iface.state == "UP" {
            "UP".green()
        } else {
            "DOWN".red()
        };
        println!("  {:<15} {}", iface.name, state);
    }
}
