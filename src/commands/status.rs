use colored::Colorize;
use std::fs;
use std::process::Command;

use crate::iptables::IptablesExecutor;

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

fn print_forwarding_status() {
    // IPv4
    let ipv4_forward = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    print!("  IPv4: ");
    if ipv4_forward {
        println!("{}", "enabled".green());
    } else {
        println!("{}", "disabled".red());
    }

    // IPv6
    let ipv6_forward = fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    print!("  IPv6: ");
    if ipv6_forward {
        println!("{}", "enabled".green());
    } else {
        println!("{}", "disabled".yellow());
    }
}

fn print_iptables_status() {
    // Check iptables
    let iptables_ok = Command::new("which")
        .arg("iptables")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    print!("  iptables:   ");
    if iptables_ok {
        println!("{}", "installed".green());
    } else {
        println!("{}", "not found".red());
    }

    // Check ip6tables
    let ip6tables_ok = Command::new("which")
        .arg("ip6tables")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    print!("  ip6tables:  ");
    if ip6tables_ok {
        println!("{}", "installed".green());
    } else {
        println!("{}", "not found".yellow());
    }

    // Check iptables-persistent
    let persistent_ok = Command::new("which")
        .arg("netfilter-persistent")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    print!("  persistent: ");
    if persistent_ok {
        println!("{}", "installed".green());
    } else {
        println!("{}", "not installed (rules may not persist)".yellow());
    }
}

fn print_rules_summary() -> Result<(), String> {
    // Count IPv4 rules
    let ipv4_count = IptablesExecutor::count_rules(false).unwrap_or(0);

    // Count IPv6 rules (may fail if not root or ip6tables not available)
    let ipv6_count = IptablesExecutor::count_rules(true).unwrap_or(0);

    println!("  IPv4 rules: {}", ipv4_count.to_string().cyan());
    println!("  IPv6 rules: {}", ipv6_count.to_string().cyan());

    if ipv4_count > 0 || ipv6_count > 0 {
        println!();
        println!("  Use {} to see details", "nat-gate list".cyan());
        if ipv6_count > 0 {
            println!("  Use {} for IPv6 rules", "nat-gate list -6".cyan());
        }
    }

    Ok(())
}

fn print_interfaces() {
    let output = Command::new("ip")
        .args(["-o", "link", "show"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // Parse interface name from: "2: eth0: <BROADCAST..."
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let iface = parts[1].trim();
                    if iface != "lo" {
                        let state = if line.contains("state UP") {
                            "UP".green()
                        } else {
                            "DOWN".red()
                        };
                        println!("  {:<15} {}", iface, state);
                    }
                }
            }
        }
    } else {
        println!("  {}", "Unable to list interfaces".yellow());
    }
}
