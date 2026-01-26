use colored::Colorize;

use crate::utils::{check_iptables, check_root, enable_ip_forwarding};
use crate::utils::system::{check_iptables_persistent, suggest_install_persistent};

pub fn run() -> Result<(), String> {
    println!("{}", "Initializing nat-gate...".blue().bold());

    // Step 1: Check root
    print!("  Checking root privileges... ");
    check_root()?;
    println!("{}", "OK".green());

    // Step 2: Check iptables
    print!("  Checking iptables installation... ");
    check_iptables()?;
    println!("{}", "OK".green());

    // Step 3: Enable IP forwarding
    print!("  Enabling IP forwarding... ");
    enable_ip_forwarding()?;
    println!("{}", "OK".green());

    // Step 4: Check for iptables-persistent
    print!("  Checking iptables-persistent... ");
    if check_iptables_persistent() {
        println!("{}", "OK".green());
    } else {
        println!("{}", "NOT FOUND".yellow());
        println!("\n{}", suggest_install_persistent().yellow());
    }

    println!("\n{}", "System initialized successfully!".green().bold());
    println!("You can now use:");
    println!("  {} - Add a forwarding rule", "nat-gate add <tcp|udp> <port> <target_ip>".cyan());
    println!("  {} - List active rules", "nat-gate list".cyan());
    println!("  {} - Remove a rule", "nat-gate del <tcp|udp> <port>".cyan());

    Ok(())
}
