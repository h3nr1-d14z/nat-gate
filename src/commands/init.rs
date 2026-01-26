use colored::Colorize;

use crate::utils::system::{
    check_iptables_persistent, enable_ipv6_forwarding, suggest_install_persistent,
};
use crate::utils::{check_iptables, check_root, enable_ip_forwarding};

pub fn run(ipv6: bool) -> Result<(), String> {
    println!("{}", "Initializing nat-gate...".blue().bold());

    // Step 1: Check root
    print!("  Checking root privileges... ");
    check_root()?;
    println!("{}", "OK".green());

    // Step 2: Check iptables
    print!("  Checking iptables installation... ");
    check_iptables()?;
    println!("{}", "OK".green());

    // Step 3: Enable IPv4 forwarding
    print!("  Enabling IPv4 forwarding... ");
    enable_ip_forwarding()?;
    println!("{}", "OK".green());

    // Step 4: Enable IPv6 forwarding if requested
    if ipv6 {
        print!("  Enabling IPv6 forwarding... ");
        enable_ipv6_forwarding()?;
        println!("{}", "OK".green());
    }

    // Step 5: Check for iptables-persistent
    print!("  Checking iptables-persistent... ");
    if check_iptables_persistent() {
        println!("{}", "OK".green());
    } else {
        println!("{}", "NOT FOUND".yellow());
        println!("\n{}", suggest_install_persistent().yellow());
    }

    println!("\n{}", "System initialized successfully!".green().bold());
    println!("You can now use:");
    println!(
        "  {} - Add a forwarding rule",
        "nat-gate add <tcp|udp> <port> <target_ip>".cyan()
    );
    println!(
        "  {} - Add with interface",
        "nat-gate add tcp 443 10.0.0.5 -i eth0".cyan()
    );
    println!(
        "  {} - Add port range",
        "nat-gate add tcp 8000-8080 10.0.0.5".cyan()
    );
    if ipv6 {
        println!(
            "  {} - Add IPv6 rule",
            "nat-gate add -6 tcp 443 fd7a:115c::1".cyan()
        );
    }
    println!("  {} - List active rules", "nat-gate list".cyan());
    println!("  {} - Show system status", "nat-gate status".cyan());
    println!(
        "  {} - Remove a rule",
        "nat-gate del <tcp|udp> <port>".cyan()
    );

    Ok(())
}
