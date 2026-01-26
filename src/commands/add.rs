use colored::Colorize;

use crate::iptables::IptablesExecutor;
use crate::utils::{check_iptables, check_root, save_iptables_rules};

pub fn run(
    proto: &str,
    port: &str,
    target: &str,
    interface: Option<&str>,
    ipv6: bool,
    limit: Option<&str>,
) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    check_iptables()?;

    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };
    let iface_info = interface.map(|i| format!(" on {i}")).unwrap_or_default();
    let limit_info = limit.map(|l| format!(" (limit: {l})")).unwrap_or_default();

    println!(
        "{}",
        format!(
            "Adding {} {} port {} -> {}{}{}",
            ip_version,
            proto.to_uppercase(),
            port,
            target,
            iface_info,
            limit_info
        )
        .blue()
        .bold()
    );

    // Check if rule already exists
    let existing_rules = IptablesExecutor::list_nat_rules(ipv6)?;
    let comment = IptablesExecutor::comment_marker(proto, port);
    if existing_rules.contains(&comment) {
        let v6_flag = if ipv6 { " -6" } else { "" };
        return Err(format!(
            "A rule for {proto} port {port} already exists. Delete it first with: nat-gate del{v6_flag} {proto} {port}"
        ));
    }

    // Add PREROUTING rule (DNAT)
    print!("  Adding PREROUTING rule... ");
    IptablesExecutor::add_prerouting_rule(proto, port, target, interface, ipv6, limit)?;
    println!("{}", "OK".green());

    // Add POSTROUTING rule (MASQUERADE)
    print!("  Adding POSTROUTING rule... ");
    IptablesExecutor::add_postrouting_rule(proto, port, target, ipv6)?;
    println!("{}", "OK".green());

    // Save rules
    print!("  Saving rules... ");
    match save_iptables_rules() {
        Ok(_) => println!("{}", "OK".green()),
        Err(e) => {
            println!("{}", "WARNING".yellow());
            println!("    {}", e.yellow());
        }
    }

    println!(
        "\n{}",
        format!(
            "Successfully added: {} {} port {} -> {}{}{}",
            ip_version,
            proto.to_uppercase(),
            port,
            target,
            iface_info,
            limit_info
        )
        .green()
        .bold()
    );

    Ok(())
}
