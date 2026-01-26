use colored::Colorize;

use crate::iptables::{parser::find_rules_for_deletion, IptablesExecutor};
use crate::utils::{check_iptables, check_root, save_iptables_rules};

pub fn run(proto: &str, port: &str, ipv6: bool) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    check_iptables()?;

    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };

    println!(
        "{}",
        format!(
            "Deleting {} {} port {} forwarding rule",
            ip_version,
            proto.to_uppercase(),
            port
        )
        .blue()
        .bold()
    );

    // Get current rules with line numbers
    let rules_output = IptablesExecutor::list_nat_rules(ipv6)?;

    // Find matching rules
    let rules_to_delete = find_rules_for_deletion(&rules_output, proto, port);

    if rules_to_delete.is_empty() {
        return Err(format!(
            "No nat-gate rule found for {ip_version} {proto} port {port}"
        ));
    }

    println!("  Found {} rule(s) to delete", rules_to_delete.len());

    // Delete rules (in reverse order by line number to maintain correct indices)
    for (chain, line_num) in &rules_to_delete {
        print!("  Deleting from {chain} (line {line_num})... ");
        IptablesExecutor::delete_rule_by_line(chain, *line_num, ipv6)?;
        println!("{}", "OK".green());
    }

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
            "Successfully deleted: {} {} port {} forwarding rule",
            ip_version,
            proto.to_uppercase(),
            port
        )
        .green()
        .bold()
    );

    Ok(())
}
