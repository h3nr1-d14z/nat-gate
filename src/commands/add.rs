use colored::Colorize;

use crate::iptables::IptablesExecutor;
use crate::utils::{check_iptables, check_root, save_iptables_rules};

pub fn run(proto: &str, port: u16, target: &str) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    check_iptables()?;

    println!(
        "{}",
        format!("Adding {} port {} -> {}", proto.to_uppercase(), port, target)
            .blue()
            .bold()
    );

    // Check if rule already exists
    let existing_rules = IptablesExecutor::list_nat_rules()?;
    let comment = IptablesExecutor::comment_marker(proto, port);
    if existing_rules.contains(&comment) {
        return Err(format!(
            "A rule for {} port {} already exists. Delete it first with: nat-gate del {} {}",
            proto, port, proto, port
        ));
    }

    // Add PREROUTING rule (DNAT)
    print!("  Adding PREROUTING rule... ");
    IptablesExecutor::add_prerouting_rule(proto, port, target)?;
    println!("{}", "OK".green());

    // Add POSTROUTING rule (MASQUERADE)
    print!("  Adding POSTROUTING rule... ");
    IptablesExecutor::add_postrouting_rule(proto, port, target)?;
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
            "Successfully added: {} port {} -> {}",
            proto.to_uppercase(),
            port,
            target
        )
        .green()
        .bold()
    );

    Ok(())
}
