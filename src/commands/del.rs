use colored::Colorize;

use crate::iptables::{IptablesExecutor, parser::find_rules_for_deletion};
use crate::utils::{check_iptables, check_root, save_iptables_rules};

pub fn run(proto: &str, port: u16) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    check_iptables()?;

    println!(
        "{}",
        format!("Deleting {} port {} forwarding rule", proto.to_uppercase(), port)
            .blue()
            .bold()
    );

    // Get current rules with line numbers
    let rules_output = IptablesExecutor::list_nat_rules()?;

    // Find matching rules
    let rules_to_delete = find_rules_for_deletion(&rules_output, proto, port);

    if rules_to_delete.is_empty() {
        return Err(format!(
            "No nat-gate rule found for {} port {}",
            proto, port
        ));
    }

    println!("  Found {} rule(s) to delete", rules_to_delete.len());

    // Delete rules (in reverse order by line number to maintain correct indices)
    for (chain, line_num) in &rules_to_delete {
        print!("  Deleting from {} (line {})... ", chain, line_num);
        IptablesExecutor::delete_rule_by_line(chain, *line_num)?;
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
            "Successfully deleted: {} port {} forwarding rule",
            proto.to_uppercase(),
            port
        )
        .green()
        .bold()
    );

    Ok(())
}
