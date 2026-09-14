use colored::Colorize;

use crate::iptables::rulestore::RuleStore;
use crate::iptables::IptablesExecutor;
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

    // Load current state and find matching entries (exact marker match,
    // so tcp:443 can never match tcp:4430)
    let store = RuleStore::load(ipv6)?;
    let to_delete = store.entries_for(proto, port);

    if to_delete.is_empty() {
        return Err(format!(
            "No nat-gate rule found for {ip_version} {proto} port {port}"
        ));
    }

    println!("  Found {} rule(s) to delete", to_delete.len());

    // Delete by exact spec: immune to line-number shifts
    for entry in &to_delete {
        print!(
            "  Deleting from {} ({})... ",
            entry.chain.as_str(),
            entry.rule.marker()
        );
        IptablesExecutor::delete_rule_spec(entry.chain.as_str(), &entry.spec, ipv6)?;
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
