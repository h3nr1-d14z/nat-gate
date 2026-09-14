use colored::Colorize;

use crate::iptables::rulestore::RuleStore;
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

    // Check if rule already exists (exact marker match: tcp:443 never
    // collides with tcp:4430)
    let store = RuleStore::load(ipv6)?;
    if store.find(proto, port).is_some() {
        let v6_flag = if ipv6 { " -6" } else { "" };
        return Err(format!(
            "A rule for {proto} port {port} already exists. Delete it first with: nat-gate del{v6_flag} {proto} {port}"
        ));
    }

    // Add PREROUTING rule (DNAT)
    print!("  Adding PREROUTING rule... ");
    IptablesExecutor::add_prerouting_rule(proto, port, target, interface, ipv6, limit)?;
    println!("{}", "OK".green());

    // Add POSTROUTING rule (MASQUERADE); roll back PREROUTING on failure
    // so we never leave a DNAT without its masquerade half
    print!("  Adding POSTROUTING rule... ");
    if let Err(e) = IptablesExecutor::add_postrouting_rule(proto, port, target, ipv6) {
        println!("{}", "FAILED".red());
        eprintln!("    {}", e.yellow());
        print!("  Rolling back PREROUTING rule... ");
        if let Err(rb_err) = rollback_rule(proto, port, ipv6) {
            eprintln!(
                "{} {}",
                "WARNING:".yellow().bold(),
                format!(
                    "rollback failed ({rb_err}); an orphaned PREROUTING rule may remain — run `nat-gate del{ipv6_flag_bare} {proto} {port}`",
                    ipv6_flag_bare = if ipv6 { "-6" } else { "" }
                )
                .yellow()
            );
            return Err(e);
        }
        println!("{}", "OK".green());
        return Err(e);
    }
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

/// Remove every entry carrying this rule's identity (used to undo a
/// partial add). Tolerates entries that were never created.
fn rollback_rule(proto: &str, port: &str, ipv6: bool) -> Result<(), String> {
    let store = RuleStore::load(ipv6)?;
    for entry in store.entries_for(proto, port) {
        IptablesExecutor::delete_rule_spec(entry.chain.as_str(), &entry.spec, ipv6)?;
    }
    Ok(())
}
