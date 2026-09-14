use colored::Colorize;
use serde::Serialize;
use serde_json;

use crate::backend;
use crate::output;
use crate::utils::check_root;

#[derive(Debug, Serialize)]
struct ForwardingRule {
    proto: String,
    port: String,
    target: String,
    interface: Option<String>,
}

impl From<&crate::iptables::rulestore::NatRule> for ForwardingRule {
    fn from(r: &crate::iptables::rulestore::NatRule) -> Self {
        ForwardingRule {
            proto: r.proto.clone(),
            port: r.port.clone(),
            target: r.target.clone(),
            interface: r.interface.clone(),
        }
    }
}

pub fn run(ipv6: bool, json_output: bool) -> Result<(), String> {
    // Pre-flight checks
    check_root()?;
    backend::check_dependencies()?;

    let ip_version = if ipv6 { "IPv6" } else { "IPv4" };
    let store = backend::load_rules(ipv6)?;
    let rules: Vec<ForwardingRule> = store.rules().map(ForwardingRule::from).collect();

    if rules.is_empty() {
        if json_output {
            output::print_value(serde_json::json!({
                "success": true,
                "data": {
                    "rules": [],
                    "count": 0,
                    "ip_version": ip_version
                }
            }));
        } else {
            println!(
                "{}",
                format!("No nat-gate {ip_version} forwarding rules found.").yellow()
            );
            let v6_flag = if ipv6 { " -6" } else { "" };
            println!(
                "Use {} to add a rule.",
                format!("nat-gate add{v6_flag} <tcp|udp> <port> <target>").cyan()
            );
        }
        return Ok(());
    }

    if json_output {
        output::print_value(serde_json::json!({
            "success": true,
            "data": {
                "rules": rules,
                "count": rules.len(),
                "ip_version": ip_version
            }
        }));
    } else {
        println!(
            "{}",
            format!("Active nat-gate {ip_version} forwarding rules:")
                .blue()
                .bold()
        );
        println!();

        // Table header
        println!("┌──────────┬─────────────┬─────────────────────┬────────────┐");
        println!(
            "│ {} │ {} │ {} │ {} │",
            "Protocol".bold(),
            "Port       ".bold(),
            "Target              ".bold(),
            "Interface ".bold()
        );
        println!("├──────────┼─────────────┼─────────────────────┼────────────┤");

        // Table rows
        for rule in &rules {
            let iface = rule.interface.as_deref().unwrap_or("-");
            println!(
                "│ {:<8} │ {:>11} │ {:<19} │ {:<10} │",
                rule.proto, rule.port, rule.target, iface
            );
        }

        println!("└──────────┴─────────────┴─────────────────────┴────────────┘");
        println!();
        println!("Total: {} rule(s)", rules.len().to_string().green());
    }

    Ok(())
}
