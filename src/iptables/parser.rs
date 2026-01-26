use regex::Regex;

/// Represents a NAT rule managed by nat-gate
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct NatRule {
    pub chain: String,
    pub line_number: u32,
    pub proto: String,
    pub port: String,  // Changed to String to support port ranges like "8000-8080"
    pub target: String,
}

/// Parse iptables-save output to find nat-gate managed rules
#[allow(dead_code)]
pub fn parse_rules(iptables_output: &str) -> Vec<NatRule> {
    let mut rules = Vec::new();

    // Pattern to match nat-gate comment and extract details
    // Supports both single ports and port ranges
    // Example: -A PREROUTING -p tcp -m tcp --dport 443 -m comment --comment "nat-gate:tcp:443" -j DNAT --to-destination 100.64.0.5:443
    // Example: -A PREROUTING -p tcp -m tcp --dport 8000:8080 -m comment --comment "nat-gate:tcp:8000-8080" -j DNAT --to-destination 100.64.0.5:8000-8080
    let prerouting_pattern = Regex::new(
        r#"-A PREROUTING -p (tcp|udp).*--dport (\d+(?::\d+)?).*--comment "nat-gate:(tcp|udp):(\S+)".*--to-destination ([\d.]+):\S+"#
    ).unwrap();

    for cap in prerouting_pattern.captures_iter(iptables_output) {
        if let (Some(proto), Some(port), Some(target)) = (
            cap.get(1).map(|m| m.as_str()),
            cap.get(4).map(|m| m.as_str()),  // Use port from comment (uses - for ranges)
            cap.get(5).map(|m| m.as_str()),
        ) {
            rules.push(NatRule {
                chain: "PREROUTING".to_string(),
                line_number: 0, // Will be filled by line-number parsing
                proto: proto.to_string(),
                port: port.to_string(),
                target: target.to_string(),
            });
        }
    }

    rules
}

/// Parse iptables -L output to get line numbers for nat-gate rules
#[allow(dead_code)]
pub fn parse_rules_with_line_numbers(iptables_list_output: &str) -> Vec<NatRule> {
    let mut rules = Vec::new();
    let mut current_chain = String::new();

    // Pattern for chain header
    let chain_pattern = Regex::new(r"^Chain (\w+)").unwrap();

    // Pattern for nat-gate rules in -L output
    // Supports both single ports and port ranges
    // Example: 1    DNAT       tcp  --  anywhere  anywhere  tcp dpt:443 /* nat-gate:tcp:443 */ to:100.64.0.5:443
    // Example: 1    DNAT       tcp  --  anywhere  anywhere  tcp dpts:8000:8080 /* nat-gate:tcp:8000-8080 */ to:100.64.0.5:8000-8080
    let rule_pattern = Regex::new(
        r"^(\d+)\s+\w+\s+(tcp|udp)\s+.*dpt[s]?:(\d+(?::\d+)?).*nat-gate:(tcp|udp):(\S+).*(?:to:([\d.]+):|MASQUERADE)"
    ).unwrap();

    for line in iptables_list_output.lines() {
        // Check for chain header
        if let Some(cap) = chain_pattern.captures(line) {
            if let Some(chain) = cap.get(1) {
                current_chain = chain.as_str().to_string();
            }
            continue;
        }

        // Only process PREROUTING for listing (avoid duplicates)
        if current_chain != "PREROUTING" {
            continue;
        }

        // Try to match a nat-gate rule
        if let Some(cap) = rule_pattern.captures(line) {
            if let (Some(line_num), Some(proto), Some(port), Some(target)) = (
                cap.get(1).and_then(|m| m.as_str().parse::<u32>().ok()),
                cap.get(2).map(|m| m.as_str()),
                cap.get(5).map(|m| m.as_str()),  // Use port from comment (uses - for ranges)
                cap.get(6).map(|m| m.as_str()),
            ) {
                rules.push(NatRule {
                    chain: current_chain.clone(),
                    line_number: line_num,
                    proto: proto.to_string(),
                    port: port.to_string(),
                    target: target.to_string(),
                });
            }
        }
    }

    rules
}

/// Find rules matching a specific protocol and port for deletion
pub fn find_rules_for_deletion(iptables_list_output: &str, proto: &str, port: &str) -> Vec<(String, u32)> {
    let mut rules: Vec<(String, u32)> = Vec::new();
    let mut current_chain = String::new();

    let chain_pattern = Regex::new(r"^Chain (\w+)").unwrap();
    let comment = format!("nat-gate:{proto}:{port}");

    for line in iptables_list_output.lines() {
        // Check for chain header
        if let Some(cap) = chain_pattern.captures(line) {
            if let Some(chain) = cap.get(1) {
                current_chain = chain.as_str().to_string();
            }
            continue;
        }

        // Only process PREROUTING and POSTROUTING chains
        if current_chain != "PREROUTING" && current_chain != "POSTROUTING" {
            continue;
        }

        // Check if this line contains our comment marker
        if line.contains(&comment) {
            // Extract line number (first number in the line)
            if let Some(line_num) = line.split_whitespace().next() {
                if let Ok(num) = line_num.parse::<u32>() {
                    rules.push((current_chain.clone(), num));
                }
            }
        }
    }

    // Sort by line number in descending order (delete from end first)
    rules.sort_by(|a, b| b.1.cmp(&a.1));
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_rules_for_deletion() {
        let output = r#"Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 /* nat-gate:tcp:443 */ to:100.64.0.5:443
2        0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 /* nat-gate:tcp:80 */ to:100.64.0.5:80

Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 MASQUERADE  tcp  --  *      *       0.0.0.0/0            100.64.0.5           tcp dpt:443 /* nat-gate:tcp:443 */
2        0     0 MASQUERADE  tcp  --  *      *       0.0.0.0/0            100.64.0.5           tcp dpt:80 /* nat-gate:tcp:80 */
"#;

        let rules = find_rules_for_deletion(output, "tcp", "443");
        assert_eq!(rules.len(), 2);
        // Both rules have line number 1, check that both chains are present
        let chains: Vec<_> = rules.iter().map(|(c, _)| c.as_str()).collect();
        assert!(chains.contains(&"PREROUTING"));
        assert!(chains.contains(&"POSTROUTING"));
    }

    #[test]
    fn test_find_rules_for_deletion_port_range() {
        let output = r#"Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpts:8000:8080 /* nat-gate:tcp:8000-8080 */ to:100.64.0.5:8000-8080

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 MASQUERADE  tcp  --  *      *       0.0.0.0/0            100.64.0.5           tcp dpts:8000:8080 /* nat-gate:tcp:8000-8080 */
"#;

        let rules = find_rules_for_deletion(output, "tcp", "8000-8080");
        assert_eq!(rules.len(), 2);
        let chains: Vec<_> = rules.iter().map(|(c, _)| c.as_str()).collect();
        assert!(chains.contains(&"PREROUTING"));
        assert!(chains.contains(&"POSTROUTING"));
    }
}
