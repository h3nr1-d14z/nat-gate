use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

use ratatui::widgets::TableState;
use serde::Deserialize;

use crate::iptables::rulestore::RuleStore;
use crate::iptables::IptablesExecutor;
use crate::utils::format_bytes;

#[derive(Debug, Clone, PartialEq, Default)]
pub enum Screen {
    #[default]
    Main,
    AddRule,
    Help,
    Confirm(ConfirmAction),
    PeerPicker,
}

/// Actions that require confirmation
#[derive(Debug, Clone, PartialEq)]
pub enum ConfirmAction {
    DeleteRule(usize),
    FlushAll,
}

/// Protocol type for rules
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }

    pub fn toggle(&mut self) {
        *self = match self {
            Protocol::Tcp => Protocol::Udp,
            Protocol::Udp => Protocol::Tcp,
        };
    }
}

/// Form fields for add rule dialog
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum FormField {
    #[default]
    Protocol,
    Port,
    Target,
    Interface,
    Limit,
    Cancel,
    Submit,
}

impl FormField {
    pub fn next(&self) -> FormField {
        match self {
            FormField::Protocol => FormField::Port,
            FormField::Port => FormField::Target,
            FormField::Target => FormField::Interface,
            FormField::Interface => FormField::Limit,
            FormField::Limit => FormField::Cancel,
            FormField::Cancel => FormField::Submit,
            FormField::Submit => FormField::Protocol,
        }
    }

    pub fn prev(&self) -> FormField {
        match self {
            FormField::Protocol => FormField::Submit,
            FormField::Port => FormField::Protocol,
            FormField::Target => FormField::Port,
            FormField::Interface => FormField::Target,
            FormField::Limit => FormField::Interface,
            FormField::Cancel => FormField::Limit,
            FormField::Submit => FormField::Cancel,
        }
    }
}

/// Form state for adding a new rule
#[derive(Debug, Clone, Default)]
pub struct AddRuleForm {
    pub protocol: Protocol,
    pub port: String,
    pub target: String,
    pub interface: String,
    pub limit: String,
    pub focus: FormField,
    pub error: Option<String>,
}

impl AddRuleForm {
    pub fn reset(&mut self) {
        self.protocol = Protocol::Tcp;
        self.port.clear();
        self.target.clear();
        self.interface.clear();
        self.limit.clear();
        self.focus = FormField::Protocol;
        self.error = None;
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate port
        if self.port.is_empty() {
            return Err("Port is required".to_string());
        }

        if self.port.contains('-') {
            let parts: Vec<&str> = self.port.split('-').collect();
            if parts.len() != 2 {
                return Err("Invalid port range format".to_string());
            }
            let start: u16 = parts[0]
                .parse()
                .map_err(|_| "Invalid start port".to_string())?;
            let end: u16 = parts[1]
                .parse()
                .map_err(|_| "Invalid end port".to_string())?;
            if start == 0 || end == 0 {
                return Err("Port must be 1-65535".to_string());
            }
            if start > end {
                return Err("Start port must be <= end port".to_string());
            }
            if end - start > 1000 {
                return Err("Port range too large (max 1000)".to_string());
            }
        } else {
            let port: u16 = self
                .port
                .parse()
                .map_err(|_| "Invalid port number".to_string())?;
            if port == 0 {
                return Err("Port must be 1-65535".to_string());
            }
        }

        // Validate target IP
        if self.target.is_empty() {
            return Err("Target IP is required".to_string());
        }

        // Basic IP validation
        if self.target.contains(':') {
            // IPv6 - basic check
            if self.target.split(':').count() < 3 {
                return Err("Invalid IPv6 address".to_string());
            }
        } else {
            // IPv4
            let parts: Vec<&str> = self.target.split('.').collect();
            if parts.len() != 4 {
                return Err("Invalid IPv4 address".to_string());
            }
            for part in parts {
                if part.parse::<u8>().is_err() {
                    return Err("Invalid IPv4 address".to_string());
                }
            }
        }

        // Validate limit if provided
        if !self.limit.is_empty() {
            let parts: Vec<&str> = self.limit.split('/').collect();
            if parts.len() != 2 {
                return Err("Limit format: number/unit".to_string());
            }
            let _rate: u32 = parts[0]
                .parse()
                .map_err(|_| "Invalid limit number".to_string())?;
            let unit = parts[1].to_lowercase();
            match unit.as_str() {
                "s" | "sec" | "second" | "m" | "min" | "minute" | "h" | "hour" | "d" | "day" => {}
                _ => return Err("Unit: sec/min/hour/day".to_string()),
            }
        }

        Ok(())
    }
}

/// A forwarding rule for display
#[derive(Debug, Clone)]
pub struct ForwardingRule {
    pub proto: String,
    pub port: String,
    pub target: String,
}

/// Traffic statistics for a rule
#[derive(Debug, Clone)]
pub struct RuleStats {
    pub proto: String,
    pub port: String,
    pub target: String,
    pub packets: u64,
    pub bytes: u64,
    pub bytes_formatted: String,
}

/// Tailscale peer information
#[derive(Debug, Clone)]
pub struct TailscalePeer {
    pub hostname: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub online: bool,
}

/// Main application state
pub struct App {
    pub(crate) running: bool,
    pub(crate) screen: Screen,
    pub(crate) ipv6_mode: bool,

    // Rules list
    pub(crate) rules: Vec<ForwardingRule>,
    pub(crate) rules_state: TableState,

    // Statistics
    pub(crate) stats: Vec<RuleStats>,
    pub(crate) last_stats_update: Instant,

    // Add rule form
    pub(crate) add_form: AddRuleForm,

    // Tailscale peers
    pub(crate) tailscale_peers: Vec<TailscalePeer>,
    pub(crate) peer_selection: usize,
    pub(crate) peer_scroll_offset: usize,

    // System status
    pub(crate) ipv4_forwarding: bool,
    pub(crate) ipv6_forwarding: bool,

    // Error/status message
    pub(crate) message: Option<(String, bool)>, // (message, is_error)
    pub(crate) message_time: Option<Instant>,
}

impl Default for App {
    fn default() -> Self {
        let mut state = TableState::default();
        state.select(Some(0));

        Self {
            running: true,
            screen: Screen::default(),
            ipv6_mode: false,

            rules: Vec::new(),
            rules_state: state,

            stats: Vec::new(),
            last_stats_update: Instant::now(),

            add_form: AddRuleForm::default(),

            tailscale_peers: Vec::new(),
            peer_selection: 0,
            peer_scroll_offset: 0,

            ipv4_forwarding: false,
            ipv6_forwarding: false,

            message: None,
            message_time: None,
        }
    }
}

impl App {
    /// Check if stats should be auto-refreshed
    pub fn should_refresh_stats(&self) -> bool {
        self.last_stats_update.elapsed() > Duration::from_secs(super::stats_refresh_secs())
    }

    /// Set a status message
    pub fn set_message(&mut self, msg: String, is_error: bool) {
        self.message = Some((msg, is_error));
        self.message_time = Some(Instant::now());
    }

    /// Clear message if it's been shown long enough
    pub fn clear_old_message(&mut self) {
        if let Some(time) = self.message_time {
            if time.elapsed() > Duration::from_secs(super::message_timeout_secs()) {
                self.message = None;
                self.message_time = None;
            }
        }
    }

    /// Get currently selected rule index
    pub fn selected_rule(&self) -> Option<usize> {
        self.rules_state.selected()
    }

    /// Move selection up
    pub fn select_previous(&mut self) {
        if self.rules.is_empty() {
            return;
        }
        let i = match self.rules_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.rules.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.rules_state.select(Some(i));
    }

    /// Move selection down
    pub fn select_next(&mut self) {
        if self.rules.is_empty() {
            return;
        }
        let i = match self.rules_state.selected() {
            Some(i) => {
                if i >= self.rules.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.rules_state.select(Some(i));
    }

    /// Refresh the rules list
    pub fn refresh_rules(&mut self) {
        match RuleStore::load(self.ipv6_mode) {
            Ok(store) => {
                self.rules = store
                    .rules()
                    .map(|r| ForwardingRule {
                        proto: r.proto.clone(),
                        port: r.port.clone(),
                        target: r.target.clone(),
                    })
                    .collect();
                // Reset selection if out of bounds
                if let Some(idx) = self.rules_state.selected() {
                    if idx >= self.rules.len() && !self.rules.is_empty() {
                        self.rules_state.select(Some(self.rules.len() - 1));
                    }
                }
            }
            Err(e) => {
                self.set_message(format!("Failed to list rules: {e}"), true);
            }
        }
    }

    /// Refresh traffic statistics
    pub fn refresh_stats(&mut self) {
        self.last_stats_update = Instant::now();

        match RuleStore::load(self.ipv6_mode) {
            Ok(store) => {
                self.stats = store
                    .stats()
                    .into_iter()
                    .map(|s| RuleStats {
                        proto: s.proto,
                        port: s.port,
                        target: s.target,
                        packets: s.packets,
                        bytes: s.bytes,
                        bytes_formatted: format_bytes(s.bytes),
                    })
                    .collect();
            }
            Err(e) => {
                self.set_message(format!("Failed to get stats: {e}"), true);
            }
        }
    }

    /// Refresh system status
    pub fn refresh_system_status(&mut self) {
        // Check IPv4 forwarding
        if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
            self.ipv4_forwarding = content.trim() == "1";
        }

        // Check IPv6 forwarding
        if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding") {
            self.ipv6_forwarding = content.trim() == "1";
        }
    }

    /// Load Tailscale peers
    pub fn load_tailscale_peers(&mut self) {
        self.tailscale_peers = get_tailscale_peers();
        self.peer_selection = 0;
        self.peer_scroll_offset = 0;
    }

    /// Add a new forwarding rule
    pub fn add_rule(&mut self) -> Result<(), String> {
        self.add_form.validate()?;

        let proto = self.add_form.protocol.as_str();
        let port = &self.add_form.port;
        let target = &self.add_form.target;
        let interface = if self.add_form.interface.is_empty() {
            None
        } else {
            Some(self.add_form.interface.as_str())
        };
        let limit = if self.add_form.limit.is_empty() {
            None
        } else {
            Some(self.add_form.limit.as_str())
        };

        // Add PREROUTING rule
        IptablesExecutor::add_prerouting_rule(
            proto,
            port,
            target,
            interface,
            self.ipv6_mode,
            limit,
        )?;

        // Add POSTROUTING rule
        IptablesExecutor::add_postrouting_rule(proto, port, target, self.ipv6_mode)?;

        Ok(())
    }

    /// Delete the selected rule
    pub fn delete_rule(&mut self, index: usize) -> Result<(), String> {
        if index >= self.rules.len() {
            return Err("Invalid rule index".to_string());
        }

        let rule = &self.rules[index];
        let proto = &rule.proto;
        let port = &rule.port;

        // Exact marker match via the shared rulestore
        let store = RuleStore::load(self.ipv6_mode)?;
        let to_delete = store.entries_for(proto, port);

        if to_delete.is_empty() {
            return Err("No matching rules found".to_string());
        }

        for entry in to_delete {
            IptablesExecutor::delete_rule_spec(entry.chain.as_str(), &entry.spec, self.ipv6_mode)?;
        }

        Ok(())
    }

    /// Flush all rules
    pub fn flush_all(&mut self) -> Result<(), String> {
        let store = RuleStore::load(self.ipv6_mode)?;
        for entry in store.entries() {
            IptablesExecutor::delete_rule_spec(entry.chain.as_str(), &entry.spec, self.ipv6_mode)?;
        }
        Ok(())
    }

    /// Toggle IPv6 mode
    pub fn toggle_ipv6(&mut self) {
        self.ipv6_mode = !self.ipv6_mode;
        self.refresh_rules();
        self.refresh_stats();
    }

    /// Move peer selection up
    pub fn select_previous_peer(&mut self) {
        if self.tailscale_peers.is_empty() {
            return;
        }
        if self.peer_selection == 0 {
            self.peer_selection = self.tailscale_peers.len() - 1;
        } else {
            self.peer_selection -= 1;
        }
        self.adjust_peer_scroll();
    }

    /// Move peer selection down
    pub fn select_next_peer(&mut self) {
        if self.tailscale_peers.is_empty() {
            return;
        }
        if self.peer_selection >= self.tailscale_peers.len() - 1 {
            self.peer_selection = 0;
        } else {
            self.peer_selection += 1;
        }
        self.adjust_peer_scroll();
    }

    /// Adjust scroll offset to keep selection visible
    fn adjust_peer_scroll(&mut self) {
        const VISIBLE_PEERS: usize = 10;

        if self.peer_selection < self.peer_scroll_offset {
            self.peer_scroll_offset = self.peer_selection;
        } else if self.peer_selection >= self.peer_scroll_offset + VISIBLE_PEERS {
            self.peer_scroll_offset = self.peer_selection - VISIBLE_PEERS + 1;
        }
    }

    /// Get visible peers with scroll offset
    pub fn visible_peers(&self) -> impl Iterator<Item = (usize, &TailscalePeer)> {
        const VISIBLE_PEERS: usize = 10;
        self.tailscale_peers
            .iter()
            .enumerate()
            .skip(self.peer_scroll_offset)
            .take(VISIBLE_PEERS)
    }

    /// Check if there are more peers above the scroll viewport
    pub fn has_peers_above(&self) -> bool {
        self.peer_scroll_offset > 0
    }

    /// Check if there are more peers below the scroll viewport
    pub fn has_peers_below(&self) -> bool {
        const VISIBLE_PEERS: usize = 10;
        self.peer_scroll_offset + VISIBLE_PEERS < self.tailscale_peers.len()
    }

    /// Select the currently highlighted peer
    pub fn select_peer(&mut self) {
        if let Some(peer) = self.tailscale_peers.get(self.peer_selection) {
            // Prefer IPv4, fallback to IPv6
            if let Some(ip) = peer.ipv4.as_ref().or(peer.ipv6.as_ref()) {
                self.add_form.target = ip.clone();
            }
        }
    }
}

/// Tailscale status response for JSON parsing
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscaleStatus {
    #[serde(rename = "Self")]
    self_node: Option<TailscalePeerJson>,
    peer: Option<HashMap<String, TailscalePeerJson>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscalePeerJson {
    #[serde(rename = "HostName")]
    hostname: String,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Vec<String>,
    online: bool,
}

/// Get Tailscale peers
fn get_tailscale_peers() -> Vec<TailscalePeer> {
    let output = match Command::new("tailscale")
        .args(["status", "--json"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };

    let status: TailscaleStatus = match serde_json::from_slice(&output) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut peers = Vec::new();

    // Add self node
    if let Some(self_node) = status.self_node {
        peers.push(json_to_peer(&self_node));
    }

    // Add other peers
    if let Some(peer_map) = status.peer {
        for (_, peer) in peer_map {
            peers.push(json_to_peer(&peer));
        }
    }

    // Sort by hostname
    peers.sort_by_key(|p| p.hostname.to_lowercase());

    peers
}

fn json_to_peer(peer: &TailscalePeerJson) -> TailscalePeer {
    let ipv4 = peer
        .tailscale_ips
        .iter()
        .find(|ip| !ip.contains(':'))
        .cloned();

    let ipv6 = peer
        .tailscale_ips
        .iter()
        .find(|ip| ip.contains(':'))
        .cloned();

    TailscalePeer {
        hostname: peer.hostname.clone(),
        ipv4,
        ipv6,
        online: peer.online,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_form_validation_valid() {
        let form = AddRuleForm {
            protocol: Protocol::Tcp,
            port: "443".to_string(),
            target: "100.64.0.5".to_string(),
            interface: String::new(),
            limit: String::new(),
            focus: FormField::Protocol,
            error: None,
        };
        assert!(form.validate().is_ok());
    }

    #[test]
    fn test_form_validation_empty_port() {
        let form = AddRuleForm {
            port: String::new(),
            target: "100.64.0.5".to_string(),
            ..Default::default()
        };
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_form_validation_invalid_ip() {
        let form = AddRuleForm {
            port: "443".to_string(),
            target: "invalid".to_string(),
            ..Default::default()
        };
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_form_validation_port_range() {
        let form = AddRuleForm {
            port: "8000-8080".to_string(),
            target: "100.64.0.5".to_string(),
            ..Default::default()
        };
        assert!(form.validate().is_ok());
    }

    #[test]
    fn test_form_validation_port_range_too_large() {
        let form = AddRuleForm {
            port: "1-2000".to_string(),
            target: "100.64.0.5".to_string(),
            ..Default::default()
        };
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_form_validation_rate_limit() {
        let form = AddRuleForm {
            port: "443".to_string(),
            target: "100.64.0.5".to_string(),
            limit: "100/min".to_string(),
            ..Default::default()
        };
        assert!(form.validate().is_ok());
    }

    #[test]
    fn test_protocol_toggle() {
        let mut proto = Protocol::Tcp;
        proto.toggle();
        assert_eq!(proto, Protocol::Udp);
        proto.toggle();
        assert_eq!(proto, Protocol::Tcp);
    }

    #[test]
    fn test_form_field_navigation() {
        let field = FormField::Protocol;
        assert_eq!(field.next(), FormField::Port);
        assert_eq!(field.prev(), FormField::Submit);
    }
}
