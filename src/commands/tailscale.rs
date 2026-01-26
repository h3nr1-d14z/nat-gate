use std::collections::HashMap;
use std::process::Command;

use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json;

use crate::output;

/// Tailscale peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscalePeer {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "HostName")]
    hostname: String,
    #[serde(rename = "DNSName")]
    dns_name: String,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Vec<String>,
    online: bool,
    #[serde(default)]
    exit_node: bool,
    #[serde(default)]
    exit_node_option: bool,
}

/// Tailscale status response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscaleStatus {
    #[serde(rename = "Self")]
    self_node: Option<TailscalePeer>,
    peer: Option<HashMap<String, TailscalePeer>>,
}

/// Simplified peer info for output
#[derive(Debug, Serialize)]
struct PeerInfo {
    hostname: String,
    dns_name: String,
    ipv4: Option<String>,
    ipv6: Option<String>,
    online: bool,
    exit_node: bool,
}

pub fn run(json_output: bool) -> Result<(), String> {
    // Check if tailscale is installed
    let which_output = Command::new("which")
        .arg("tailscale")
        .output()
        .map_err(|e| format!("Failed to check for tailscale: {e}"))?;

    if !which_output.status.success() {
        let msg = "Tailscale is not installed. Please install Tailscale first.";
        if json_output {
            output::print_error(msg);
        }
        return Err(msg.to_string());
    }

    // Get tailscale status
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .map_err(|e| format!("Failed to run tailscale status: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = format!("Tailscale status failed: {stderr}");
        if json_output {
            output::print_error(&msg);
        }
        return Err(msg);
    }

    let status: TailscaleStatus = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse tailscale status: {e}"))?;

    // Collect all peers
    let mut peers: Vec<PeerInfo> = Vec::new();

    // Add self node
    if let Some(self_node) = status.self_node {
        peers.push(peer_to_info(&self_node));
    }

    // Add other peers
    if let Some(peer_map) = status.peer {
        for (_, peer) in peer_map {
            peers.push(peer_to_info(&peer));
        }
    }

    // Sort by hostname
    peers.sort_by(|a, b| a.hostname.to_lowercase().cmp(&b.hostname.to_lowercase()));

    if json_output {
        output::print_list(&peers, "peers");
    } else {
        print_peers_table(&peers);
    }

    Ok(())
}

fn peer_to_info(peer: &TailscalePeer) -> PeerInfo {
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

    // Clean up DNS name (remove trailing dot)
    let dns_name = peer.dns_name.trim_end_matches('.').to_string();

    PeerInfo {
        hostname: peer.hostname.clone(),
        dns_name,
        ipv4,
        ipv6,
        online: peer.online,
        exit_node: peer.exit_node || peer.exit_node_option,
    }
}

fn print_peers_table(peers: &[PeerInfo]) {
    println!("{}", "Tailscale Peers:".blue().bold());
    println!();

    if peers.is_empty() {
        println!("{}", "  No peers found.".yellow());
        return;
    }

    // Calculate column widths
    let name_width = peers
        .iter()
        .map(|p| p.hostname.len())
        .max()
        .unwrap_or(10)
        .max(10);

    let ip_width = 16;

    // Header
    println!(
        "  {:<name_width$}  {:<ip_width$}  {:<ip_width$}  {}",
        "HOSTNAME".bold(),
        "IPv4".bold(),
        "IPv6".bold(),
        "STATUS".bold(),
        name_width = name_width,
        ip_width = ip_width
    );

    println!("  {}", "─".repeat(name_width + ip_width * 2 + 20));

    // Rows
    for peer in peers {
        let ipv4 = peer.ipv4.as_deref().unwrap_or("-");
        let ipv6 = peer
            .ipv6
            .as_ref()
            .map(|ip| {
                // Truncate long IPv6 addresses
                if ip.len() > ip_width {
                    format!("{}...", &ip[..ip_width - 3])
                } else {
                    ip.clone()
                }
            })
            .unwrap_or_else(|| "-".to_string());

        let status = if peer.online {
            "online".green()
        } else {
            "offline".red()
        };

        let exit = if peer.exit_node {
            " [exit]".cyan()
        } else {
            "".normal()
        };

        println!(
            "  {:<name_width$}  {:<ip_width$}  {:<ip_width$}  {}{}",
            peer.hostname,
            ipv4,
            ipv6,
            status,
            exit,
            name_width = name_width,
            ip_width = ip_width
        );
    }

    println!();
    println!("Total: {} peer(s)", peers.len().to_string().green());
    println!();
    println!(
        "Use {} to forward traffic to a peer.",
        "nat-gate add <tcp|udp> <port> <ip>".cyan()
    );
}
