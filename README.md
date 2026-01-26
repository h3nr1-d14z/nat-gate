# nat-gate

A CLI tool for managing iptables port forwarding through Tailscale tunnels.

**nat-gate** makes it easy to expose services running on your Tailscale network to the public internet through a gateway server. Perfect for:
- Exposing web servers behind NAT
- Running game servers accessible from anywhere
- Sharing development environments

## Installation

### curl | bash (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/h3nr1-d14z/nat-gate/master/scripts/install.sh | bash
```

### npm

```bash
npm install -g @h3nr1-d14z/nat-gate
```

### From Source

```bash
cargo install --git https://github.com/h3nr1-d14z/nat-gate
```

## Quick Start

1. **Initialize your system** (enables IP forwarding, checks dependencies):

```bash
sudo nat-gate init
```

2. **Add a forwarding rule** (forward TCP port 443 to Tailscale IP 100.64.0.5):

```bash
sudo nat-gate add tcp 443 100.64.0.5
```

3. **List active rules**:

```bash
sudo nat-gate list
```

4. **Remove a rule**:

```bash
sudo nat-gate del tcp 443
```

5. **Check system status**:

```bash
nat-gate status
```

## Commands

| Command | Description |
|---------|-------------|
| `nat-gate init` | Initialize system for port forwarding |
| `nat-gate add <tcp\|udp> <port> <target_ip>` | Add a forwarding rule |
| `nat-gate del <tcp\|udp> <port>` | Delete a forwarding rule |
| `nat-gate list` | List all managed rules |
| `nat-gate status` | Show system status and rule summary |
| `nat-gate backup [file]` | Export rules to JSON backup |
| `nat-gate restore <file>` | Import rules from JSON backup |
| `nat-gate apply` | Apply rules from YAML config file |
| `nat-gate tailscale` | List available Tailscale peers |

### Global Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview changes without executing |
| `--json` | Output in JSON format for scripting |

### Command Options

| Flag | Description |
|------|-------------|
| `-6, --ipv6` | Use IPv6 (ip6tables) instead of IPv4 |
| `-i, --interface <iface>` | Limit rule to specific interface (e.g., eth0) |
| `-c, --config <file>` | Specify config file path (for `apply` command) |

## Features

### Port Ranges

Forward a range of ports at once:

```bash
# Forward ports 8000-8080 to target
sudo nat-gate add tcp 8000-8080 100.64.0.5
```

### IPv6 Support

Use the `-6` flag for IPv6 forwarding:

```bash
# Initialize with IPv6 support
sudo nat-gate init -6

# Add IPv6 forwarding rule
sudo nat-gate add -6 tcp 443 fd7a:115c:a1e0::1

# List IPv6 rules
sudo nat-gate list -6
```

### Interface Selection

Limit forwarding to a specific network interface:

```bash
# Only forward traffic arriving on eth0
sudo nat-gate add tcp 443 100.64.0.5 -i eth0
```

### Dry Run Mode

Preview changes without executing them:

```bash
# See what would happen
nat-gate --dry-run add tcp 443 100.64.0.5

# Preview in JSON format
nat-gate --dry-run --json add tcp 443 100.64.0.5
```

### JSON Output

Get machine-readable output for scripting:

```bash
# List rules as JSON
sudo nat-gate --json list

# Get status as JSON
nat-gate --json status
```

### Backup & Restore

Save and restore your rules:

```bash
# Backup all rules to a file
sudo nat-gate backup my-rules.json

# Restore rules (with preview)
nat-gate --dry-run restore my-rules.json

# Actually restore
sudo nat-gate restore my-rules.json
```

### Config File

Define rules in a YAML config file:

```yaml
# ~/.config/nat-gate/rules.yaml
rules:
  - protocol: tcp
    port: 443
    target: 100.64.0.5
  - protocol: tcp
    port: 8000-8080
    target: 100.64.0.5
    interface: eth0
  - protocol: udp
    port: 51820
    target: 100.64.0.10
```

Apply the config:

```bash
# Apply from default location
sudo nat-gate apply

# Apply from specific file
sudo nat-gate apply -c /path/to/rules.yaml

# Preview first
nat-gate --dry-run apply
```

### Tailscale Integration

List available Tailscale peers and their IPs:

```bash
nat-gate tailscale
```

Output:
```
Tailscale Peers:

  HOSTNAME          IPv4              IPv6              STATUS
  ─────────────────────────────────────────────────────────────
  my-server         100.64.0.5        fd7a:115c:...     online
  raspberry-pi      100.64.0.10       fd7a:115c:...     online
  laptop            100.64.0.15       -                 offline

Total: 3 peer(s)
```

### System Status

Check your system's forwarding configuration:

```bash
nat-gate status
```

This shows:
- IP forwarding status (IPv4/IPv6)
- iptables installation status
- Active rule counts
- Network interfaces

## How It Works

nat-gate manages iptables NAT rules to forward incoming traffic to Tailscale IPs:

1. **PREROUTING (DNAT)**: Rewrites the destination IP of incoming packets
2. **POSTROUTING (MASQUERADE)**: Ensures return traffic is properly routed

All rules are tagged with a comment (`nat-gate:<proto>:<port>`) for safe identification and removal.

## Example Use Case

You have a web server running on a machine with Tailscale IP `100.64.0.5`, but it's behind NAT and can't receive incoming connections. You have a VPS with a public IP.

On your VPS:

```bash
# One-time setup
sudo nat-gate init

# Forward HTTPS traffic to your web server
sudo nat-gate add tcp 443 100.64.0.5

# Forward HTTP traffic too
sudo nat-gate add tcp 80 100.64.0.5

# Forward a range of ports for dev server
sudo nat-gate add tcp 3000-3010 100.64.0.5
```

Now traffic to your VPS on ports 80, 443, and 3000-3010 is forwarded through Tailscale to your web server.

## Requirements

- Linux (iptables)
- Root/sudo access
- Tailscale installed and connected
- `iptables-persistent` recommended for rule persistence

## Safety Features

- All rules are tagged with identifiable comments
- Only removes rules created by nat-gate
- Validates all inputs (protocol, port range, IP format)
- Checks for root privileges before any operation
- Warns if rules can't be persisted
- Dry-run mode to preview changes

## Documentation

- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [Man Page](docs/nat-gate.1) - Full command reference

## Building from Source

```bash
git clone https://github.com/h3nr1-d14z/nat-gate
cd nat-gate
cargo build --release
```

Binary will be at `target/release/nat-gate`.

### Cross-compilation

```bash
# Install cross
cargo install cross

# Build for Linux x86_64
cross build --target x86_64-unknown-linux-musl --release

# Build for Linux ARM64
cross build --target aarch64-unknown-linux-musl --release
```

## License

MIT License - see [LICENSE](LICENSE) for details.
