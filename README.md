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

### Options

| Flag | Description |
|------|-------------|
| `-6, --ipv6` | Use IPv6 (ip6tables) instead of IPv4 |
| `-i, --interface <iface>` | Limit rule to specific interface (e.g., eth0) |

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
