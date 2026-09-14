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

### Docker

```bash
docker run --rm --cap-add=NET_ADMIN --network=host \
  ghcr.io/h3nr1-d14z/nat-gate list
```

### Homebrew (Linux)

```bash
brew install h3nr1-d14z/tap/nat-gate
```

### Arch Linux (AUR)

```bash
yay -S nat-gate
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
| `nat-gate flush` | Remove all nat-gate managed rules |
| `nat-gate check` | Health check for rules and connectivity |
| `nat-gate stats` | Show traffic statistics per rule |
| `nat-gate backup [file]` | Export rules to JSON backup |
| `nat-gate restore <file>` | Import rules from JSON backup |
| `nat-gate apply` | Apply rules from YAML config file |
| `nat-gate tailscale` | List available Tailscale peers |
| `nat-gate completions <shell>` | Generate shell completions |
| `nat-gate service <install\|uninstall\|status>` | Manage systemd service |
| `nat-gate sessions` | Show live forwarded sessions (client IPs) |
| `nat-gate log <show\|top\|daemon\|status>` | Query connection logs / run logger |
| `nat-gate tui` | Launch interactive terminal UI |

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
| `--limit <rate>` | Rate limit connections (e.g., 100/min, 10/sec) |
| `-c, --config <file>` | Specify config file path (for `apply` command) |

## Features

### Port Ranges

Forward a range of ports at once:

```bash
# Forward ports 8000-8080 to target
sudo nat-gate add tcp 8000-8080 100.64.0.5
```

### Rate Limiting

Protect your services from abuse with rate limiting:

```bash
# Limit to 100 connections per minute
sudo nat-gate add tcp 443 100.64.0.5 --limit 100/min

# Limit to 10 connections per second
sudo nat-gate add tcp 80 100.64.0.5 --limit 10/sec
```

Supported units: `sec`, `min`, `hour`, `day`

Rate limiting applies to **new connections only**: once a connection is
established, its packets are NAT'd by the kernel's conntrack table and no
longer traverse the nat rules, so active sessions are never throttled
mid-stream. Over-limit new connections are refused (the first packet does
not match the DNAT rule and is delivered locally, producing an immediate
connection refusal rather than a timeout).

Rate limits are preserved by the YAML config, `apply`, `backup`, and
`restore` round-trip.

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

### Flush All Rules

Remove all nat-gate managed rules at once:

```bash
# Remove all IPv4 rules
sudo nat-gate flush

# Remove all IPv6 rules
sudo nat-gate flush -6

# Preview what would be removed
nat-gate --dry-run flush
```

### Health Check

Verify your forwarding configuration is working:

```bash
# Check all rules
sudo nat-gate check

# Test a specific port
sudo nat-gate check --port 443
```

Output:
```
Checking nat-gate configuration...
  IP forwarding (IPv4): OK
  IP forwarding (IPv6): OK

  IPv4 Rule Health:
    tcp:443 -> 100.64.0.5: OK (target reachable)
    tcp:80 -> 100.64.0.5: OK (target reachable)
    udp:51820 -> 100.64.0.10: WARN (target unreachable)

All checks passed!
```

### Traffic Statistics

View packet and byte counts per rule:

```bash
sudo nat-gate stats
```

Output:
```
Rule Statistics (IPv4):
------------------------------------------------------------
 Protocol    Port       Target          Packets     Bytes
------------------------------------------------------------
    tcp      443     100.64.0.5          1,234    2.1 MB
    tcp       80     100.64.0.5            567    128 KB
------------------------------------------------------------
   TOTAL                                 1,801    2.2 MB

Total: 2 rule(s), 1,801 packets, 2.2 MB
```

### Connection Logging (Gaming & Abuse Visibility)

Because forwarded traffic is MASQUERADE'd, your game server only sees the
gateway's Tailscale IP — the original player IPs exist only in the gateway's
conntrack table. nat-gate captures them there.

Requires `conntrack-tools` on the gateway (`apt install conntrack` /
`pacman -S conntrack-tools`).

```bash
# Live forwarded sessions right now (client IP, traffic per session)
sudo nat-gate sessions

# Enable persistent logging (installs nat-gate-logger.service)
sudo nat-gate service install --with-logging

# Query the log
sudo nat-gate log show --since 24h
sudo nat-gate log show --client 203.0.113.7 --port 25565
sudo nat-gate log top --since 7d          # top talkers — real IPs for bans
```

Logged events (`/var/lib/nat-gate/connections.jsonl`, JSONL, size-rotated
10 MB × 5):

```json
{"ts":"2026-09-14T12:00:01Z","event":"new","proto":"tcp","client":"203.0.113.7:52188","rule":"nat-gate:tcp:25565","target":"100.64.0.5","verdict":"forwarded"}
{"ts":"2026-09-14T12:38:21Z","event":"end","proto":"tcp","client":"203.0.113.7:52188","rule":"nat-gate:tcp:25565","target":"100.64.0.5","verdict":"forwarded","duration_s":2291,"packets":14823,"bytes":2204551}
```

Each record's `verdict` distinguishes `forwarded` traffic from
`not_forwarded` (rate-limited or refused) — the latter gives you visibility
into connection floods your rate limits are absorbing.

**Privacy:** player IP addresses are personal data. Logs stay on the
gateway, rotation bounds retention (~50 MB by default); tune with
`log daemon --max-bytes/--keep`. Deleting `/var/lib/nat-gate/` clears them.

### Shell Completions

Generate completions for your shell:

```bash
# Bash
nat-gate completions bash > /etc/bash_completion.d/nat-gate

# Zsh
nat-gate completions zsh > ~/.zfunc/_nat-gate

# Fish
nat-gate completions fish > ~/.config/fish/completions/nat-gate.fish
```

### Systemd Service

Install nat-gate as a systemd service to automatically apply rules on boot:

```bash
# Install and enable the service
sudo nat-gate service install

# Check service status
sudo nat-gate service status

# Uninstall the service
sudo nat-gate service uninstall
```

The service reads rules from `~/.config/nat-gate/rules.yaml` or `/etc/nat-gate/rules.yaml`.

### Interactive TUI Mode

Launch an interactive terminal interface for managing rules:

```bash
sudo nat-gate tui
```

The TUI provides:
- **Rules list** with real-time traffic statistics
- **Add rules** with Tailscale peer picker
- **Delete rules** with confirmation
- **Auto-refresh** statistics every 5 seconds
- **IPv4/IPv6 toggle**

**Key Bindings:**

| Key | Action |
|-----|--------|
| `↑`/`k` | Move selection up |
| `↓`/`j` | Move selection down |
| `a` | Add new rule |
| `d`/`Delete` | Delete selected rule |
| `f` | Flush all rules |
| `r` | Refresh data |
| `6` | Toggle IPv4/IPv6 mode |
| `?`/`h` | Show help |
| `q`/`Esc` | Quit / Close modal |

**Add Rule Form:**
- Use `Tab` to navigate between fields
- Press `Enter` on Target field to open Tailscale peer picker
- Press `Space` on Protocol field to toggle TCP/UDP

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

# Get stats as JSON
sudo nat-gate --json stats
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
    limit: 100/min
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

## Docker Usage

Run nat-gate in a Docker container:

```bash
# Show help
docker run --rm ghcr.io/h3nr1-d14z/nat-gate --help

# List rules (requires host network and NET_ADMIN capability)
docker run --rm --cap-add=NET_ADMIN --network=host \
  ghcr.io/h3nr1-d14z/nat-gate list

# Add a rule
docker run --rm --cap-add=NET_ADMIN --network=host \
  ghcr.io/h3nr1-d14z/nat-gate add tcp 443 100.64.0.5

# Use with config file
docker run --rm --cap-add=NET_ADMIN --network=host \
  -v /path/to/rules.yaml:/etc/nat-gate/rules.yaml \
  ghcr.io/h3nr1-d14z/nat-gate apply -c /etc/nat-gate/rules.yaml
```

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

# Optional: Install as a service for persistence
sudo nat-gate service install
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
- Rate limiting to protect services

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

### Docker Build

```bash
docker build -t nat-gate .
```

## License

MIT License - see [LICENSE](LICENSE) for details.
