# Troubleshooting Guide

This guide helps you diagnose and fix common issues with nat-gate.

## Quick Diagnostics

Run `nat-gate status` to get an overview of your system configuration:

```bash
nat-gate status
```

This shows:
- IP forwarding status (IPv4/IPv6)
- iptables installation status
- Active rule counts
- Network interface states

## Common Issues

### 1. "This command must be run as root"

**Problem:** nat-gate requires root privileges to modify iptables rules.

**Solution:** Use `sudo` before nat-gate commands:

```bash
sudo nat-gate add tcp 443 100.64.0.5
```

### 2. "iptables is not installed"

**Problem:** iptables is not available on your system.

**Solution:** Install iptables:

```bash
# Debian/Ubuntu
sudo apt install iptables

# CentOS/RHEL
sudo yum install iptables

# Arch Linux
sudo pacman -S iptables
```

### 3. Connection Refused

**Symptoms:**
- Connections to the forwarded port are refused
- `telnet <ip> <port>` shows "Connection refused"

**Possible causes and solutions:**

#### a) Target service not running

Check if the service is running on the target machine:

```bash
# On the target machine
sudo ss -tlnp | grep <port>
```

#### b) Target service only listening on localhost

Some services bind to 127.0.0.1 by default. Configure them to listen on all interfaces or the Tailscale IP.

#### c) Firewall on target machine

The target machine's firewall may be blocking incoming connections:

```bash
# On the target machine - check firewall
sudo iptables -L INPUT -n

# Allow the port
sudo iptables -A INPUT -p tcp --dport <port> -j ACCEPT
```

#### d) IP forwarding not enabled

Ensure IP forwarding is enabled:

```bash
sudo nat-gate init
```

Or check manually:

```bash
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1
```

### 4. Connection Timeout

**Symptoms:**
- Connections hang and eventually timeout
- No response from forwarded port

**Possible causes and solutions:**

#### a) Tailscale not connected

Verify Tailscale is running and connected:

```bash
tailscale status
```

#### b) Target machine unreachable

Ping the target Tailscale IP:

```bash
ping 100.64.0.5
```

#### c) Wrong target IP

Verify you're using the correct Tailscale IP:

```bash
nat-gate tailscale
```

#### d) POSTROUTING rule missing

Check that both PREROUTING and POSTROUTING rules exist:

```bash
sudo iptables -t nat -L PREROUTING -n | grep nat-gate
sudo iptables -t nat -L POSTROUTING -n | grep nat-gate
```

### 5. Rules Not Persisting After Reboot

**Problem:** Rules disappear after system restart.

**Solution:** Install iptables-persistent:

```bash
# Debian/Ubuntu
sudo apt install iptables-persistent

# Save current rules
sudo netfilter-persistent save
```

nat-gate will use netfilter-persistent automatically when available.

### 6. Rule Already Exists

**Problem:** `nat-gate add` reports that a rule already exists.

**Solution:** Delete the existing rule first:

```bash
sudo nat-gate del tcp 443
sudo nat-gate add tcp 443 100.64.0.5
```

Or list current rules to see what's configured:

```bash
sudo nat-gate list
```

### 7. IPv6 Not Working

**Problem:** IPv6 forwarding rules don't work.

**Solutions:**

#### a) Enable IPv6 forwarding

```bash
sudo nat-gate init -6
```

#### b) Check ip6tables is installed

```bash
which ip6tables
```

#### c) Verify IPv6 is enabled on target

```bash
# On target machine
ip -6 addr show
```

### 8. Traffic Not Forwarding on Specific Interface

**Problem:** Rules with `-i` interface option don't work.

**Solutions:**

#### a) Verify interface name

```bash
ip link show
```

#### b) Check traffic is arriving on that interface

```bash
sudo tcpdump -i eth0 port 443
```

#### c) Multiple interfaces with same destination

If you have multiple interfaces, traffic might be arriving on a different one than expected.

### 9. Tailscale Command Not Found

**Problem:** `nat-gate tailscale` fails because Tailscale isn't installed.

**Solution:** Install Tailscale:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

Or visit: https://tailscale.com/download

### 10. Port Range Too Large

**Problem:** `nat-gate add` rejects a port range.

**Cause:** nat-gate limits port ranges to 1000 ports to prevent accidental massive rule creation.

**Solution:** Split into smaller ranges or reconsider your port allocation.

## Debug Mode

For detailed iptables information, use iptables directly:

```bash
# Show all NAT rules with line numbers
sudo iptables -t nat -L -n -v --line-numbers

# Show NAT rules in save format
sudo iptables-save -t nat

# Watch for packets hitting rules
sudo watch -n1 'iptables -t nat -L -n -v'
```

## Getting Help

If you're still having issues:

1. Check the [GitHub Issues](https://github.com/h3nr1-d14z/nat-gate/issues) for similar problems
2. Open a new issue with:
   - Output of `nat-gate status`
   - Output of `sudo iptables -t nat -L -n -v`
   - Output of `tailscale status`
   - The exact command you're running
   - The error message you're seeing

## Useful Commands Reference

```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# Enable IP forwarding temporarily
sudo sysctl -w net.ipv4.ip_forward=1

# View all NAT rules
sudo iptables -t nat -L -n -v

# View rules in save format (easier to read)
sudo iptables-save -t nat | grep nat-gate

# Delete all nat-gate rules (careful!)
sudo iptables -t nat -L -n --line-numbers | grep nat-gate

# Check if port is listening
sudo ss -tlnp | grep <port>

# Test connectivity
telnet <ip> <port>
nc -zv <ip> <port>

# Monitor traffic
sudo tcpdump -i any port <port>
```
