# routectl

Route network traffic through different interfaces based on domain names — using plain Linux policy routing. No VPN, no kernel modules, no iptables.

```
youtube.com            →  wlan0   (unlimited SIM)
*.googlevideo.com      →  wlan0   (matched live as DNS resolves)
github.com             →  eth0    (default broadband)
```

---

## How it works

routectl resolves domain names to IPs and installs `/32` host routes that override the default route for matched destinations. Every packet to a matched IP exits through the interface you specified — everything else goes through your normal default route, untouched.

For **exact** domains, it pre-resolves them on startup. For **glob and regex** patterns (like `*.googlevideo.com`), it runs a DNS proxy in the background that intercepts every DNS response on the machine and installs routes on the fly — before the app even opens the connection. Both happen automatically from a single command.

```
# What routectl does under the hood:
ip route replace 142.250.74.14/32 via 10.20.30.1 dev wlan0 metric 50
ip route replace 203.0.113.1/32   via 10.20.30.1 dev wlan0 metric 50
```

---

## Requirements

- Linux with `iproute2` (`ip` command)
- Python 3.9+
- `pip install pyyaml` — for YAML config files
- `pip install dnspython` — optional, improves DNS resolution reliability
- Root / `sudo` for commands that modify routes

---

## Installation

```bash
git clone https://github.com/yourname/routectl
cd routectl
pip install pyyaml
```

---

## Quick start

**1. Find your interface names**

```bash
ip link show        # → eth0, wlan0, wg0 …
ip route show       # → gateways
```

**2. Edit `routes.yaml`**

```yaml
default: broadband

interfaces:
  unlimited_sim:
    device: wlan0
  broadband:
    device: eth0

rules:
  - via: unlimited_sim
    domains:
      - youtube.com
      - "*.googlevideo.com"
      - "*.ytimg.com"
```

**3. Test your rules — no root needed**

```bash
python3 -m routectl test youtube.com
python3 -m routectl test rr3.sn-abc.googlevideo.com
```

**4. Run**

```bash
sudo python3 -m routectl daemon
```

That's it. routectl pre-routes all literal domains, then automatically starts the DNS proxy for glob/regex patterns. Everything is cleaned up on exit.

---

## Commands

| Command | Root | Description |
|---------|------|-------------|
| `daemon` | ✓ | Run forever: pre-routes literals, auto-starts DNS proxy if glob/regex rules exist, refreshes periodically |
| `apply-all` | ✓ | One-shot: resolve and route all literal domains from the config, then exit |
| `apply <domain …>` | ✓ | Resolve and route specific domains |
| `flush` | ✓ | Remove all managed routes |
| `status` | — | Show interfaces, rules, and active routes |
| `test <domain>` | — | Show which interface a domain would use (no changes) |
| `info` | — | Show detected gateways and interface state |

**Flags:**

| Flag | Description |
|------|-------------|
| `-c / --config <file>` | Config file path (default: `routes.yaml`) |
| `-n / --dry-run` | Print `ip route` commands without running them |
| `-v / --verbose` | Enable debug logging |

---

## How `daemon` works

`daemon` is the primary run command. It does everything in one shot:

1. **Pre-routes** all literal/exact domains from your rules file immediately
2. **Detects** whether your config has any glob or regex rules
3. **If yes** — starts a DNS proxy in the background automatically:
   - Detects your system's DNS resolver (systemd-resolved or resolv.conf)
   - Finds the real upstream DNS server
   - Redirects system DNS through the proxy transparently
   - Every DNS response is inspected; matched hostnames get a route installed instantly
4. **Loops** every `daemon_interval` seconds to refresh routes as IPs change
5. **On exit** (Ctrl+C or SIGTERM) — restores DNS config exactly as it was, saves state

If your config has only exact rules, the DNS proxy is never started.

---

## Config reference

### Interfaces

```yaml
interfaces:
  my_interface:
    device: wlan0           # required — kernel device name (ip link show)
    gateway: 10.20.30.1     # optional — auto-detected if omitted
    metric: 50              # optional — lower = higher priority (default: 100, 110, …)
    description: "..."      # optional — shown in status output
    table_id: 201           # optional — routing table ID (default: 200, 201, …)
```

### Rules

```yaml
rules:
  - comment: "optional note"
    via: my_interface       # required — must match an interface name above
    ttl: 300                # optional — seconds to cache IPs (default: 300)
    domains:
      - "pattern"
      - "another pattern"
```

### Global settings

```yaml
default: broadband          # interface for unmatched domains (omit to leave alone)
default_ttl: 300            # TTL applied to all rules unless overridden
daemon_interval: 60         # seconds between daemon refresh cycles
resolve_retries: 3          # DNS retry count per domain
resolve_timeout: 4.0        # seconds per DNS attempt
ipv6: false                 # also manage IPv6 routes (AAAA records)
table_base: 200             # first routing table ID reserved for this tool

# DNS proxy settings (used automatically when glob/regex rules are present)
dns_listen: "127.0.0.53"
dns_port: 53
dns_upstream: "8.8.8.8"    # overridden automatically by real system DNS
dns_upstream_port: 53
```

---

## Pattern syntax

Three types, freely mixed within any rule. Rules are evaluated top-to-bottom — first match wins.

### Exact
```yaml
- youtube.com         # matches youtube.com and all subdomains (*.youtube.com)
```

### Glob
Uses shell-style wildcards. Requires the DNS proxy (auto-started by `daemon`).
```yaml
- "*.googlevideo.com"       # any subdomain
- "cdn[0-9]*.twitch.tv"     # cdn1.twitch.tv, cdn99.twitch.tv …
- "img-??.example.com"      # exactly two characters in position
```

| Symbol | Meaning |
|--------|---------|
| `*` | Any number of characters |
| `?` | Exactly one character |
| `[abc]` | One character from the set |
| `[0-9]` | One character from the range |

### Regex
Wrap in `/slashes/`. Flags: `i` (case-insensitive), `m`, `s`, `x`. Requires the DNS proxy.
```yaml
- "/\\.live$/"                            # any .live TLD
- "/^(www\\.)?youtube\\.com$/"            # anchored match with optional www
- "/\\.akamai(zed|edge)?\\.(com|net)$/"   # alternation
- "/\\.(ru|cn|ir)$/i"                     # multiple TLDs, case-insensitive
```

> Glob and regex patterns cannot be pre-resolved (they match infinite hostnames).
> `daemon` handles them automatically via the DNS proxy. `apply-all` skips them and logs a count.

---

## Package layout

```
routectl/
├── config.py      — Config, Interface, Rule dataclasses + YAML/JSON loader
├── iface.py       — device and gateway detection
├── routing.py     — ip route add/del, DNS resolution, state file
├── dns.py         — DNS packet parser, proxy server, resolver backend management
├── display.py     — terminal output (status, test, info)
├── cli.py         — argument parser and command handlers
├── __init__.py    — package exports
└── __main__.py    — python3 -m routectl entry point
```

---

## Examples

### Zero-rated SIM for streaming

Route YouTube and Netflix through a carrier SIM that zero-rates them:

```yaml
default: broadband
interfaces:
  sim:
    device: wlan0
    description: "Zero-rated SIM"
  broadband:
    device: eth0

rules:
  - comment: "YouTube"
    via: sim
    ttl: 600
    domains:
      - youtube.com
      - "*.googlevideo.com"
      - "*.ytimg.com"
      - youtu.be

  - comment: "Netflix"
    via: sim
    ttl: 600
    domains:
      - netflix.com
      - "*.nflxext.com"
      - "*.nflxvideo.net"
```

### WireGuard for sensitive domains only

```yaml
default: direct
interfaces:
  tunnel:
    device: wg0         # no gateway needed — WireGuard is point-to-point
    metric: 10
  direct:
    device: eth0

rules:
  - via: tunnel
    domains:
      - "*.mybank.com"
      - paypal.com
      - "*.google.com"
      - gmail.com
```

### Three interfaces, tiered by cost

```yaml
default: broadband
interfaces:
  broadband:
    device: eth0
    metric: 100
  fast_sim:
    device: wlan0
    metric: 50
    description: "5G SIM — streaming"
  metered:
    device: wwan0
    metric: 200
    description: "Backup SIM — use sparingly"

rules:
  - via: fast_sim
    domains:
      - youtube.com
      - "*.googlevideo.com"
      - netflix.com
      - "*.nflxext.com"

  - comment: "Keep large downloads off the SIM"
    via: broadband
    domains:
      - "*.releases.ubuntu.com"
      - "*.debian.org"
      - "*.kernel.org"
```

---

## Running as a systemd service

```bash
sudo mkdir -p /opt/routectl /etc/routectl
sudo cp -r routectl/ /opt/routectl/
sudo cp routes.yaml /etc/routectl/
sudo cp routectl.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now routectl
journalctl -u routectl -f
```

On stop or reboot, the service flushes all managed routes and restores DNS automatically.

---

## Troubleshooting

**Gateway not detected**
Add it explicitly: `gateway: 10.20.30.1`. Run `ip route show dev <device>` to find it.

**Traffic still going through wrong interface**
Check with `ip route get <ip>`. If wrong, look for conflicting policy rules with `ip rule show`.

**Routes disappear after reboot**
The kernel routing table is in-memory. Use the systemd service for persistence.

**Glob/regex not matching**
Make sure you're running `daemon`, not `apply-all`. Use `test` to verify the pattern:
```bash
python3 -m routectl test rr3.sn-abc.googlevideo.com
```

**DNS not restored after crash**
Run manually:
```bash
# systemd-resolved:
sudo systemctl restart systemd-resolved

# resolv.conf — restore your original nameserver:
sudo nano /etc/resolv.conf
```

---

## License

MIT
