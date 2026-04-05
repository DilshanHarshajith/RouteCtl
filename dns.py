"""
dns.py — DNS interception proxy.

Intercepts every DNS response on the machine and installs /32 routes
for hostnames that match glob or regex rules — automatically, with zero
latency added to DNS queries.

Activated automatically when the config contains any glob/regex rules.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from .config import Config
from .routing import add_route, match_interface, match_rule, save_state

log = logging.getLogger("routectl.dns")


# ══════════════════════════════════════════════════════════════════════════════
# DNS packet parsing (pure stdlib, no dependencies)
# ══════════════════════════════════════════════════════════════════════════════

def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name from wire format, following compression pointers."""
    labels: list[str] = []
    visited: set[int] = set()
    jumped  = False
    end_off = offset

    while True:
        if offset >= len(data) or offset in visited:
            break
        visited.add(offset)
        length = data[offset]

        if length == 0:
            if not jumped:
                end_off = offset + 1
            break
        elif (length & 0xC0) == 0xC0:          # compression pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_off = offset + 2
            jumped = True
            offset = ptr
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length

    return ".".join(labels), end_off


def parse_response(data: bytes) -> tuple[Optional[str], list[str]]:
    """
    Parse a raw DNS response.
    Returns (queried_hostname, [resolved_ip, ...]).
    Handles A (IPv4) and AAAA (IPv6) records.
    Returns (None, []) on any parse error.
    """
    if len(data) < 12:
        return None, []
    try:
        _id, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return None, []
    if not (flags & 0x8000):        # QR bit — must be a response
        return None, []

    offset = 12
    qname: Optional[str] = None

    for _ in range(qdcount):
        name, offset = _parse_name(data, offset)
        if qname is None:
            qname = name
        offset += 4                 # qtype + qclass

    ips: list[str] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata   = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:       # A
            ips.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and rdlen == 16:   # AAAA
            ips.append(str(ipaddress.IPv6Address(rdata)))

    return qname, ips


# ══════════════════════════════════════════════════════════════════════════════
# Proxy server
# ══════════════════════════════════════════════════════════════════════════════

class _Handler(socketserver.BaseRequestHandler):
    server: "_Server"

    def handle(self):
        data: bytes       = self.request[0]
        sock: socket.socket = self.request[1]

        # forward to upstream immediately
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(5)
            up.sendto(data, (self.server.cfg.dns_upstream,
                             self.server.cfg.dns_upstream_port))
            response, _ = up.recvfrom(4096)
            up.close()
        except OSError as exc:
            log.debug("Upstream DNS error: %s", exc)
            return

        # reply to client — no latency penalty
        sock.sendto(response, self.client_address)

        # route installation in background thread
        threading.Thread(
            target=self._maybe_install_route,
            args=(response,),
            daemon=True,
        ).start()

    def _maybe_install_route(self, response: bytes):
        hostname, ips = parse_response(response)
        if not hostname or not ips:
            return

        cfg   = self.server.cfg
        state = self.server.state
        lock  = self.server.lock

        iface = match_interface(hostname, cfg)
        if iface is None:
            return

        rule = match_rule(hostname, cfg)
        ttl  = rule.ttl if rule else 300
        now  = time.time()

        with lock:
            new_ips: list[str] = []
            for ip in ips:
                prev = state.get(ip)
                if prev and prev["interface"] == iface.name and prev.get("expires", 0) > now:
                    state[ip]["expires"] = now + ttl
                    continue
                if add_route(ip, iface, self.server.dry_run):
                    new_ips.append(ip)
                    state[ip] = {
                        "interface": iface.name,
                        "device":    iface.device,
                        "domain":    hostname,
                        "expires":   now + ttl,
                        "added":     now,
                    }
            if new_ips:
                save_state(state)
                for ip in new_ips:
                    log.info("  DNS-ROUTE  %-30s %-16s → %s (%s)",
                             hostname, ip, iface.name, iface.device)


class _Server(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, cfg: Config, state: dict, dry_run: bool):
        self.cfg     = cfg
        self.state   = state
        self.lock    = threading.Lock()
        self.dry_run = dry_run
        super().__init__((cfg.dns_listen, cfg.dns_port), _Handler)


# ══════════════════════════════════════════════════════════════════════════════
# Resolver backend detection & management
# ══════════════════════════════════════════════════════════════════════════════

def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def detect_backend() -> str:
    """Returns 'systemd-resolved' or 'resolv.conf'."""
    r = _run(["systemctl", "is-active", "systemd-resolved"])
    if r.returncode == 0 and r.stdout.strip() == "active" and shutil.which("resolvectl"):
        return "systemd-resolved"
    return "resolv.conf"


def get_upstream(backend: str) -> Optional[str]:
    """Read the real upstream DNS, skipping loopback stubs."""
    if backend == "systemd-resolved":
        for path in ("/run/systemd/resolve/resolv.conf",
                     "/run/systemd/resolve/stub-resolv.conf"):
            try:
                for line in Path(path).read_text().splitlines():
                    if line.startswith("nameserver"):
                        ip = line.split()[1]
                        if not ip.startswith("127."):
                            return ip
            except OSError:
                continue
        r = _run(["resolvectl", "status", "--no-pager"])
        for line in r.stdout.splitlines():
            m = re.search(r'DNS Servers?:\s*([\d.]+)', line)
            if m and not m.group(1).startswith("127."):
                return m.group(1)
    else:
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                if line.startswith("nameserver"):
                    ip = line.split()[1]
                    if not ip.startswith("127.") and ip != "::1":
                        return ip
        except OSError:
            pass
    return None


def snapshot(backend: str) -> dict:
    """Capture current DNS state for later restoration."""
    snap: dict = {"backend": backend}
    if backend == "systemd-resolved":
        r = _run(["resolvectl", "status", "--no-pager"])
        snap["resolvectl_status"] = r.stdout
        iface_dns: dict[str, list[str]] = {}
        current = None
        for line in r.stdout.splitlines():
            m = re.match(r'^Link \d+ \((\S+)\)', line.strip())
            if m:
                current = m.group(1)
            elif current:
                dm = re.search(r'Current DNS Server:\s*([\d.a-fA-F:]+)', line)
                if dm:
                    iface_dns.setdefault(current, []).append(dm.group(1))
        snap["iface_dns"] = iface_dns
        r2 = _run(["ip", "-o", "link", "show"])
        snap["interfaces"] = [i for i in re.findall(r'^\d+:\s+(\S+):', r2.stdout, re.M)
                              if i != "lo"]
    else:
        try:
            snap["resolv_conf"] = Path("/etc/resolv.conf").read_text()
        except OSError:
            snap["resolv_conf"] = ""
    return snap


def redirect(backend: str, listen_ip: str, dry_run: bool) -> None:
    """Point the system resolver at the proxy."""
    if backend == "systemd-resolved":
        r = _run(["ip", "-o", "link", "show"])
        for dev in re.findall(r'^\d+:\s+(\S+):', r.stdout, re.M):
            if dev == "lo":
                continue
            cmd = ["resolvectl", "dns", dev, listen_ip]
            if dry_run:
                log.info("[dry-run] %s", " ".join(cmd))
            else:
                _run(cmd)
    else:
        content = f"# routectl — temporary, restored on exit\nnameserver {listen_ip}\n"
        if dry_run:
            log.info("[dry-run] write /etc/resolv.conf: nameserver %s", listen_ip)
        else:
            Path("/etc/resolv.conf").write_text(content)


def restore(backend: str, snap: dict, dry_run: bool) -> None:
    """Restore DNS configuration from a snapshot."""
    if backend == "systemd-resolved":
        iface_dns: dict = snap.get("iface_dns", {})
        all_ifaces: list = snap.get("interfaces", [])
        targets = iface_dns.keys() or all_ifaces
        for dev in targets:
            servers = iface_dns.get(dev, [])
            cmd = (["resolvectl", "dns", dev] + servers) if servers \
                  else ["resolvectl", "revert", dev]
            if dry_run:
                log.info("[dry-run] %s", " ".join(cmd))
            else:
                _run(cmd)
        if not dry_run:
            _run(["systemctl", "restart", "systemd-resolved"])
    else:
        original = snap.get("resolv_conf", "")
        if dry_run:
            log.info("[dry-run] restore /etc/resolv.conf")
        else:
            try:
                Path("/etc/resolv.conf").write_text(original)
            except OSError as e:
                log.error("Could not restore /etc/resolv.conf: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# Public API — start / stop
# ══════════════════════════════════════════════════════════════════════════════

class ProxyContext:
    """
    Manages the full lifecycle of the DNS proxy:
      start()  — detects upstream, redirects system DNS, starts server
      stop()   — restores DNS, closes server
    Can also be used as a context manager.
    """

    def __init__(self, cfg: Config, state: dict, dry_run: bool):
        self.cfg     = cfg
        self.state   = state
        self.dry_run = dry_run
        self._backend:  Optional[str]  = None
        self._snap:     Optional[dict] = None
        self._server:   Optional[_Server] = None
        self._thread:   Optional[threading.Thread] = None
        self._stopped   = threading.Event()

    def start(self) -> None:
        # detect & configure upstream
        self._backend = detect_backend()
        log.info("DNS backend: %s", self._backend)

        upstream = get_upstream(self._backend)
        if upstream:
            log.info("Upstream DNS: %s", upstream)
            self.cfg.dns_upstream = upstream
        else:
            log.warning("Could not detect upstream DNS — using %s", self.cfg.dns_upstream)

        self._snap = snapshot(self._backend)

        # start server on loopback
        self.cfg.dns_listen = "127.0.0.53"
        self.cfg.dns_port   = 53

        self._server = _Server(self.cfg, self.state, self.dry_run)

        # redirect system DNS to proxy
        redirect(self._backend, self.cfg.dns_listen, self.dry_run)
        log.info("System DNS → %s:%d (upstream: %s)",
                 self.cfg.dns_listen, self.cfg.dns_port, self.cfg.dns_upstream)

        # run server in background thread
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="dns-proxy",
        )
        self._thread.start()
        log.info("DNS proxy active — glob/regex rules will match as queries arrive")

    def stop(self) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._backend and self._snap:
            log.info("Restoring system DNS…")
            restore(self._backend, self._snap, self.dry_run)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()
