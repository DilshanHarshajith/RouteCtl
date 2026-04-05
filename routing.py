"""
routing.py — Host route management, DNS resolution, and state tracking.
"""
from __future__ import annotations

import json
import logging
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

from .config import Config, Interface, Rule

log = logging.getLogger("routectl.routing")

try:
    import dns.resolver as _dns_resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False

STATE_PATH = Path("/tmp/routectl_state.json")


# ── helpers ────────────────────────────────────────────────────────────────────

def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    log.debug("$ %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


# ── DNS resolution ─────────────────────────────────────────────────────────────

def resolve(hostname: str, cfg: Config) -> list[str]:
    af = socket.AF_INET6 if cfg.ipv6 else socket.AF_INET
    if _HAS_DNSPYTHON:
        try:
            rtype   = "AAAA" if cfg.ipv6 else "A"
            answers = _dns_resolver.resolve(hostname, rtype, lifetime=cfg.resolve_timeout)
            return [str(a) for a in answers]
        except Exception:
            pass
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(cfg.resolve_timeout)
    try:
        for attempt in range(cfg.resolve_retries):
            try:
                infos = socket.getaddrinfo(hostname, None, af)
                return list(dict.fromkeys(i[4][0] for i in infos))
            except socket.gaierror:
                if attempt < cfg.resolve_retries - 1:
                    time.sleep(0.3 * (attempt + 1))
        return []
    finally:
        socket.setdefaulttimeout(old)


# ── state file ─────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            pass
    return {}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2))


def purge_expired(state: dict, cfg: Config, dry_run: bool) -> None:
    now = time.time()
    for ip in [k for k, v in state.items() if v.get("expires", 0) < now]:
        log.info("TTL expired → removing %s (was → %s)", ip, state[ip].get("interface"))
        del_route(ip, dry_run)
        del state[ip]


# ── route add / del ────────────────────────────────────────────────────────────

def add_route(ip: str, iface: Interface, dry_run: bool) -> bool:
    if not iface.gw:
        log.warning("No gateway for %s — cannot route %s", iface.name, ip)
        return False
    host = f"{ip}/32"
    cmd  = ["ip", "route", "replace", host,
            "via", iface.gw, "dev", iface.device,
            "metric", str(iface.metric)]
    if dry_run:
        log.info("[dry-run] %s", " ".join(cmd))
        return True
    r = _run(cmd)
    if r.returncode != 0:
        log.warning("route add %s via %s: %s", host, iface.name, r.stderr.strip())
        return False
    return True


def del_route(ip: str, dry_run: bool) -> bool:
    host = f"{ip}/32"
    cmd  = ["ip", "route", "del", host]
    if dry_run:
        log.info("[dry-run] %s", " ".join(cmd))
        return True
    r = _run(cmd)
    return r.returncode == 0


# ── matching ───────────────────────────────────────────────────────────────────

def match_interface(hostname: str, cfg: Config) -> Optional[Interface]:
    for rule in cfg.rules:
        if rule.matches(hostname):
            return cfg.interfaces[rule.interface_name]
    if cfg.default_interface:
        return cfg.interfaces.get(cfg.default_interface)
    return None


def match_rule(hostname: str, cfg: Config) -> Optional[Rule]:
    for rule in cfg.rules:
        if rule.matches(hostname):
            return rule
    return None


# ── bulk apply ─────────────────────────────────────────────────────────────────

def apply_domains(
    domains: list[str],
    cfg: Config,
    dry_run: bool,
    state: dict,
) -> tuple[int, int, int]:
    """
    Resolve each domain, add /32 routes for matched IPs.
    Returns (added, refreshed, failed).
    """
    now = time.time()
    added = refreshed = failed = 0

    for hostname in domains:
        iface = match_interface(hostname, cfg)
        if iface is None:
            log.debug("No interface for %s — skipped", hostname)
            continue

        rule = match_rule(hostname, cfg)
        ttl  = rule.ttl if rule else 300

        ips = resolve(hostname, cfg)
        if not ips:
            log.warning("DNS: no result for %s", hostname)
            failed += 1
            continue

        for ip in ips:
            prev = state.get(ip)
            if prev and prev["interface"] == iface.name and prev.get("expires", 0) > now:
                state[ip]["expires"] = now + ttl
                refreshed += 1
                continue
            if prev and prev["interface"] != iface.name:
                del_route(ip, dry_run)
            ok = add_route(ip, iface, dry_run)
            if ok:
                log.info("  ROUTE  %-28s %-16s → %s (%s)",
                         hostname, ip, iface.name, iface.device)
                state[ip] = {
                    "interface": iface.name,
                    "device":    iface.device,
                    "domain":    hostname,
                    "expires":   now + ttl,
                    "added":     now,
                }
                added += 1
            else:
                failed += 1

    return added, refreshed, failed


def flush_all(cfg: Config, state: dict, dry_run: bool) -> None:
    log.info("Flushing %d managed routes…", len(state))
    for ip in list(state):
        ok = del_route(ip, dry_run)
        if ok:
            log.info("  REMOVE  %-16s (%s)", ip, state[ip].get("domain", "?"))
        del state[ip]
