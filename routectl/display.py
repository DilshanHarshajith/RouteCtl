"""
display.py — Terminal output helpers.
"""
from __future__ import annotations

import shutil
import sys
import time

from .config import Config
from .iface import device_exists, device_is_up, get_addrs


def c(color: str, text) -> str:
    codes = {
        "bold":  "\033[1m",
        "green": "\033[32m",
        "yellow":"\033[33m",
        "red":   "\033[31m",
        "cyan":  "\033[36m",
        "gray":  "\033[90m",
    }
    if not sys.stdout.isatty():
        return str(text)
    return f"{codes.get(color, '')}{text}\033[0m"


def print_status(cfg: Config, state: dict) -> None:
    W   = shutil.get_terminal_size((100, 40)).columns
    now = time.time()

    # ── Interfaces ──────────────────────────────────────────────────────────
    print(c("bold", "\n  Interfaces"))
    print("  " + "─" * (W - 4))
    for name, iface in cfg.interfaces.items():
        exists  = device_exists(iface.device)
        up      = device_is_up(iface.device) if exists else False
        dot     = c("green", "●") if up else c("red", "●")
        default = c("yellow", " [default]") if name == cfg.default_interface else ""
        gw      = iface.gw or c("red", "no gateway")
        addrs   = get_addrs(iface.device) if exists else []
        addr_s  = ", ".join(addrs) if addrs else c("gray", "no IP")
        routes  = sum(1 for e in state.values() if e["interface"] == name)
        print(f"  {dot}  {c('bold', name):<20s}  dev {c('cyan', iface.device):<10s}"
              f"  gw {gw:<16s}  addr {addr_s:<18s}  routes={c('yellow', str(routes))}{default}")
        if iface.description:
            print(f"       {c('gray', iface.description)}")

    # ── Rules ───────────────────────────────────────────────────────────────
    print(c("bold", "\n  Rules  (top → bottom, first match wins)"))
    print("  " + "─" * (W - 4))
    kind_color = {"regex": "yellow", "glob": "cyan", "exact": "gray"}
    for i, rule in enumerate(cfg.rules, 1):
        kc   = kind_color[rule.kind]
        note = f"  {c('gray', '# ' + rule.comment)}" if rule.comment else ""
        print(f"  {c('gray', str(i)):>4}  {c(kc, '['+rule.kind+']'):<18s}"
              f"  {rule.pattern:<40s}  → {c('cyan', rule.interface_name)}{note}")

    if cfg.has_proxy_rules:
        print(f"\n  {c('yellow', '⚡')} Config contains glob/regex rules — "
              f"DNS proxy starts automatically when running {c('bold', 'daemon')}.")

    # ── Active routes ────────────────────────────────────────────────────────
    print(c("bold", f"\n  Active Routes  ({len(state)} total)"))
    print("  " + "─" * (W - 4))
    if not state:
        print(f"  {c('gray', '(none)')}")
    else:
        grouped: dict[str, list] = {}
        for ip, e in sorted(state.items()):
            grouped.setdefault(e["interface"], []).append((ip, e))
        for iface_name, entries in grouped.items():
            iface = cfg.interfaces.get(iface_name)
            dev   = iface.device if iface else "?"
            print(f"\n    {c('bold', iface_name)}  ({dev})")
            for ip, e in sorted(entries, key=lambda x: x[1].get("domain", "")):
                ttl_left = max(0, int(e.get("expires", 0) - now))
                stale    = ttl_left == 0
                print(f"      {c('red', ip) if stale else ip:<18s}  "
                      f"{e.get('domain', '?'):<38s}  "
                      f"{c('red', 'STALE') if stale else c('gray', f'ttl {ttl_left}s')}")
    print()


def print_test(domain: str, cfg: Config) -> None:
    from .routing import match_interface, match_rule
    iface = match_interface(domain, cfg)
    rule  = match_rule(domain, cfg)
    if iface:
        kind = f"[{rule.kind}] '{rule.pattern}'" if rule else "[default]"
        print(f"  {c('bold', domain)}")
        print(f"    matched by  {c('yellow', kind)}")
        print(f"    route via   {c('green', iface.name)}  "
              f"(dev {c('cyan', iface.device)}, gw {iface.gateway or 'auto'})")
    else:
        print(f"  {c('bold', domain)}  →  {c('red', 'no match and no default')}")


def print_info(cfg: Config) -> None:
    from .iface import detect_all_gateways
    detect_all_gateways(cfg)
    print(c("bold", "\n  Interface Info"))
    print("  " + "─" * 60)
    for name, iface in cfg.interfaces.items():
        exists = device_exists(iface.device)
        up     = device_is_up(iface.device) if exists else False
        addrs  = get_addrs(iface.device) if exists else []
        gw     = iface.gw or c("red", "NOT FOUND")
        status = c("green", "up") if up else (c("red", "down") if exists else c("red", "missing"))
        print(f"  {c('bold', name):<20s}  dev={iface.device:<10s}  "
              f"status={status:<8s}  gw={gw:<16s}  addr={', '.join(addrs) or '—'}")
    print()
