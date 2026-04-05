"""
iface.py — Network interface detection utilities.
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from .config import Config, Interface

log = logging.getLogger("routectl.iface")


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    log.debug("$ %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def detect_gateway(device: str) -> Optional[str]:
    """Find the next-hop gateway for a device by inspecting the routing table."""
    r = _run(["ip", "route", "show", "dev", device])
    for line in r.stdout.splitlines():
        m = re.search(r'\bvia\s+([\d.]+)', line)
        if m:
            return m.group(1)
    r2 = _run(["ip", "route", "show", "default"])
    for line in r2.stdout.splitlines():
        if f"dev {device}" in line:
            m = re.search(r'\bvia\s+([\d.]+)', line)
            if m:
                return m.group(1)
    return None


def detect_all_gateways(cfg: Config) -> None:
    """Populate _resolved_gateway for every interface in the config."""
    for name, iface in cfg.interfaces.items():
        if iface.gateway:
            iface._resolved_gateway = iface.gateway
        else:
            gw = detect_gateway(iface.device)
            if gw:
                iface._resolved_gateway = gw
                log.debug("Auto-detected gateway for %s (%s): %s", name, iface.device, gw)
            else:
                log.warning(
                    "Could not detect gateway for %s (%s) — routes may fail",
                    name, iface.device,
                )


def device_exists(device: str) -> bool:
    return Path(f"/sys/class/net/{device}").exists()


def device_is_up(device: str) -> bool:
    r = _run(["ip", "link", "show", device])
    return "state UP" in r.stdout or ",UP," in r.stdout


def get_addrs(device: str) -> list[str]:
    r = _run(["ip", "-4", "addr", "show", "dev", device])
    return re.findall(r'inet ([\d.]+)/', r.stdout)
