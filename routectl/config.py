"""
config.py — Config dataclasses and YAML/JSON loader.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

log = logging.getLogger("routectl.config")

# ── optional YAML ──────────────────────────────────────────────────────────────
try:
    import yaml as _yaml
    def _parse_yaml(text: str) -> dict:
        return _yaml.safe_load(text)
except ImportError:
    _yaml = None
    def _parse_yaml(text: str) -> dict:
        raise SystemExit("pyyaml not installed — run: pip install pyyaml")


# ══════════════════════════════════════════════════════════════════════════════
# Dataclasses
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Interface:
    name: str
    device: str
    gateway: Optional[str]          # None = auto-detect at runtime
    table_id: int
    metric: int = 100
    description: str = ""
    _resolved_gateway: Optional[str] = field(default=None, repr=False)

    @property
    def gw(self) -> Optional[str]:
        return self._resolved_gateway or self.gateway


@dataclass
class Rule:
    pattern: str
    interface_name: str
    comment: str = ""
    ttl: int = 300
    _regex: Optional[re.Pattern] = field(default=None, repr=False)
    _is_glob: bool = field(default=False, repr=False)

    def __post_init__(self):
        m = re.fullmatch(r'/(.+)/([imsx]*)', self.pattern)
        if m:
            flags = sum(getattr(re, f.upper(), 0) for f in m.group(2))
            self._regex = re.compile(m.group(1), flags)
        elif any(c in self.pattern for c in ('*', '?', '[')):
            self._is_glob = True

    def matches(self, hostname: str) -> bool:
        h = hostname.lower().rstrip('.')
        p = self.pattern.lower()
        if self._regex:
            return bool(self._regex.search(h))
        if self._is_glob:
            return fnmatch(h, p)
        return h == p or h.endswith('.' + p)

    @property
    def kind(self) -> str:
        if self._regex:   return "regex"
        if self._is_glob: return "glob"
        return "exact"

    @property
    def needs_proxy(self) -> bool:
        """True if this rule cannot be resolved proactively — requires DNS interception."""
        return bool(self._regex or self._is_glob)


@dataclass
class Config:
    interfaces: dict[str, Interface]
    rules: list[Rule]
    default_interface: Optional[str] = None
    resolve_retries: int = 3
    resolve_timeout: float = 4.0
    daemon_interval: int = 60
    ipv6: bool = False
    dns_listen: str = "127.0.0.53"
    dns_port: int = 53
    dns_upstream: str = "8.8.8.8"
    dns_upstream_port: int = 53
    _table_base: int = 200

    @property
    def has_proxy_rules(self) -> bool:
        """True if any rule requires DNS interception (glob or regex)."""
        return any(r.needs_proxy for r in self.rules)

    @property
    def literal_domains(self) -> list[str]:
        """All exact/literal patterns — safe to pre-resolve."""
        seen: set[str] = set()
        out: list[str] = []
        for r in self.rules:
            if not r.needs_proxy and r.pattern not in seen:
                seen.add(r.pattern)
                out.append(r.pattern)
        return out


# ══════════════════════════════════════════════════════════════════════════════
# Loader
# ══════════════════════════════════════════════════════════════════════════════

def load(path: str) -> Config:
    text = Path(path).read_text()
    ext  = Path(path).suffix.lower()
    raw: dict = _parse_yaml(text) if (ext in ('.yaml', '.yml') or _yaml) else json.loads(text)

    # Sanity-check the top-level structure
    if not isinstance(raw, dict):
        raise SystemExit(
            f"\nConfig error: {path} did not parse as a YAML mapping.\n"
            f"  Got: {type(raw).__name__} — check for syntax errors at the top of the file.\n"
        )

    ifaces_raw = raw.get("interfaces", {})
    if not isinstance(ifaces_raw, dict):
        raise SystemExit(
            f"\nConfig error: 'interfaces' block is not a mapping.\n"
            f"  Got: {type(ifaces_raw).__name__}\n"
            f"  Parsed value: {ifaces_raw!r}\n\n"
            f"  The interfaces block must be a dict, e.g.:\n\n"
            f"    interfaces:\n"
            f"      eth0_iface:\n"
            f"        device: eth0\n"
        )

    table_base = int(raw.get("table_base", 200))

    interfaces: dict[str, Interface] = {}
    for i, (name, spec) in enumerate(ifaces_raw.items()):
        # Defend against malformed YAML — interface block parsed as a list
        # instead of a dict (usually caused by accidental `- key: val` syntax).
        if not isinstance(spec, dict):
            raise SystemExit(
                f"\nConfig error in interface '{name}':\n"
                f"  Expected a mapping (key: value pairs) but got: {type(spec).__name__}\n"
                f"  Parsed value: {spec!r}\n\n"
                f"  Check your routes.yaml — interface blocks must look like:\n\n"
                f"    {name}:\n"
                f"      device: eth0\n"
                f"      gateway: 192.168.1.1   # optional\n\n"
                f"  Common mistake — accidental list syntax (do NOT use dashes):\n"
                f"    {name}:\n"
                f"      - device: eth0         # wrong\n"
            )
        if "device" not in spec:
            raise SystemExit(
                f"\nConfig error in interface '{name}': missing required field 'device'.\n"
                f"  Add the kernel device name, e.g.:\n\n"
                f"    {name}:\n"
                f"      device: eth0\n"
            )
        interfaces[name] = Interface(
            name        = name,
            device      = spec["device"],
            gateway     = spec.get("gateway"),
            table_id    = spec.get("table_id", table_base + i),
            metric      = int(spec.get("metric", 100 + i * 10)),
            description = spec.get("description", ""),
        )

    rules: list[Rule] = []
    for r in raw.get("rules", []):
        iface_name = r["via"]
        if iface_name not in interfaces:
            log.warning("Rule references unknown interface %r — skipped", iface_name)
            continue
        domains = r.get("domains", [])
        if isinstance(domains, str):
            domains = [domains]
        for pat in domains:
            rules.append(Rule(
                pattern        = pat,
                interface_name = iface_name,
                comment        = r.get("comment", ""),
                ttl            = int(r.get("ttl", raw.get("default_ttl", 300))),
            ))

    return Config(
        interfaces        = interfaces,
        rules             = rules,
        default_interface = raw.get("default"),
        resolve_retries   = int(raw.get("resolve_retries", 3)),
        resolve_timeout   = float(raw.get("resolve_timeout", 4.0)),
        daemon_interval   = int(raw.get("daemon_interval", 60)),
        ipv6              = bool(raw.get("ipv6", False)),
        dns_listen        = raw.get("dns_listen", "127.0.0.53"),
        dns_port          = int(raw.get("dns_port", 53)),
        dns_upstream      = raw.get("dns_upstream", "8.8.8.8"),
        dns_upstream_port = int(raw.get("dns_upstream_port", 53)),
        _table_base       = table_base,
    )