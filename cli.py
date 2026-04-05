"""
cli.py — Command-line interface and main entry point.

Commands:
  daemon      Run forever: pre-routes literals, starts DNS proxy if needed,
              refreshes routes periodically. This is the primary run command.
  apply-all   One-shot: resolve and route all literal domains from the config.
  apply       Resolve and route specific domains given on the command line.
  flush       Remove all managed routes.
  status      Show interfaces, rules, and active routes.
  test        Show which interface a domain would use (no changes, no root).
  info        Show detected gateways and interface state (no root).
"""
from __future__ import annotations

import atexit
import logging
import os
import signal
import sys
import time

from . import config as _config
from . import dns as _dns
from . import iface as _iface
from .display import print_info, print_status, print_test
from .routing import (
    apply_domains, flush_all,
    load_state, purge_expired, save_state,
)

log = logging.getLogger("routectl")


# ══════════════════════════════════════════════════════════════════════════════
# Commands
# ══════════════════════════════════════════════════════════════════════════════

def cmd_daemon(cfg: _config.Config, args) -> None:
    """
    Primary run mode.

    1. Pre-routes all literal (exact) domains immediately.
    2. If glob/regex rules exist → starts DNS proxy automatically in background.
    3. Loops every daemon_interval seconds to purge stale routes and re-resolve
       literal domains (handles IP rotation for exact matches).
    """
    _iface.detect_all_gateways(cfg)
    state = load_state()

    # ── step 1: pre-route literals ────────────────────────────────────────────
    if cfg.literal_domains:
        log.info("Pre-routing %d literal domain(s)…", len(cfg.literal_domains))
        purge_expired(state, cfg, args.dry_run)
        a, r, f = apply_domains(cfg.literal_domains, cfg, args.dry_run, state)
        save_state(state)
        log.info("Pre-route — added=%d  refreshed=%d  failed=%d", a, r, f)

    # ── step 2: start DNS proxy if glob/regex rules present ───────────────────
    proxy: _dns.ProxyContext | None = None
    if cfg.has_proxy_rules:
        proxy_rules = sum(1 for r in cfg.rules if r.needs_proxy)
        log.info(
            "%d glob/regex rule(s) detected — starting DNS proxy automatically",
            proxy_rules,
        )
        proxy = _dns.ProxyContext(cfg, state, args.dry_run)
        proxy.start()
    else:
        log.info("No glob/regex rules — DNS proxy not needed.")

    # ── cleanup on exit ───────────────────────────────────────────────────────
    def _shutdown(signum=None, frame=None):
        log.info("Shutting down…")
        if proxy:
            proxy.stop()
        save_state(state)
        sys.exit(0)

    atexit.register(_shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── step 3: refresh loop ──────────────────────────────────────────────────
    log.info("Daemon running — refresh interval=%ds  (Ctrl+C to stop)",
             cfg.daemon_interval)
    cycle = 0
    try:
        while True:
            time.sleep(cfg.daemon_interval)
            cycle += 1
            log.debug("── refresh cycle %d ──", cycle)
            purge_expired(state, cfg, args.dry_run)
            if cfg.literal_domains:
                a, r, f = apply_domains(cfg.literal_domains, cfg, args.dry_run, state)
                if a or f:
                    log.info("Refresh — added=%d  refreshed=%d  failed=%d", a, r, f)
            save_state(state)
    except KeyboardInterrupt:
        pass
    finally:
        _shutdown()


def cmd_apply_all(cfg: _config.Config, args) -> None:
    """One-shot: resolve all literal domains from the config."""
    _iface.detect_all_gateways(cfg)
    state = load_state()

    if not cfg.literal_domains:
        log.warning("No literal domains in config. "
                    "Glob/regex rules need 'daemon' (DNS proxy) to work.")
        return

    skipped = sum(1 for r in cfg.rules if r.needs_proxy)
    log.info("Applying %d literal domain(s) from config…", len(cfg.literal_domains))
    if skipped:
        log.info("  (%d glob/regex rule(s) skipped — use 'daemon' for those)", skipped)

    purge_expired(state, cfg, args.dry_run)
    a, r, f = apply_domains(cfg.literal_domains, cfg, args.dry_run, state)
    save_state(state)
    log.info("Done — added=%d  refreshed=%d  failed=%d", a, r, f)


def cmd_apply(cfg: _config.Config, args) -> None:
    """Resolve and route specific domains given on the command line."""
    _iface.detect_all_gateways(cfg)
    state = load_state()
    purge_expired(state, cfg, args.dry_run)
    a, r, f = apply_domains(args.domains, cfg, args.dry_run, state)
    save_state(state)
    log.info("Done — added=%d  refreshed=%d  failed=%d", a, r, f)


def cmd_flush(cfg: _config.Config, args) -> None:
    state = load_state()
    flush_all(cfg, state, args.dry_run)
    save_state(state)


# ══════════════════════════════════════════════════════════════════════════════
# Parser
# ══════════════════════════════════════════════════════════════════════════════

EPILOG = """\
Examples:
  # Full run — pre-routes literals, auto-starts DNS proxy for glob/regex
  sudo python3 -m routectl daemon

  # One-shot: route all literal domains from the config, then exit
  sudo python3 -m routectl apply-all

  # Route specific domains manually
  sudo python3 -m routectl apply youtube.com github.com

  # Inspect what is active
  python3 -m routectl status

  # Test a domain against your rules (no root, no changes)
  python3 -m routectl test rr3.sn-abc.googlevideo.com

  # Remove every managed route
  sudo python3 -m routectl flush
"""


def build_parser():
    import argparse
    p = argparse.ArgumentParser(
        prog="routectl",
        description="Route traffic per domain through specific network interfaces.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    p.add_argument("-c", "--config", default="routes.yaml",
                   help="Config file path (default: routes.yaml)")
    p.add_argument("-n", "--dry-run", action="store_true",
                   help="Print commands without executing")
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    sub.add_parser("daemon",
                   help="Run forever: pre-route literals, auto DNS proxy for glob/regex")

    sub.add_parser("apply-all",
                   help="One-shot: resolve all literal domains from config")

    pa = sub.add_parser("apply", help="Resolve and route specific domains")
    pa.add_argument("domains", nargs="+")

    sub.add_parser("flush",  help="Remove all managed routes")
    sub.add_parser("status", help="Show interfaces, rules and active routes")

    pt = sub.add_parser("test", help="Show which interface a domain would use (no changes)")
    pt.add_argument("domain")

    sub.add_parser("info", help="Show detected gateways and interface state")

    return p


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    logging.basicConfig(
        level   = logging.DEBUG if args.verbose else logging.INFO,
        format  = "%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt = "%H:%M:%S",
    )

    if args.cmd is None:
        parser.print_help()
        sys.exit(0)

    cfg = _config.load(args.config)

    # ── no-root commands ──────────────────────────────────────────────────────
    if args.cmd == "test":
        print_test(args.domain, cfg)
        return

    if args.cmd == "info":
        print_info(cfg)
        return

    if args.cmd == "status":
        print_status(cfg, load_state())
        return

    # ── root required ─────────────────────────────────────────────────────────
    if os.geteuid() != 0 and not args.dry_run:
        log.error("'%s' requires root. Use sudo or --dry-run.", args.cmd)
        sys.exit(1)

    if args.cmd == "daemon":
        cmd_daemon(cfg, args)
    elif args.cmd == "apply-all":
        cmd_apply_all(cfg, args)
    elif args.cmd == "apply":
        cmd_apply(cfg, args)
    elif args.cmd == "flush":
        cmd_flush(cfg, args)
