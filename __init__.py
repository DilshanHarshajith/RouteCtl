"""
routectl — Policy-based multi-interface traffic routing by domain.

Usage:
    sudo python3 -m routectl daemon        # full run mode
    sudo python3 -m routectl apply-all     # one-shot
    python3 -m routectl status             # inspect
    python3 -m routectl test <domain>      # debug rules
"""
from .config import Config, Interface, Rule, load   # noqa: F401
