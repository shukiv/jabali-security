"""IP reputation database -- in-memory CIDR blocklist lookups."""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class IPReputationDB:
    """In-memory IP reputation database loaded from blocklist files."""

    def __init__(self) -> None:
        # feed_name -> set of ip_network objects
        self._feeds: dict[str, set[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}

    def load_feed(self, name: str, path: Path) -> int:
        """Load a blocklist file (one IP or CIDR per line). Returns entry count."""
        if not path.is_file():
            logger.warning("Feed file not found: %s", path)
            return 0

        networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Handle "IP ; comment" format (Spamhaus DROP)
            if ";" in line:
                line = line.split(";")[0].strip()
            # Handle "IP/CIDR" or plain "IP"
            try:
                net = ipaddress.ip_network(line, strict=False)
                networks.add(net)
            except ValueError:
                continue

        self._feeds[name] = networks
        logger.info("Loaded feed %s: %d entries from %s", name, len(networks), path)
        return len(networks)

    def check(self, ip: str) -> list[str]:
        """Check if an IP is in any loaded feed. Returns list of matching feed names."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []

        matches: list[str] = []
        for name, networks in self._feeds.items():
            for net in networks:
                if addr in net:
                    matches.append(name)
                    break
        return matches

    def is_malicious(self, ip: str) -> bool:
        """Quick check: is this IP in any feed?"""
        return len(self.check(ip)) > 0

    @property
    def total_entries(self) -> int:
        return sum(len(nets) for nets in self._feeds.values())

    @property
    def feed_names(self) -> list[str]:
        return list(self._feeds.keys())
