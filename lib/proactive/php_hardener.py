"""PHP-FPM pool scanner -- read-only discovery and status checking of PHP-FPM pools."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from lib.proactive.models import PoolStatus

logger = logging.getLogger(__name__)

# PHP-FPM pool config search paths
_POOL_SEARCH_PATHS = [
    "/etc/php/*/fpm/pool.d/*.conf",
    "/etc/php-fpm.d/*.conf",
    "/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf",
    "/etc/opt/remi/php*/php-fpm.d/*.conf",
]

# Regex to parse pool config values
_POOL_NAME_RE = re.compile(r"^\[(\S+)\]")
_KEY_VALUE_RE = re.compile(r"^(\S+)\s*=\s*(.*)")


class PHPPoolScanner:
    """Discover PHP-FPM pools and report their hardening status (read-only)."""

    async def scan_pools(self) -> list[PoolStatus]:
        """Discover all PHP-FPM pools and check their hardening status."""
        pools: list[PoolStatus] = []
        seen: set[str] = set()

        import glob as glob_mod
        for pattern in _POOL_SEARCH_PATHS:
            for conf_path in sorted(glob_mod.glob(pattern)):
                if conf_path in seen:
                    continue
                seen.add(conf_path)
                pool = self._parse_pool_config(conf_path)
                if pool:
                    pools.append(pool)

        logger.info("Discovered %d PHP-FPM pools", len(pools))
        return pools

    def _parse_pool_config(self, conf_path: str) -> PoolStatus | None:
        """Parse a single PHP-FPM pool config file."""
        p = Path(conf_path)
        if not p.is_file():
            return None

        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        # Extract PHP version from path (e.g., /etc/php/8.2/fpm/pool.d/...)
        php_version = "unknown"
        version_match = re.search(r"/php[/-]?(\d+\.?\d*)", conf_path)
        if version_match:
            php_version = version_match.group(1)

        pool_name = ""
        user = ""
        group = ""
        listen = ""
        disable_functions = ""
        open_basedir = ""

        for line in content.splitlines():
            line = line.strip()
            if line.startswith(";") or line.startswith("#") or not line:
                continue

            nm = _POOL_NAME_RE.match(line)
            if nm:
                pool_name = nm.group(1)
                continue

            kv = _KEY_VALUE_RE.match(line)
            if not kv:
                continue
            key, val = kv.group(1), kv.group(2).strip()

            if key == "user":
                user = val
            elif key == "group":
                group = val
            elif key == "listen":
                listen = val
            elif key in ("php_admin_value[disable_functions]", "php_value[disable_functions]"):
                disable_functions = val
            elif key in ("php_admin_value[open_basedir]", "php_value[open_basedir]"):
                open_basedir = val

        if not pool_name or not user:
            return None

        # Check hardening status
        issues: list[str] = []
        hardened = True

        if not disable_functions:
            issues.append("disable_functions not set")
            hardened = False
        else:
            # Check if dangerous functions are present in disable list
            disabled_set = {f.strip().lower() for f in disable_functions.split(",")}
            critical = {"exec", "passthru", "shell_exec", "system", "proc_open", "popen"}
            missing = critical - disabled_set
            if missing:
                issues.append("Missing from disable_functions: %s" % ", ".join(sorted(missing)))
                hardened = False

        if not open_basedir:
            issues.append("open_basedir not set")
            hardened = False

        return PoolStatus(
            pool_name=pool_name,
            php_version=php_version,
            user=user,
            group=group,
            listen=listen,
            hardened=hardened,
            disable_functions=disable_functions,
            open_basedir=open_basedir,
            issues=issues,
            socket_path=conf_path,
        )
