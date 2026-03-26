"""PHP-FPM pool hardener -- auto-harden pools with disable_functions and open_basedir."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from lib.proactive.models import PoolStatus

logger = logging.getLogger(__name__)

# Dangerous functions to disable in PHP-FPM pools
_DANGEROUS_FUNCTIONS = (
    "exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,"
    "pcntl_fork,dl,putenv,show_source,posix_kill,posix_mkfifo"
)

# PHP-FPM pool config search paths
_POOL_SEARCH_PATHS = [
    "/etc/php/*/fpm/pool.d/*.conf",
    "/etc/php-fpm.d/*.conf",
    "/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf",
    "/etc/opt/remi/php*/php-fpm.d/*.conf",
]

# Marker comments for jabali-managed hardening block
_MARKER_START = "; JABALI-SECURITY-HARDENING-START"
_MARKER_END = "; JABALI-SECURITY-HARDENING-END"

# Regex to parse pool config values
_POOL_NAME_RE = re.compile(r"^\[(\S+)\]")
_KEY_VALUE_RE = re.compile(r"^(\S+)\s*=\s*(.*)")


class PHPHardener:
    """Discover and harden PHP-FPM pools."""

    def __init__(self, enabled: bool = False, auto: bool = False) -> None:
        self._enabled = enabled
        self._auto = auto

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
        has_jabali_block = _MARKER_START in content

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
            hardened=hardened and has_jabali_block,
            disable_functions=disable_functions,
            open_basedir=open_basedir,
            issues=issues,
            socket_path=conf_path,
        )

    async def harden_pool(self, conf_path: str) -> bool:
        """Add hardening directives to a PHP-FPM pool config."""
        p = Path(conf_path)
        if not p.is_file():
            logger.error("Pool config not found: %s", conf_path)
            return False

        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.error("Cannot read pool config: %s", conf_path)
            return False

        # Parse user for open_basedir
        pool = self._parse_pool_config(conf_path)
        if not pool:
            return False

        # Remove existing jabali block if present
        content = self._remove_jabali_block(content)

        # Build hardening block
        open_basedir = "/home/%s:/tmp:/usr/share/php:/var/lib/php" % pool.user
        block = "\n".join([
            "",
            _MARKER_START,
            "php_admin_value[disable_functions] = %s" % _DANGEROUS_FUNCTIONS,
            "php_admin_value[open_basedir] = %s" % open_basedir,
            "php_admin_value[upload_tmp_dir] = /home/%s/tmp" % pool.user,
            "php_admin_value[session.save_path] = /home/%s/tmp" % pool.user,
            "php_admin_value[sys_temp_dir] = /home/%s/tmp" % pool.user,
            _MARKER_END,
            "",
        ])

        # Append block
        content = content.rstrip() + block
        p.write_text(content, encoding="utf-8")
        logger.info("Hardened pool %s at %s", pool.pool_name, conf_path)
        return True

    async def unharden_pool(self, conf_path: str) -> bool:
        """Remove jabali hardening from a pool config."""
        p = Path(conf_path)
        if not p.is_file():
            return False

        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False

        new_content = self._remove_jabali_block(content)
        if new_content == content:
            return False  # Nothing to remove

        p.write_text(new_content, encoding="utf-8")
        logger.info("Removed hardening from %s", conf_path)
        return True

    async def auto_harden_all(self) -> int:
        """Harden all unhardened pools. Returns count of pools hardened."""
        if not self._auto:
            return 0
        pools = await self.scan_pools()
        count = 0
        for pool in pools:
            if not pool.hardened:
                if await self.harden_pool(pool.socket_path):
                    count += 1
        if count:
            logger.info("Auto-hardened %d PHP-FPM pools", count)
        return count

    @staticmethod
    def _remove_jabali_block(content: str) -> str:
        """Remove the JABALI-SECURITY-HARDENING block from content."""
        lines = content.splitlines()
        result: list[str] = []
        in_block = False
        for line in lines:
            if line.strip() == _MARKER_START:
                in_block = True
                continue
            if line.strip() == _MARKER_END:
                in_block = False
                continue
            if not in_block:
                result.append(line)
        return "\n".join(result)

    @property
    def enabled(self) -> bool:
        return self._enabled
