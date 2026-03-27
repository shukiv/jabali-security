"""Async auth log parser — tail auth logs and emit failed login events."""
from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Awaitable, Callable

from lib.bruteforce.models import AuthEvent
from lib.log_tailer import AsyncLogTailer

logger = logging.getLogger(__name__)

# Service patterns: (rule_name, compiled_regex with named group "ip")
_LOG_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "ssh": [
        ("ssh_failed_password", re.compile(
            r"Failed password for (?:invalid user )?\S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        )),
        ("ssh_invalid_user", re.compile(
            r"Invalid user \S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        )),
        ("ssh_connection_closed_preauth", re.compile(
            r"Connection closed by (?:authenticating user \S+ )?(?P<ip>\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]"
        )),
    ],
    "dovecot": [
        ("dovecot_auth_failed", re.compile(
            r"auth-worker.*(?:password|auth failed).*rip=(?P<ip>\d+\.\d+\.\d+\.\d+)"
        )),
    ],
    "exim": [
        ("exim_auth_failed", re.compile(
            r"authenticator failed.*\[(?P<ip>\d+\.\d+\.\d+\.\d+)\]"
        )),
    ],
    "postfix": [
        ("postfix_sasl_failed", re.compile(
            r"SASL (?:LOGIN|PLAIN|CRAM-MD5) authentication failed.*\[(?P<ip>\d+\.\d+\.\d+\.\d+)\]"
        )),
    ],
    "stalwart": [
        # Stalwart log format: 2026-03-19T20:22:55Z WARN ... (auth.failed) remote-ip = 1.2.3.4
        ("stalwart_auth_failed", re.compile(
            r"(?:auth\.failed|auth\.error|Authentication failed).{0,200}remote-ip\s*=\s*(?P<ip>\d+\.\d+\.\d+\.\d+)"
        )),
        # Alternative format: ... (security.authentication-failed) ... remote-ip = x.x.x.x
        ("stalwart_security_auth_failed", re.compile(
            r"security\.authentication-failed.{0,200}remote-ip\s*=\s*(?P<ip>\d+\.\d+\.\d+\.\d+)"
        )),
        # Brute force detection by Stalwart itself
        ("stalwart_brute_force", re.compile(
            r"(?:security\.brute-force|too many auth).{0,200}remote-ip\s*=\s*(?P<ip>\d+\.\d+\.\d+\.\d+)"
        )),
    ],
}


class AuthLogParser:
    """Tail multiple auth log files and emit AuthEvent for failed logins."""

    def __init__(self, log_configs: dict[str, str]) -> None:
        """
        log_configs: mapping of service_name -> log_file_path
        Example: {"ssh": "/var/log/auth.log", "dovecot": "/var/log/mail.log"}
        """
        self._log_configs = log_configs
        self._running = False
        self._tailers: list[AsyncLogTailer] = []

    async def run(self, callback: Callable[[AuthEvent], Awaitable[None]]) -> None:
        """Tail all configured logs concurrently. Calls callback for each failed login."""
        self._running = True
        tasks = []
        for service, log_path in self._log_configs.items():
            if not Path(log_path).exists():
                logger.warning("Log file not found for %s: %s", service, log_path)
                continue
            patterns = _LOG_PATTERNS.get(service, [])
            if not patterns:
                logger.warning("No patterns defined for service: %s", service)
                continue
            tasks.append(self._tail_log(service, log_path, patterns, callback))

        if not tasks:
            logger.warning("No log files to monitor for brute-force detection")
            return

        logger.info("Brute-force log parser started: monitoring %d log files", len(tasks))
        await asyncio.gather(*tasks)

    async def stop(self) -> None:
        self._running = False
        for tailer in self._tailers:
            await tailer.stop()

    async def _tail_log(
        self,
        service: str,
        log_path: str,
        patterns: list[tuple[str, re.Pattern[str]]],
        callback: Callable[[AuthEvent], Awaitable[None]],
    ) -> None:
        """Tail a single log file, matching patterns and emitting events."""
        tailer = AsyncLogTailer(log_path)
        self._tailers.append(tailer)

        async def _on_line(raw_line: str) -> None:
            line = raw_line.strip()
            if line:
                await self._process_line(service, line, patterns, callback)

        logger.info("Tailing %s for %s events", log_path, service)
        await tailer.tail(_on_line)

    async def _process_line(
        self,
        service: str,
        line: str,
        patterns: list[tuple[str, re.Pattern[str]]],
        callback: Callable[[AuthEvent], Awaitable[None]],
    ) -> None:
        """Match line against patterns and emit AuthEvent if matched."""
        for _rule_name, pattern in patterns:
            m = pattern.search(line)
            if m:
                ip = m.group("ip")
                # Extract username if present (best-effort)
                username = ""
                user_match = re.search(r"(?:user |for )(\S+)", line)
                if user_match:
                    username = user_match.group(1)

                event = AuthEvent(
                    ip=ip,
                    service=service,
                    username=username,
                    success=False,
                    raw_line=line[:500],
                )
                await callback(event)
                break  # One match per line
