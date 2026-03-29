"""Async auth log parser — tail auth logs and emit failed login events."""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
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
        journald_services: list[tuple[str, list[tuple[str, re.Pattern[str]]]]] = []

        for service, log_path in self._log_configs.items():
            patterns = _LOG_PATTERNS.get(service, [])
            if not patterns:
                logger.warning("No patterns defined for service: %s", service)
                continue
            if Path(log_path).exists():
                tasks.append(self._tail_log(service, log_path, patterns, callback))
            else:
                # Log file missing — queue for journald fallback
                journald_services.append((service, patterns))

        # Fallback: use journalctl for services whose log files don't exist
        if journald_services and shutil.which("journalctl"):
            unit_map = {"ssh": "ssh.service", "sshd": "ssh.service",
                        "dovecot": "dovecot.service", "postfix": "postfix.service",
                        "exim": "exim4.service", "stalwart": "stalwart-mail.service"}
            units = []
            all_patterns: list[tuple[str, re.Pattern[str]]] = []
            for svc, pats in journald_services:
                unit = unit_map.get(svc, f"{svc}.service")
                units.append(unit)
                all_patterns.extend(pats)
                logger.info("Log file missing for %s, using journald (%s)", svc, unit)
            tasks.append(self._tail_journald(units, all_patterns, callback))

        if not tasks:
            logger.warning("No log files to monitor for brute-force detection")
            return

        logger.info("Brute-force log parser started: monitoring %d sources", len(tasks))
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

    async def _tail_journald(
        self,
        units: list[str],
        patterns: list[tuple[str, re.Pattern[str]]],
        callback: Callable[[AuthEvent], Awaitable[None]],
    ) -> None:
        """Follow journald output for specified units, matching brute-force patterns."""
        cmd = ["journalctl", "--follow", "--no-pager", "-o", "short", "-n", "0"]
        for unit in units:
            cmd.extend(["-u", unit])

        logger.info("Tailing journald for units: %s", ", ".join(units))
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            while self._running and proc.stdout:
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").strip()
                if line:
                    service = "ssh"
                    if "dovecot" in line.lower():
                        service = "dovecot"
                    elif "postfix" in line.lower():
                        service = "postfix"
                    elif "exim" in line.lower():
                        service = "exim"
                    await self._process_line(service, line, patterns, callback)
        finally:
            proc.terminate()
            await proc.wait()

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
