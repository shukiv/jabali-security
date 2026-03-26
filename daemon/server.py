"""Async daemon supervisor -- the heart of Jabali Security."""

from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web

from api.app import create_app
from lib.config import JabaliConfig
from lib.constants import VERSION
from lib.registry import ComponentRegistry

logger = logging.getLogger("jabali-security")


class SecurityDaemon:
    """Main supervisor that coordinates all async tasks."""

    def __init__(self, config: JabaliConfig, disabled: set[str] | None = None) -> None:
        self.config = config
        self._disabled = disabled
        self._start_time: datetime | None = None
        self._registry: ComponentRegistry | None = None

    async def run(self) -> None:
        """Start all subsystems and run until shutdown."""
        self._start_time = datetime.now(timezone.utc)

        self._registry = await ComponentRegistry.build(self.config, disabled=self._disabled)

        async with self._registry:
            app = create_app()
            self._registry.populate_app(app, daemon=self)
            api_runner = web.AppRunner(app)
            await api_runner.setup()
            api_site = web.TCPSite(api_runner, self.config.api_bind, self.config.api_port)

            loop = asyncio.get_running_loop()
            stop_event = asyncio.Event()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, stop_event.set)

            logger.info("Jabali Security %s starting...", VERSION)
            logger.info(
                "Watching dirs: %s | Workers: %d | Engines: %s",
                ", ".join(self.config.watch_dirs),
                self.config.workers,
                ", ".join(self._registry.scanner.scanner_names) or "none",
            )

            await api_site.start()
            logger.info("REST API listening on %s:%d", self.config.api_bind, self.config.api_port)

            try:
                async with asyncio.TaskGroup() as tg:
                    for coro in self._registry.background_tasks(self):
                        tg.create_task(coro)
                    tg.create_task(self._wait_for_stop(stop_event))
            except* KeyboardInterrupt:
                pass
            finally:
                await api_runner.cleanup()
                logger.info("Jabali Security stopped.")

    async def _scan_worker(self, worker_id: int) -> None:
        """Worker: read file -> behavior check -> scan -> score -> respond."""
        reg = self._registry
        logger.info("Scan worker %d started", worker_id)
        while True:
            event = await reg.scan_queue.get()
            try:
                # Record behavior and get behavioral findings
                behavior_findings = await reg.behavior.record_event(event)

                # Read file content (with post-read size guard)
                try:
                    content = await asyncio.to_thread(Path(event.path).read_bytes)
                except (FileNotFoundError, PermissionError, OSError):
                    # File gone -- still evaluate behavior findings if any
                    if behavior_findings:
                        score = reg.scoring.evaluate(event, behavior_findings)
                        if score.action != "ignore":
                            await reg.response.handle(event, score)
                    continue
                if len(content) > self.config.max_file_size:
                    continue

                # Check hash cache -- skip known-clean files
                file_hash = reg.hash_cache.get_hash(content)
                if reg.hash_cache.is_known_clean(file_hash) and not behavior_findings:
                    continue

                # Run all content scanners
                content_findings = await reg.scanner.scan(event.path, content)

                # Merge content + behavior findings
                all_findings = content_findings + behavior_findings

                if not all_findings:
                    reg.hash_cache.mark_clean(file_hash)
                    continue

                # Score and respond
                score = reg.scoring.evaluate(event, all_findings)
                reg.hash_cache.mark_dirty(file_hash)

                if score.action != "ignore":
                    await reg.response.handle(event, score)

            except Exception:
                logger.exception("Worker %d: error processing %s", worker_id, event.path)
            finally:
                reg.scan_queue.task_done()

    @staticmethod
    def _make_auth_callback(detector, firewall, incidents):
        """Build the async callback that bridges log parser -> detector -> firewall."""
        from datetime import datetime, timedelta, timezone

        async def _on_auth_event(event):
            decision = detector.record(event)
            if decision is None:
                return
            await firewall.block_ip(decision.ip, decision.duration)
            # Persist to blocked_ips table
            db = incidents._db
            if db is not None:
                now = datetime.now(timezone.utc)
                expires_at = None
                if decision.duration > 0:
                    expires_at = (now + timedelta(seconds=decision.duration)).isoformat()
                await db.execute(
                    "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at, blocked_by) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (decision.ip, decision.reason, now.isoformat(), expires_at, "bruteforce"),
                )
                await db.commit()

        return _on_auth_event

    @staticmethod
    def _make_waf_callback(incidents):
        """Build the async callback that persists WAF events to the database."""
        async def _on_waf_event(event):
            db = incidents._db
            if db is None:
                return
            await db.execute(
                "INSERT OR IGNORE INTO waf_events "
                "(id, client_ip, uri, method, rule_id, rule_msg, severity, action, "
                "hostname, username, matched_data, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.id,
                    event.client_ip,
                    event.uri,
                    event.method,
                    event.rule_id,
                    event.rule_msg,
                    event.severity,
                    event.action,
                    event.hostname,
                    event.username,
                    event.matched_data,
                    event.timestamp.isoformat(),
                ),
            )
            await db.commit()

        return _on_waf_event

    async def _handle_process_threats(self, threats: list) -> None:
        """Callback for process monitor -- log threats."""
        for threat in threats:
            logger.critical(
                "PROCESS THREAT: pid=%d ppid=%d score=%d user=%s cmd=%s -- %s",
                threat.pid, threat.ppid, threat.score,
                threat.username, threat.cmdline[:100], threat.description,
            )
        # Future: create incidents for process threats

    async def _wait_for_stop(self, stop_event: asyncio.Event) -> None:
        """Wait for shutdown signal, then cancel all tasks."""
        await stop_event.wait()
        logger.info("Shutdown signal received...")
        raise KeyboardInterrupt
