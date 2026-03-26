"""Async daemon supervisor -- the heart of Jabali Security."""

from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web

from api.app import create_app
from lib.behavior_tracker import BehaviorTracker
from lib.config import JabaliConfig
from lib.constants import VERSION
from lib.filter import PreFilter
from lib.hash_cache import HashCache
from lib.incidents import IncidentStore
from lib.process_monitor import ProcessMonitor
from lib.quarantine import QuarantineManager
from lib.queue import ScanQueue
from lib.response import ResponseEngine
from lib.scanner import ScanOrchestrator
from lib.scoring import ScoringEngine
from lib.watcher.inotify import InotifyWatcher

logger = logging.getLogger("jabali-security")


class SecurityDaemon:
    """Main supervisor that coordinates all async tasks."""

    def __init__(self, config: JabaliConfig) -> None:
        self.config = config
        self._start_time: datetime | None = None
        self._watcher: InotifyWatcher | None = None
        self._hash_cache: HashCache | None = None
        self._incidents: IncidentStore | None = None

    async def run(self) -> None:
        """Start all subsystems and run until shutdown."""
        self._start_time = datetime.now(timezone.utc)

        # Initialize data directory
        data_dir = Path(self.config.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        scan_queue = ScanQueue()
        pre_filter = PreFilter(self.config)
        self._watcher = InotifyWatcher(
            watch_dirs=self.config.watch_dirs,
            pre_filter=pre_filter,
        )
        self._hash_cache = HashCache(persist_path=data_dir / "hash_cache.json")
        scanner = ScanOrchestrator(self.config)
        scoring = ScoringEngine(self.config)
        behavior = BehaviorTracker(ttl=self.config.behavior_ttl)

        # Initialize incident store
        self._incidents = IncidentStore(db_path=data_dir / "incidents.db")
        await self._incidents.open()

        # Initialize quarantine + response
        quarantine = QuarantineManager(base_dir=self.config.quarantine_dir)
        response = ResponseEngine(self.config, quarantine, self._incidents)

        # Initialize process monitor
        proc_monitor = ProcessMonitor(
            poll_interval=self.config.process_poll_interval,
            enabled=self.config.process_monitor_enabled,
        )

        # Initialize REST API
        app = create_app(
            config=self.config,
            daemon=self,
            incidents=self._incidents,
            quarantine=quarantine,
            scanner=scanner,
            scoring=scoring,
        )
        api_runner = web.AppRunner(app)
        await api_runner.setup()
        api_site = web.TCPSite(api_runner, self.config.api_bind, self.config.api_port)

        # Register signal handlers
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop_event.set)

        logger.info("Jabali Security %s starting...", VERSION)
        logger.info(
            "Watching dirs: %s | Workers: %d | Engines: %s",
            ", ".join(self.config.watch_dirs),
            self.config.workers,
            ", ".join(scanner.scanner_names) or "none",
        )

        # Start API server
        await api_site.start()
        logger.info("REST API listening on %s:%d", self.config.api_bind, self.config.api_port)

        # Launch tasks with TaskGroup
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self._watcher.start(scan_queue))
                for i in range(self.config.workers):
                    tg.create_task(
                        self._scan_worker(scan_queue, scanner, scoring, behavior, response, i)
                    )
                tg.create_task(proc_monitor.run(self._handle_process_threats))
                tg.create_task(self._wait_for_stop(stop_event))
        except* KeyboardInterrupt:
            pass
        finally:
            await api_runner.cleanup()
            if self._watcher is not None:
                await self._watcher.stop()
            if self._hash_cache is not None:
                self._hash_cache.save()
            if self._incidents is not None:
                await self._incidents.close()
            logger.info("Jabali Security stopped.")

    async def _scan_worker(
        self,
        queue: ScanQueue,
        scanner: ScanOrchestrator,
        scoring: ScoringEngine,
        behavior: BehaviorTracker,
        response: ResponseEngine,
        worker_id: int,
    ) -> None:
        """Worker: read file -> behavior check -> scan -> score -> respond."""
        logger.info("Scan worker %d started", worker_id)
        while True:
            event = await queue.get()
            try:
                # Record behavior and get behavioral findings
                behavior_findings = await behavior.record_event(event)

                # Read file content (with post-read size guard)
                try:
                    content = await asyncio.to_thread(Path(event.path).read_bytes)
                except (FileNotFoundError, PermissionError, OSError):
                    # File gone — still evaluate behavior findings if any
                    if behavior_findings:
                        score = scoring.evaluate(event, behavior_findings)
                        if score.action != "ignore":
                            await response.handle(event, score)
                    continue
                if len(content) > self.config.max_file_size:
                    continue

                # Check hash cache — skip known-clean files
                file_hash = self._hash_cache.get_hash(content)
                if self._hash_cache.is_known_clean(file_hash) and not behavior_findings:
                    continue

                # Run all content scanners
                content_findings = await scanner.scan(event.path, content)

                # Merge content + behavior findings
                all_findings = content_findings + behavior_findings

                if not all_findings:
                    self._hash_cache.mark_clean(file_hash)
                    continue

                # Score and respond
                score = scoring.evaluate(event, all_findings)
                self._hash_cache.mark_dirty(file_hash)

                if score.action != "ignore":
                    await response.handle(event, score)

            except Exception:
                logger.exception("Worker %d: error processing %s", worker_id, event.path)
            finally:
                queue.task_done()

    async def _handle_process_threats(self, threats: list) -> None:
        """Callback for process monitor — log threats."""
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
