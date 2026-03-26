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
from lib.bruteforce.detector import BruteForceDetector
from lib.bruteforce.firewall import FirewallManager
from lib.bruteforce.log_parser import AuthLogParser
from lib.config import JabaliConfig
from lib.constants import VERSION
from lib.filter import PreFilter
from lib.hash_cache import HashCache
from lib.incidents import IncidentStore
from lib.proactive.php_hardener import PHPHardener
from lib.proactive.process_killer import ProactiveProcessKiller
from lib.process_monitor import ProcessMonitor
from lib.quarantine import QuarantineManager
from lib.queue import ScanQueue
from lib.response import ResponseEngine
from lib.scanner import ScanOrchestrator
from lib.scoring import ScoringEngine
from lib.waf.audit_log_parser import ModSecAuditLogParser
from lib.waf.rule_manager import WafRuleManager
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

        # Initialize firewall
        firewall = FirewallManager(backend=self.config.firewall_backend)
        await firewall.initialize()

        # Initialize brute-force detector + log parser (if enabled)
        bf_detector: BruteForceDetector | None = None
        auth_parser: AuthLogParser | None = None
        if self.config.bruteforce_enabled:
            bf_detector = BruteForceDetector(
                thresholds={
                    "ssh": (self.config.bruteforce_ssh_threshold, self.config.bruteforce_ssh_window),
                    "dovecot": (self.config.bruteforce_mail_threshold, self.config.bruteforce_mail_window),
                    "exim": (self.config.bruteforce_mail_threshold, self.config.bruteforce_mail_window),
                    "postfix": (self.config.bruteforce_mail_threshold, self.config.bruteforce_mail_window),
                },
                block_durations=self.config.bruteforce_block_durations,
                whitelist=set(self.config.bruteforce_whitelist_ips),
            )
            log_configs: dict[str, str] = {}
            if Path(self.config.bruteforce_ssh_log).exists():
                log_configs["ssh"] = self.config.bruteforce_ssh_log
            if Path(self.config.bruteforce_mail_log).exists():
                log_configs["dovecot"] = self.config.bruteforce_mail_log
                log_configs["postfix"] = self.config.bruteforce_mail_log
            auth_parser = AuthLogParser(log_configs)

        # Initialize WAF components (if enabled)
        waf_parser: ModSecAuditLogParser | None = None
        waf_rules: WafRuleManager | None = None
        if self.config.waf_enabled:
            waf_rules = WafRuleManager(
                overrides_file=self.config.waf_overrides_file,
                rules_dir=self.config.waf_rules_dir,
                web_server=self.config.waf_web_server,
            )
            waf_parser = ModSecAuditLogParser(
                log_path=self.config.waf_audit_log,
                log_type=self.config.waf_audit_log_type,
            )

        # Initialize quarantine + response
        quarantine = QuarantineManager(base_dir=self.config.quarantine_dir)
        response = ResponseEngine(self.config, quarantine, self._incidents)

        # Initialize process monitor
        proc_monitor = ProcessMonitor(
            poll_interval=self.config.process_poll_interval,
            enabled=self.config.process_monitor_enabled,
        )

        # Initialize proactive defense components
        proactive_killer = ProactiveProcessKiller(
            enabled=self.config.process_kill_enabled,
            threshold=self.config.process_kill_threshold,
            min_uid=self.config.process_kill_min_uid,
            whitelist_commands=self.config.process_kill_whitelist,
        )

        php_hardener: PHPHardener | None = None
        if self.config.php_hardening_enabled:
            php_hardener = PHPHardener(
                enabled=True,
                auto=self.config.php_hardening_auto,
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
        app["firewall"] = firewall
        app["bruteforce_detector"] = bf_detector
        app["waf_parser"] = waf_parser
        app["waf_rules"] = waf_rules
        app["proactive_killer"] = proactive_killer
        app["php_hardener"] = php_hardener
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

        # Run initial PHP-FPM auto-hardening if enabled
        if php_hardener is not None:
            try:
                hardened_count = await php_hardener.auto_harden_all()
                if hardened_count:
                    logger.info("Auto-hardened %d PHP-FPM pools at startup", hardened_count)
            except Exception:
                logger.exception("Error during initial PHP-FPM auto-hardening")

        # Launch tasks with TaskGroup
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self._watcher.start(scan_queue))
                for i in range(self.config.workers):
                    tg.create_task(
                        self._scan_worker(scan_queue, scanner, scoring, behavior, response, i)
                    )
                tg.create_task(proc_monitor.run(proactive_killer.handle_threats))
                if self.config.bruteforce_enabled and auth_parser is not None:
                    tg.create_task(auth_parser.run(
                        self._make_auth_callback(bf_detector, firewall, self._incidents)
                    ))
                if self.config.waf_enabled and waf_parser is not None:
                    tg.create_task(waf_parser.run(
                        self._make_waf_callback(self._incidents)
                    ))
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
