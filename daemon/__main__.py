"""Jabali Security CLI entry point (click-based)."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import os
import signal
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import click

from lib.config import JabaliConfig, load_config, update_conf_key
from lib.constants import APP_NAME, CONFIG_FILE, LOG_DIR

logger = logging.getLogger(APP_NAME)

_PID_DIR_ROOT = Path("/var/run/jabali-security")
_PID_FILENAME = "jabali-security.pid"
_MAX_PID = 4194304  # Linux default pid_max

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
_LOG_BACKUP_COUNT = 3


# -- PID helpers -------------------------------------------------------------

def _pid_dir() -> Path:
    if os.getuid() == 0:
        return _PID_DIR_ROOT
    # Use XDG_RUNTIME_DIR (e.g. /run/user/<uid>) to avoid /tmp symlink attacks
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / "jabali-security"
    return Path.home() / ".cache" / "jabali-security"


def _pid_file() -> Path:
    d = _pid_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / _PID_FILENAME


def _write_pid() -> None:
    pf = _pid_file()
    # Use O_CREAT|O_WRONLY|O_TRUNC without following symlinks:
    # unlink first to avoid writing through a symlink
    try:
        if pf.is_symlink():
            pf.unlink()
    except OSError:
        pass
    fd = os.open(str(pf), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
    try:
        os.write(fd, str(os.getpid()).encode())
    finally:
        os.close(fd)


def _remove_pid() -> None:
    try:
        _pid_file().unlink(missing_ok=True)
    except OSError:
        pass


def _read_pid() -> int | None:
    pf = _pid_file()
    if not pf.exists() or pf.is_symlink():
        return None
    text = pf.read_text().strip()
    if not text.isdigit():
        return None
    pid = int(text)
    if pid < 1 or pid > _MAX_PID:
        return None
    return pid


def _verify_pid_is_ours(pid: int) -> bool:
    """Check that a PID belongs to a jabali-security process via /proc."""
    try:
        cmdline = Path("/proc/%d/cmdline" % pid).read_bytes()
        return b"jabali-security" in cmdline or b"daemon" in cmdline
    except OSError:
        return False


# -- Logging setup -----------------------------------------------------------

def _setup_logging(foreground: bool, level: str) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    if foreground:
        handler: logging.Handler = logging.StreamHandler(sys.stderr)
    else:
        log_dir = Path(str(LOG_DIR))
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_dir / "jabali-security.log",
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUP_COUNT,
        )

    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    root.addHandler(handler)


# -- API client helpers ------------------------------------------------------

def _api_request(config: JabaliConfig, method: str, path: str, body: dict | None = None) -> dict:
    """Make an API request to the running daemon. Returns parsed JSON or raises."""
    url = "http://%s:%d%s" % (config.api_bind, config.api_port, path)
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if config.api_key:
        headers["X-API-Key"] = config.api_key
    req = Request(url, data=data, headers=headers, method=method)  # noqa: S310
    with urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def _daemon_not_running() -> None:
    """Print daemon-not-running message and exit."""
    click.echo("Daemon is not running. Use 'jabali-security start' first.", err=True)
    sys.exit(1)


def _api_call(config: JabaliConfig, method: str, path: str, body: dict | None = None) -> dict:
    """Wrapper around _api_request that handles connection errors."""
    try:
        return _api_request(config, method, path, body)
    except (URLError, ConnectionRefusedError, OSError):
        _daemon_not_running()
        return {}  # unreachable, satisfies type checker


# -- Standalone scan helpers -------------------------------------------------

def _standalone_scan(file_path: str, config: JabaliConfig) -> dict:
    """Scan a single file without the daemon running."""
    from lib.filter import PreFilter
    from lib.models import FileEvent
    from lib.scanner import ScanOrchestrator
    from lib.scoring import ScoringEngine
    from lib.tenant import resolve_user

    p = Path(file_path)
    if not p.is_file():
        click.echo("File not found: %s" % file_path, err=True)
        return {}

    pre_filter = PreFilter(config)
    if not pre_filter.should_scan(str(p)):
        return {}

    content = p.read_bytes()
    scanner = ScanOrchestrator(config)
    scoring = ScoringEngine(config)

    event = FileEvent(
        event_type="scan",
        path=str(p.resolve()),
        username=resolve_user(str(p)),
        size=len(content),
    )
    findings = asyncio.run(scanner.scan(str(p), content))
    score = scoring.evaluate(event, findings)

    return {
        "path": str(p.resolve()),
        "findings": [f.model_dump() for f in findings],
        "score": score.total,
        "action": score.action,
        "severity": ScoringEngine.severity_from_score(score.total),
    }


def _scan_directory(dir_path: str, config: JabaliConfig) -> list[dict]:
    """Recursively scan a directory, returning results for each matching file."""
    from lib.filter import PreFilter

    results: list[dict] = []
    pre_filter = PreFilter(config)
    for root, _dirs, files in os.walk(dir_path):
        for f in files:
            full = os.path.join(root, f)
            if pre_filter.should_scan(full):
                result = _standalone_scan(full, config)
                if result:
                    results.append(result)
    return results


def _print_scan_result(result: dict) -> None:
    """Print a single scan result in human-readable format."""
    click.echo("Scanning: %s" % result["path"])
    click.echo("  Score: %d (%s) -> %s" % (result["score"], result["severity"], result["action"]))
    findings = result.get("findings", [])
    if findings:
        click.echo("  Findings:")
        for f in findings:
            click.echo("    [%s] %s (%d) %s" % (f["scanner"], f["rule"], f["score"], f["description"]))


def _daemon_is_reachable(config: JabaliConfig) -> bool:
    """Check if the daemon API is reachable."""
    try:
        _api_request(config, "GET", "/api/v1/status")
        return True
    except (URLError, ConnectionRefusedError, OSError):
        return False


# -- CLI ---------------------------------------------------------------------

@click.group()
def cli():
    """Jabali Security -- event-driven security suite for Linux shared hosting."""


@cli.command()
@click.option("--foreground", is_flag=True, help="Run in foreground with console logging")
@click.option("--config", "config_path", type=click.Path(exists=True), default=None, help="Path to config file")
def start(foreground: bool, config_path: str | None) -> None:
    """Start the security daemon."""
    cfg_path = Path(config_path) if config_path else None
    config = load_config(cfg_path)

    _setup_logging(foreground, config.log_level)

    from daemon.server import SecurityDaemon

    daemon = SecurityDaemon(config)

    _write_pid()
    try:
        asyncio.run(daemon.run())
    finally:
        _remove_pid()


@cli.command()
def stop() -> None:
    """Stop the running daemon."""
    pid = _read_pid()
    if pid is None:
        click.echo("Jabali Security is not running (no PID file found).")
        sys.exit(1)

    if not _verify_pid_is_ours(pid):
        click.echo("PID %d does not belong to jabali-security; removing stale PID file." % pid)
        _remove_pid()
        sys.exit(1)

    try:
        os.kill(pid, signal.SIGTERM)
        click.echo("Sent SIGTERM to PID %d." % pid)
    except ProcessLookupError:
        click.echo("Process %d not found; removing stale PID file." % pid)
        _remove_pid()
        sys.exit(1)
    except PermissionError:
        click.echo("Permission denied sending signal to PID %d." % pid)
        sys.exit(1)


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def status(as_json: bool) -> None:
    """Show daemon status."""
    pid = _read_pid()
    if pid is None:
        if as_json:
            click.echo(json.dumps({"running": False}))
        else:
            click.echo("Jabali Security is not running.")
        sys.exit(0)

    config = load_config()
    url = "http://%s:%d/api/v1/status" % (config.api_bind, config.api_port)

    try:
        req = Request(url, method="GET")  # noqa: S310
        with urlopen(req, timeout=5) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
    except (URLError, OSError, json.JSONDecodeError):
        if as_json:
            click.echo(json.dumps({"running": False, "pid": pid, "error": "API unreachable"}))
        else:
            click.echo("Jabali Security PID %d found but API is unreachable." % pid)
        sys.exit(1)

    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo("Jabali Security v%s" % data.get("version", "?"))
        click.echo("  Status:     running (PID %d)" % pid)
        uptime = int(data.get("uptime_seconds", 0))
        hours, remainder = divmod(uptime, 3600)
        minutes, seconds = divmod(remainder, 60)
        click.echo("  Uptime:     %dh %dm %ds" % (hours, minutes, seconds))
        click.echo("  Workers:    %s" % data.get("workers", "?"))
        click.echo("  Queue:      %s pending" % data.get("scan_queue_size", "?"))
        click.echo("  Watched:    %s dirs" % data.get("watched_dirs", "?"))
        click.echo("  Incidents:  %s (24h)" % data.get("incidents_24h", "?"))
        click.echo("  Quarantine: %s files" % data.get("quarantined_count", "?"))
        click.echo("  Memory:     %s MB" % data.get("memory_mb", "?"))


# -- scan command ------------------------------------------------------------

@cli.command()
@click.argument("path")
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def scan(path: str, recursive: bool, as_json: bool) -> None:
    """Scan a file or directory for threats."""
    config = load_config()
    target = Path(path)

    if not target.exists():
        click.echo("Path not found: %s" % path, err=True)
        sys.exit(1)

    # Try the daemon first; fall back to standalone
    use_daemon = _daemon_is_reachable(config)

    if use_daemon:
        data = _api_call(config, "POST", "/api/v1/scan", {
            "path": str(target.resolve()),
            "recursive": recursive,
        })
        if as_json:
            click.echo(json.dumps(data, indent=2))
        else:
            results = data.get("results", [data]) if isinstance(data, dict) else data
            for r in results:
                _print_scan_result(r)
        return

    # Standalone scan
    if target.is_dir():
        if not recursive:
            click.echo("Target is a directory. Use --recursive / -r to scan recursively.", err=True)
            sys.exit(1)
        results = _scan_directory(str(target), config)
    else:
        result = _standalone_scan(str(target), config)
        results = [result] if result else []

    if as_json:
        click.echo(json.dumps(results, indent=2))
    else:
        if not results:
            click.echo("No scannable files found.")
        for r in results:
            _print_scan_result(r)


# -- incidents group ---------------------------------------------------------

@cli.group()
def incidents():
    """Manage security incidents."""


@incidents.command("list")
@click.option("--limit", "-n", default=20, help="Max results")
@click.option("--user", default=None, help="Filter by username")
@click.option("--severity", default=None, type=click.Choice(["low", "medium", "high", "critical"]))
@click.option("--json", "as_json", is_flag=True)
def incidents_list(limit: int, user: str | None, severity: str | None, as_json: bool) -> None:
    """List security incidents."""
    config = load_config()
    params: list[str] = ["limit=%d" % limit]
    if user:
        params.append("user=%s" % user)
    if severity:
        params.append("severity=%s" % severity)
    query = "&".join(params)
    data = _api_call(config, "GET", "/api/v1/incidents?%s" % query)

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    items = data.get("incidents", [])
    if not items:
        click.echo("No incidents found.")
        return

    click.echo("%-16s  %-8s  %5s  %-10s  %-30s  %s" % ("ID", "Severity", "Score", "User", "Path", "Action"))
    for item in items:
        click.echo("%-16s  %-8s  %5s  %-10s  %-30s  %s" % (
            item.get("id", "")[:16],
            item.get("severity", ""),
            item.get("total_score", ""),
            item.get("username", "") or "",
            item.get("file_event", {}).get("path", "")[:30],
            item.get("action_taken", ""),
        ))


# -- quarantine group --------------------------------------------------------

@cli.group()
def quarantine():
    """Manage quarantined files."""


@quarantine.command("list")
@click.option("--user", default=None, help="Filter by username")
@click.option("--json", "as_json", is_flag=True)
def quarantine_list(user: str | None, as_json: bool) -> None:
    """List quarantined files."""
    config = load_config()
    query = "?user=%s" % user if user else ""
    data = _api_call(config, "GET", "/api/v1/quarantine%s" % query)

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    items = data.get("records", [])
    if not items:
        click.echo("No quarantined files found.")
        return

    click.echo("%-16s  %-10s  %-30s  %s" % ("ID", "User", "Original Path", "Quarantined At"))
    for item in items:
        click.echo("%-16s  %-10s  %-30s  %s" % (
            item.get("id", "")[:16],
            item.get("username", "") or "",
            item.get("original_path", "")[:30],
            item.get("timestamp", ""),
        ))


@quarantine.command()
@click.argument("record_id")
def restore(record_id: str) -> None:
    """Restore a quarantined file."""
    config = load_config()
    data = _api_call(config, "POST", "/api/v1/quarantine/%s/restore" % record_id)
    click.echo(data.get("message", "Restored successfully."))


@quarantine.command()
@click.argument("record_id")
def delete(record_id: str) -> None:
    """Delete a quarantined file permanently."""
    config = load_config()
    data = _api_call(config, "DELETE", "/api/v1/quarantine/%s" % record_id)
    click.echo(data.get("message", "Deleted successfully."))


# -- config group ------------------------------------------------------------

@cli.group("config")
def config_group():
    """View and update configuration."""


@config_group.command("show")
def config_show() -> None:
    """Show current configuration."""
    config = load_config()

    if _daemon_is_reachable(config):
        data = _api_call(config, "GET", "/api/v1/config")
        for key, value in sorted(data.items()):
            click.echo("%s = %s" % (key, value))
    else:
        for key, value in sorted(dataclasses.asdict(config).items()):
            click.echo("%s = %s" % (key, value))


@config_group.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set a configuration value."""
    config = load_config()

    # Always persist to config file
    conf_key = key.upper()
    update_conf_key(CONFIG_FILE, conf_key, value)
    click.echo("Updated %s in config file." % conf_key)

    # Also push to daemon if running
    if _daemon_is_reachable(config):
        try:
            _api_request(config, "PATCH", "/api/v1/config", {conf_key: value})
            click.echo("Applied to running daemon.")
        except (URLError, ConnectionRefusedError, OSError):
            click.echo("Note: daemon not reachable, change will apply on next start.")


@config_group.command("test")
def config_test() -> None:
    """Validate the configuration file."""
    try:
        config = load_config()
    except Exception as exc:
        click.echo("Configuration error: %s" % exc, err=True)
        sys.exit(1)

    click.echo("Configuration file: %s" % CONFIG_FILE)
    click.echo("  Log level:     %s" % config.log_level)
    click.echo("  API bind:      %s:%d" % (config.api_bind, config.api_port))
    click.echo("  Workers:       %d" % config.workers)
    click.echo("  Watch dirs:    %s" % ", ".join(config.watch_dirs))
    click.echo("  Scan ext:      %s" % ", ".join(config.scan_extensions))
    click.echo("  Max file size: %d bytes" % config.max_file_size)
    click.echo("  YARA enabled:  %s" % config.yara_enabled)
    click.echo("  ClamAV:        %s" % config.clamav_enabled)

    warnings: list[str] = []
    if not config.api_key:
        warnings.append("API_KEY is empty -- API will be unauthenticated")
    if config.api_bind not in ("127.0.0.1", "::1", "localhost"):
        warnings.append("API_BIND is not loopback -- API exposed to network")
    if config.auto_suspend:
        warnings.append("AUTO_SUSPEND is enabled -- accounts may be suspended automatically")

    if warnings:
        click.echo("")
        click.echo("Warnings:")
        for w in warnings:
            click.echo("  - %s" % w)
    else:
        click.echo("")
        click.echo("Configuration OK.")


# -- rules group -------------------------------------------------------------

@cli.group()
def rules():
    """Manage detection rules."""


@rules.command("list")
def rules_list() -> None:
    """List loaded detection rules."""
    config = load_config()
    data = _api_call(config, "GET", "/api/v1/rules")

    items = data.get("rules", [])
    if not items:
        click.echo("No rules loaded.")
        return

    for rule in items:
        click.echo("  [%s] %s" % (rule.get("source", ""), rule.get("name", "")))


@rules.command("update")
def rules_update() -> None:
    """Reload YARA rules and update ClamAV signatures."""
    config = load_config()
    data = _api_call(config, "POST", "/api/v1/rules/reload")
    click.echo(data.get("message", "Rules reloaded."))


# -- user group --------------------------------------------------------------

@cli.group()
def user():
    """User risk management."""


@user.command("list")
@click.option("--min-score", default=0, help="Minimum risk score")
@click.option("--json", "as_json", is_flag=True)
def user_list(min_score: int, as_json: bool) -> None:
    """List users with their risk scores."""
    config = load_config()
    data = _api_call(config, "GET", "/api/v1/users")

    users = data.get("users", [])
    if min_score > 0:
        users = [u for u in users if u.get("risk_score", 0) >= min_score]

    if as_json:
        click.echo(json.dumps(users, indent=2))
        return

    if not users:
        click.echo("No users found.")
        return

    click.echo("%-15s  %5s  %s" % ("Username", "Score", "Status"))
    for u in users:
        click.echo("%-15s  %5d  %s" % (
            u.get("username", ""),
            u.get("risk_score", 0),
            u.get("status", ""),
        ))


@user.command("risk")
@click.argument("username")
@click.option("--json", "as_json", is_flag=True)
def user_risk(username: str, as_json: bool) -> None:
    """Show risk profile for a specific user."""
    config = load_config()
    data = _api_call(config, "GET", "/api/v1/users/%s" % username)

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo("User:       %s" % data.get("username", username))
    click.echo("Risk score: %d" % data.get("risk_score", 0))
    click.echo("Status:     %s" % data.get("status", ""))
    click.echo("Incidents:  %d" % data.get("incident_count", 0))

    recent = data.get("recent_incidents", [])
    if recent:
        click.echo("")
        click.echo("Recent incidents:")
        for inc in recent:
            click.echo("  [%s] %s - %s (%s)" % (
                inc.get("severity", ""),
                inc.get("id", "")[:16],
                inc.get("action_taken", ""),
                inc.get("timestamp", ""),
            ))


# -- block / unblock / blocklist commands ------------------------------------

@cli.command()
@click.argument("ip")
@click.option("--reason", default="manual", help="Reason for blocking")
@click.option("--duration", default=0, type=int, help="Duration in seconds (0=permanent)")
def block(ip: str, reason: str, duration: int) -> None:
    """Block an IP address."""
    config = load_config()
    data = _api_call(config, "POST", "/api/v1/block", {
        "ip": ip,
        "reason": reason,
        "duration": duration,
    })
    click.echo(data.get("message", "IP %s blocked." % ip))


@cli.command()
@click.argument("ip")
def unblock(ip: str) -> None:
    """Unblock an IP address."""
    config = load_config()
    data = _api_call(config, "DELETE", "/api/v1/block/%s" % ip)
    click.echo(data.get("message", "IP %s unblocked." % ip))


@cli.command()
@click.option("--json", "as_json", is_flag=True)
def blocklist(as_json: bool) -> None:
    """List blocked IP addresses."""
    config = load_config()
    data = _api_call(config, "GET", "/api/v1/blocklist")

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    items = data.get("blocked", [])
    if not items:
        click.echo("No blocked IPs.")
        return

    click.echo("%-18s  %-12s  %-10s  %s" % ("IP", "Reason", "Duration", "Blocked At"))
    for item in items:
        dur = item.get("duration", 0)
        dur_str = "permanent" if dur == 0 else "%ds" % dur
        click.echo("%-18s  %-12s  %-10s  %s" % (
            item.get("ip", ""),
            item.get("reason", ""),
            dur_str,
            item.get("blocked_at", ""),
        ))


if __name__ == "__main__":
    cli()
