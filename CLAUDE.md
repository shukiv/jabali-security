# Jabali Security

Standalone, event-driven security suite for Linux shared hosting.

## Stack

- Python 3.12+, asyncio-based daemon
- YARA-X for signature scanning (not legacy yara-python)
- ClamAV optional backend (clamd socket, auto-detected)
- aiohttp for REST API
- click for CLI
- aiosqlite for incident storage
- Pydantic for data models

## Project Layout

- `daemon/` — CLI entry point + async daemon server
- `lib/` — Core library modules (scanners, watcher, scoring, etc.)
- `api/` — REST API (aiohttp)
- `rules/` — YARA-X rule files (.yar)
- `etc/` — Config example + systemd service
- `tests/` — pytest test suite
- `debian/` — .deb packaging

## Conventions

- Config format: KEY="value" (gniza4linux pattern)
- Config path: /etc/jabali-security/jabali-security.conf
- Data path: /var/lib/jabali-security/
- Log path: /var/log/jabali-security/
- Quarantine: /var/security/quarantine/{user}/
- API: 127.0.0.1:9876 with X-API-Key auth
- No shell=True in subprocess calls — always use list args
- Use `import yara_x` not `import yara`
- YARA-X API: `yara_x.Compiler()`, `yara_x.Scanner(rules)`, `results.matching_rules`
- Use `trash` instead of `rm`/`rmdir`

## Running

```
uv run jabali-security start --foreground
uv run pytest tests/
```
