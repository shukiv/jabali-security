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
- `lib/ufw/` — UFW firewall management (rule CRUD, enable/disable, app profiles)
- `api/` — REST API (aiohttp), routes split into `api/routes/` by domain
- `rules/` — YARA-X rule files (.yar)
- `etc/` — Config example + systemd service
- `tests/` — pytest test suite + external security test script (`test_security.sh`)
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
- PHP-FPM pool hardening is managed by the hosting panel, not by jabali-security
- WebShield requires manual nginx include + reload after install
- Default watch paths: `/home/*/public_html`, `/home/*/domains/*/public_html`, `/home/*/tmp`

## Running

```
uv run jabali-security start --foreground
uv run pytest tests/
```
