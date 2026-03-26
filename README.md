# Jabali Security

Event-driven security suite for Linux shared hosting. A lightweight, panel-agnostic alternative to Imunify360.

## Features

- **Real-time file monitoring** via Linux inotify
- **Multi-engine detection**: heuristic patterns + Shannon entropy + YARA-X + optional ClamAV
- **Behavior-first**: process tree monitoring, file lifecycle tracking
- **Scoring engine**: aggregated threat scoring with configurable thresholds
- **Automated response**: quarantine, process termination, IP blocking
- **Multi-tenant aware**: maps files to hosting accounts automatically
- **Low footprint**: targets <100MB memory, event-driven (no scheduled scans)
- **Comprehensive CLI**: full management from the command line
- **REST API**: integrate with any hosting panel

## Install

```bash
git clone ssh://git@git.linux-hosting.co.il:2222/shukivaknin/jabali-security.git
cd jabali-security
sudo bash install.sh
```

This will:
- Copy files to `/usr/local/jabali-security/`
- Create a Python venv and install dependencies
- Generate a random API key
- Set up and start the systemd service
- Raise the inotify watch limit

After install:

```bash
jabali-security status              # check it's running
jabali-security config test         # verify config
jabali-security scan /home -r       # on-demand scan
journalctl -u jabali-security -f    # watch live logs
```

## Uninstall

```bash
sudo bash install.sh --uninstall
```

Completely removes the application, config, data, logs, and quarantine.

## Development

```bash
uv sync
uv run jabali-security start --foreground
uv run jabali-security scan /path/to/file.php --json
uv run pytest tests/ -v
```

## Configuration

Config file: `/etc/jabali-security/jabali-security.conf` (root) or `~/.config/jabali-security/jabali-security.conf`

See `etc/jabali-security.conf.example` for all options.

## CLI Commands

```
jabali-security start [--foreground] [--config PATH]
jabali-security stop
jabali-security status [--json]
jabali-security scan <path> [--recursive] [--json]
jabali-security incidents [--limit N] [--user USERNAME] [--severity LEVEL] [--json]
jabali-security quarantine list|restore|delete
jabali-security config show|set|test
jabali-security rules update|list
jabali-security user risk|list
jabali-security block|unblock|blocklist
```

## REST API

Default: `http://127.0.0.1:9876/api/v1/`

Authentication via `X-API-Key` header.

| Endpoint | Method | Description |
|---|---|---|
| `/status` | GET | Daemon status |
| `/incidents` | GET | List incidents |
| `/scan` | POST | Trigger on-demand scan |
| `/quarantine` | GET | List quarantined files |
| `/users` | GET | User risk scores |
| `/blocklist` | GET | Blocked IPs |
| `/config` | GET/PATCH | Configuration |
| `/rules` | GET | Loaded YARA rules |

## Architecture

```
File Watcher (inotify) ──┐
Process Monitor (/proc) ──┼── Detection Engine ── Scoring ── Response
Behavior Tracker ─────────┘   (heuristic+entropy   Engine    Engine
                               +YARA-X+ClamAV opt)
```

## Requirements

- Linux (kernel 2.6.13+ for inotify)
- Python 3.12+
- YARA-X (`pip install yara-x`)

## License

Proprietary
