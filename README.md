# Jabali Security

**Event-driven security suite for Linux shared hosting.**
A lightweight, panel-agnostic alternative to Imunify360.

<!-- badges -->
<!-- ![Build](https://img.shields.io/badge/build-passing-brightgreen) -->
<!-- ![Tests](https://img.shields.io/badge/tests-244%20passing-brightgreen) -->
<!-- ![Python](https://img.shields.io/badge/python-3.12%2B-blue) -->
<!-- ![License](https://img.shields.io/badge/license-proprietary-red) -->

---

## Features

| Category | Capabilities |
|---|---|
| **Real-time monitoring** | inotify file watcher, process tree monitor, behavior lifecycle tracking |
| **Multi-engine scanning** | Heuristic regex, Shannon entropy, YARA-X signatures, ClamAV (optional) |
| **Threat scoring** | Aggregated score per event with configurable log/quarantine/suspend thresholds |
| **Automated response** | Quarantine, process kill, IP blocking via nftables/iptables |
| **Brute-force protection** | SSH + mail (Dovecot/Postfix/Exim/Stalwart) with progressive blocking |
| **WAF integration** | ModSecurity audit log parsing, OWASP CRS management, rule toggling |
| **Proactive defense** | PHP-FPM pool hardening (disable_functions, open_basedir), process killer |
| **Malware cleanup** | Injection removal, CMS integrity checks (WordPress/Joomla), backup-before-clean |
| **Threat intelligence** | Spamhaus, blocklist.de, MalwareBazaar, Tor exit nodes; IP + hash lookups |
| **WebShield** | Nginx rate limiting, JS challenge pages, bot UA filtering |
| **Database scanning** | MySQL table scanning for injected payloads (WordPress, Joomla) |
| **RapidScan** | Parallel directory scanner with mtime cache for unchanged-file skipping |
| **Scheduled scans** | Configurable periodic full-path scanning |
| **Multi-tenant** | Automatic file-to-user mapping for shared hosting accounts |
| **Web dashboard** | Flask UI on port 8443 with feature toggles, incident browser, scan UI |
| **REST API** | aiohttp on port 9876 with API key auth, 40+ endpoints |
| **CLI** | 30+ click commands for full management |

## Quick Install

```bash
curl -fsSL https://git.linux-hosting.co.il/shukivaknin/jabali-security/raw/branch/master/install.sh | sudo bash
```

The installer will: clone the repo, create a Python venv, install dependencies, generate an API key, configure systemd services, and raise the inotify watch limit.

```bash
jabali-security status              # check daemon status
jabali-security config test         # verify configuration
jabali-security scan /home -r       # on-demand recursive scan
journalctl -u jabali-security -f    # watch live logs
```

<!-- screenshot placeholder -->
<!-- ![Dashboard](docs/images/dashboard.png) -->

## Architecture

```
                        +-------------------+
                        |   Web Dashboard   |  (Flask + Waitress, :8443)
                        +--------+----------+
                                 |
+------------------+    +--------+----------+    +------------------+
| File Watcher     +--->|                   +--->| Response Engine  |
| (inotify)        |    |                   |    | - Quarantine     |
+------------------+    |   Scan Queue      |    | - Process kill   |
                        |       |           |    | - IP block       |
+------------------+    |   Scan Workers    |    | - Notifications  |
| Process Monitor  +--->|       |           |    +------------------+
| (/proc polling)  |    |   Detection       |
+------------------+    |   - Heuristic     |    +------------------+
                        |   - Entropy       +--->| Incident Store   |
+------------------+    |   - YARA-X        |    | (SQLite)         |
| Behavior Tracker +--->|   - ClamAV        |    +------------------+
|                  |    |       |           |
+------------------+    |   Scoring Engine  |    +------------------+
                        |                   +--->| REST API         |
+------------------+    +-------------------+    | (aiohttp, :9876) |
| Auth Log Parser  |                             +------------------+
| (SSH/Mail/Stalw) +---> Brute-Force Detector ---> Firewall Manager
+------------------+                               (nftables/iptables)

+------------------+    +-------------------+    +------------------+
| ModSec Audit Log +--->| WAF Rule Manager  |    | Threat Intel     |
+------------------+    +-------------------+    | Feed Manager     |
                                                 +------------------+
+------------------+    +-------------------+
| PHP-FPM Hardener |    | WebShield Manager |    (nginx config gen)
+------------------+    +-------------------+
```

## Requirements

- Linux with kernel 2.6.13+ (inotify support)
- Python 3.12+
- systemd (for service management)
- Optional: ClamAV, nftables/iptables, nginx, ModSecurity + OWASP CRS

## CLI Reference

Full command reference: [docs/CLI.md](docs/CLI.md)

| Group | Commands |
|---|---|
| **Daemon** | `start`, `stop`, `status` |
| **Scanning** | `scan`, `scan-full`, `scan-db`, `scan-rapid` |
| **Incidents** | `incidents list` |
| **Quarantine** | `quarantine list`, `quarantine restore`, `quarantine delete` |
| **Config** | `config show`, `config set`, `config test` |
| **Rules** | `rules list`, `rules update` |
| **Users** | `user list`, `user risk` |
| **IP Blocking** | `block`, `unblock`, `blocklist` |
| **Brute-Force** | `bruteforce stats`, `bruteforce blocked`, `bruteforce whitelist-add`, `bruteforce whitelist-remove` |
| **WAF** | `waf events`, `waf rules`, `waf disable`, `waf enable`, `waf stats`, `waf update` |
| **Proactive** | `proactive status`, `proactive php-pools`, `proactive harden`, `proactive unharden`, `proactive kills` |
| **Cleanup** | `cleanup records`, `cleanup file`, `cleanup cms` |
| **Threat Intel** | `threat-intel feeds`, `threat-intel update`, `threat-intel check-ip`, `threat-intel check-hash` |
| **WebShield** | `webshield status`, `webshield install`, `webshield uninstall`, `webshield rules` |
| **Web** | `web` |

## REST API

Base URL: `http://127.0.0.1:9876/api/v1/`
Authentication: `X-API-Key` header.
Full reference: [docs/API.md](docs/API.md)

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/status` | GET | Daemon status and stats |
| `/incidents` | GET | List incidents |
| `/incidents/{id}` | GET | Get incident detail |
| `/scan` | POST | On-demand file scan |
| `/quarantine` | GET | List quarantined files |
| `/users` | GET | User risk scores |
| `/blocklist` | GET | Blocked IPs |
| `/config` | GET/PATCH | Configuration |
| `/bruteforce/*` | GET/POST/DELETE | Brute-force management |
| `/waf/*` | GET/POST | WAF events and rules |
| `/proactive/*` | GET/POST | Proactive defense |
| `/cleanup/*` | GET/POST | Cleanup operations |
| `/threat-intel/*` | GET/POST | Threat intelligence |
| `/webshield/*` | GET/POST | WebShield management |
| `/scan/database` | POST | MySQL database scan |
| `/scan/rapid` | POST | Fast parallel scan |

## Web Dashboard

Served by Waitress on port 8443 (configurable). Login uses the API key as the password.

Pages: Dashboard overview, Incidents, Quarantine, Scan, Users, Blocklist, WAF, Brute-force, Proactive Defense, Cleanup, Threat Intel, WebShield, Config, Rules.

Features: real-time stats, feature enable/disable toggles, incident drill-down, one-click quarantine restore, config editor.

## Configuration

Config file: `/etc/jabali-security/jabali-security.conf`
Format: `KEY="value"` (one per line, `#` comments).

See [`etc/jabali-security.conf.example`](etc/jabali-security.conf.example) for all options with descriptions.
Full reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

## Development

```bash
uv sync                                    # install dependencies
uv run jabali-security start --foreground  # run daemon locally
uv run pytest tests/ -v                    # run 244 tests (~0.25s)
uv run ruff check .                        # lint
```

Full developer guide: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)

## Testing

```bash
uv run pytest tests/ -v
```

244 unit tests covering: config parsing, heuristic/entropy/YARA scanners, scoring engine, incident store, quarantine, response engine, behavior tracker, brute-force detection, IP reputation, log parsing, WebShield config, CMS detection, injection cleaning, and security hardening.

## Uninstall

```bash
sudo bash install.sh --uninstall
```

Completely removes the application, config, data, logs, and quarantine.

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | System design, components, data flow, database schema |
| [API Reference](docs/API.md) | Full REST API documentation |
| [CLI Reference](docs/CLI.md) | All CLI commands with usage and examples |
| [Configuration](docs/CONFIGURATION.md) | Every config key with type, default, and description |
| [Development](docs/DEVELOPMENT.md) | Developer setup, project structure, how to extend |

## License

Proprietary
