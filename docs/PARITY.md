# Interface Parity Rules

Jabali Security has two interfaces that must maintain feature parity:

- **Web Dashboard** — standalone Flask app on port 8443 (`web/`)
- **Jabali Panel Plugin** — Filament plugin for the hosting panel (`panel/`)

## Rule

Every feature available in the web dashboard must have an equivalent in the Jabali Panel plugin. If a server admin can do it in the web dashboard, they must be able to do it in the panel.

---

## Feature Matrix

### Pages & Data Views

| Feature | Web Dashboard | Panel Plugin | Status |
|---------|:---:|:---:|--------|
| Dashboard stats (incidents, quarantine, dirs, workers, memory, queue) | Yes | Yes | Parity |
| Daemon status (version, uptime, memory, workers) | Yes | Yes | Parity |
| Incidents list with severity, score, action, timestamp | Yes | Yes | Parity |
| Quarantine list with restore/delete | Yes | Yes | Parity |
| IP Blocklist with block/unblock | Yes | Yes | Parity |
| UFW Firewall rules with add/delete/enable/disable | Yes | Yes | Parity |
| Configuration editor (view/edit all keys) | Yes | Yes | Parity |
| WAF events table + stats | Yes | Yes | Parity |
| WAF rule files + disable/enable rules | Yes | Yes | Parity |
| Brute-Force stats + blocked IPs | Yes | Yes | Parity |
| Brute-Force whitelist management | Yes | Yes | Parity |
| Proactive Defense status | Yes | Yes | Parity |
| PHP-FPM pool hardening status | Yes | Yes | Parity |
| Process kills log | Yes | Yes | Parity |
| WebShield status + bot rules | Yes | Yes | Parity |
| WebShield install/uninstall | Yes | Yes | Parity |
| Cleanup records | Yes | Yes | Parity |
| Threat Intelligence feeds + update | Yes | Yes | Parity |
| Threat Intel IP/hash check | Yes | Yes | Parity |
| YARA/ClamAV rules list | Yes | Yes | Parity |
| Scan (on-demand) | Yes | Yes | Parity |
| Users list with incident counts | Yes | Yes | Parity |
| User detail (incidents + quarantine) | Yes | Yes | Parity |

### Module Toggles (Enable/Disable)

| Toggle | Web Dashboard | Panel Plugin | Status |
|--------|:---:|:---:|--------|
| Heuristic Scanner | Yes | Yes | Parity |
| Entropy Scanner | Yes | Yes | Parity |
| YARA-X Rules | Yes | Yes | Parity |
| Process Monitor | Yes | Yes | Parity |
| Behavior Tracking | Yes | Yes | Parity |
| Auto Quarantine | Yes | Yes | Parity |
| WAF (ModSecurity) | Yes | Yes | Parity |
| Brute-Force Protection | Yes | Yes | Parity |
| Proactive Defense | Yes | Yes | Parity |
| Process Killer | Yes | Yes | Parity |
| PHP Hardening | Yes | Yes | Parity |
| WebShield | Yes | Yes | Parity |
| Threat Intelligence | Yes | Yes | Parity |
| Auto Cleanup | Yes | Yes | Parity |
| UFW Firewall | Yes | Yes | Parity |
| Scheduled Scans | Yes | Yes | Parity |
| Auto Suspend | Yes | Yes | Parity |

### Actions

| Action | Web Dashboard | Panel Plugin | Status |
|--------|:---:|:---:|--------|
| Resolve incident (with notes) | Yes | Yes | Parity |
| Restore quarantined file | Yes | Yes | Parity |
| Delete quarantined file | Yes | Yes | Parity |
| Block IP (with reason/duration) | Yes | Yes | Parity |
| Unblock IP | Yes | Yes | Parity |
| Add UFW rule | Yes | Yes | Parity |
| Delete UFW rule | Yes | Yes | Parity |
| Enable/Disable UFW | Yes | Yes | Parity |
| Run on-demand scan | Yes | Yes | Parity |
| Reload YARA rules + freshclam | Yes | Yes | Parity |
| Update threat intel feeds | Yes | Yes | Parity |
| Install/uninstall WebShield | Yes | Yes | Parity |
| Harden/unharden PHP pool | Yes | Yes | Parity |
| WAF rule disable | Yes | Yes | Parity |
| Update OWASP CRS | Yes | Yes | Parity |
| Check IP reputation | Yes | Yes | Parity |
| Clean file | Yes | Yes | Parity |

All features have reached parity as of 2026-03-28.

---

## Implementation Notes

- Both interfaces use **grouped navigation** — 14+ features are organized into 5 logical groups:
  1. **Overview/Dashboard** — stats + module toggles
  2. **Threats** — Incidents, Quarantine, Scan (web only), Cleanup
  3. **Defense** — Blocklist, Firewall, WAF, Brute-Force, WebShield
  4. **Intelligence** — Users, Threat Intel, Rules
  5. **Settings** — Proactive, Config
- Panel plugin uses **Filament Tabs** with grouped tab structure on the Security page
- Web dashboard uses a **grouped sidebar** matching the same 5 groups
- All data comes from the **REST API** (Unix socket) — no direct database access
- API client: `panel/JabaliSecurityClient.php` wraps all HTTP calls
- After updating panel plugin code, **restart `jabali-panel` service** (FrankenPHP caches PHP in worker mode)
- Module toggles require writing to `/etc/jabali-security/jabali-security.conf` and restarting the daemon
- The web dashboard serves as the **reference implementation** — when adding a feature to the panel, match the web dashboard's behavior
- **Filament components only** — the panel plugin must NEVER use custom HTML, CSS, or inline styles. Only use Filament's built-in components (StatsOverviewWidget, Section, Table, Action, Tabs, Button, etc.). Consult Filament v5 docs when unsure.

---

## When Adding New Features

1. Add the feature to the **web dashboard** first (Flask templates + routes)
2. Add the corresponding **API endpoint** if needed
3. Add the feature to the **panel plugin** (Filament tab/action)
4. Update this **parity matrix** to reflect the new feature
5. Update `docs/API.md` if new endpoints were added
