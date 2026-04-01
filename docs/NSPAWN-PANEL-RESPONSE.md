# Panel Response: Nspawn Migration

Response to `NSPAWN-MIGRATION.md` from the panel side.

## Current Panel Implementation

The panel agent (`bin/jabali-agent`) has its own `ssh.enable_shell` / `ssh.disable_shell` actions that manage shell users directly:

- Moves user between `sftpusers` ↔ `shellusers` groups
- Sets login shell to `/usr/local/bin/jabali-shell` (enable) or `/usr/sbin/nologin` (disable)
- Owns home directory to `user:user` (enable) or `root:user` (disable)
- Creates dotfile dirs (`.vscode-server`, `.ssh`, `.local`, `.cache`, `.config`)
- Starts nspawn container via `jabali-isolate start`
- Has its own `/var/jail` cleanup in the migration action

The panel's `install.sh` also writes the sshd_config `Match Group shellusers` block with `ForceCommand /usr/local/bin/jabali-shell`.

## Conflicts to Resolve

### 1. Login Shell Path

| System | Enable shell | Disable shell |
|--------|-------------|--------------|
| Panel agent | `/usr/local/bin/jabali-shell` | `/usr/sbin/nologin` |
| jabali-security | `/bin/bash` | `/usr/sbin/nologin` |

Since `ForceCommand` in sshd_config overrides the login shell for SSH, the value in `/etc/passwd` doesn't affect SSH behavior. But the two systems shouldn't fight over it.

**Resolution:** Panel will stop setting the login shell. `ForceCommand` handles routing. jabali-security can set `/bin/bash` or whatever it wants — it doesn't matter.

### 2. ForceCommand Path

| System | sshd_config |
|--------|------------|
| Panel install.sh | `ForceCommand /usr/local/bin/jabali-shell` |
| jabali-security | `ForceCommand jabali-shell` |

Both work (jabali-shell is in PATH), but should be consistent.

**Resolution:** Panel will use the full path `/usr/local/bin/jabali-shell`. jabali-security should match. Full path is safer — avoids PATH issues in restricted SSH contexts.

### 3. Dual /var/jail Cleanup

Both the panel's `sshMigrateShellUsers` agent action and jabali-security's update command clean up `/var/jail`.

**Resolution:** Both are idempotent, so running both is harmless. Panel cleanup stays as a safety net — it handles cases where jabali-security isn't installed yet or hasn't been updated.

### 4. Who Owns What

Per the doc: "The panel should continue calling jabali-security's API for group management, and handle container lifecycle (nspawn) on its own side."

Current panel does NOT call jabali-security's API. The agent manages groups directly via `usermod`/`gpasswd`. This works and avoids an HTTP dependency on jabali-security being running.

**Resolution:** Panel keeps direct group management. Both the panel and jabali-security are root-level processes managing the same system users — having two paths to the same result is fine as long as the operations are idempotent (they are). The panel will not add a dependency on jabali-security's HTTP API for core SSH functionality.

### 5. Install Order

jabali-isolator must exist before jabali-security writes `ForceCommand jabali-shell` to sshd_config.

Panel's `install.sh` already installs jabali-isolator before calling `configure_sshd()`. Order is correct.

For jabali-security updates on existing servers: the panel's `upgrade_infra()` runs `install_jabali_shell()` (which installs the wrapper) before `jabali-security update`. Order is correct.

## Panel Changes Required

1. **Remove `usermod -s` from `sshEnableShell`** — ForceCommand handles routing, no need to set login shell
2. **Remove `usermod -s` from `sshDisableShell`** — let jabali-security own the shell field
3. **Keep everything else** — group management, home ownership, dotfile dirs, container lifecycle, /var/jail cleanup

## No Changes Required

- `SSHJAIL_JAIL_DIR` — not referenced anywhere in the panel
- API endpoints — panel doesn't call jabali-security's SSH API
- sshd_config format — panel uses full path, jabali-security should match
