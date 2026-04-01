# SSH Jail: Chroot to Nspawn Migration

## What Changed (jabali-security)

The old `/var/jail` chroot-based SSH jail has been completely removed from jabali-security. Shell users are now isolated via jabali-isolator's systemd-nspawn containers.

### sshd_config

**Before:**
```
Match Group shellusers
    ChrootDirectory /var/jail
```

**After:**
```
Match Group shellusers
    ForceCommand jabali-shell
```

The `sftpusers` Match block is unchanged (`ChrootDirectory /home/%u` + `ForceCommand internal-sftp`).

### Code Removed

- All `/var/jail` management: bind mounts, fstab entries, jail passwd/group files, device nodes, /proc mount, /tmp tmpfs, binary/library copying
- `SSHJAIL_JAIL_DIR` config key (was `/var/jail`)
- ~210 lines of Python chroot code from `lib/sshjail/manager.py`
- ~125 lines of shell setup code from `install.sh`

### What jabali-security Still Does

- SSH key CRUD (`authorized_keys` management)
- Shell/SFTP group membership (`shellusers` / `sftpusers`)
- Shell path (`/bin/bash` vs `/usr/sbin/nologin`)
- sshd_config settings (port, password auth, pubkey auth)
- API endpoints unchanged: `POST /ssh/shell/enable`, `POST /ssh/shell/disable`

### What jabali-security Does NOT Do Anymore

- No container/jail filesystem management
- No bind mounts or fstab entries
- No binary or library copying
- No device node creation
- No jail passwd/group files

---

## Action Items for Panel Team

### 1. Install Order (New Servers)

jabali-isolator (with `jabali-shell`) MUST be installed before jabali-security runs its SSH hardening. The install.sh now writes `ForceCommand jabali-shell` into sshd_config. If `jabali-shell` doesn't exist, shell users will get a connection error on SSH login.

### 2. Update Order (Existing Servers)

The jabali-security update command:
- Only migrates sshd_config if `jabali-shell` is found in PATH
- Automatically cleans up old `/var/jail` (unmounts, removes fstab entries, deletes directory)

Make sure jabali-isolator is updated/installed before jabali-security on existing servers.

### 3. Config Key Removed

`SSHJAIL_JAIL_DIR` no longer exists. If the panel references this key anywhere outside the Security plugin, remove those references. The Security plugin has already been updated.

### 4. API Compatibility

No API changes. The enable/disable shell endpoints work the same way. The panel should continue calling jabali-security's API for group management, and handle container lifecycle (nspawn) on its own side.

### 5. Old /var/jail Cleanup

The jabali-security update handles this automatically when `jabali-shell` is detected:
- Unmounts `/var/jail/proc`, `/var/jail/tmp`, user home bind mounts
- Removes fstab entries: `jabali-jail-proc`, `jabali-jail-tmp`, `jabali-ssh:*`
- Deletes `/var/jail` directory tree

If the panel installer also has cleanup code for `/var/jail`, coordinate to avoid conflicts.

---

## Flow After Migration

```
User SSHes in
    -> OpenSSH matches shellusers group
    -> ForceCommand jabali-shell
    -> jabali-shell detects interactive/command/SFTP
    -> Runs inside user's nspawn container (jabali-isolator)
```

jabali-security's role is limited to managing who is in `shellusers` vs `sftpusers` and their SSH keys.
