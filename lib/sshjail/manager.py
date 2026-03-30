"""SSH jail manager."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import pwd
import shutil
import tempfile
import time

from lib.sshjail.models import SshKey, SshKeyGenResult, SshUserStatus
from lib.sshjail.validators import (
    validate_key_id,
    validate_key_name,
    validate_key_type,
    validate_public_key,
    validate_username,
)

logger = logging.getLogger(__name__)


class SSHJailManager:
    def __init__(self, jail_dir: str = "/var/jail") -> None:
        self._jail_dir = jail_dir
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    async def list_keys(self, username: str) -> list[SshKey]:
        """Parse authorized_keys and return list of SshKey objects."""
        username = validate_username(username)
        ak_path = f"/home/{username}/.ssh/authorized_keys"

        if not os.path.isfile(ak_path):
            return []

        keys: list[SshKey] = []
        try:
            with open(ak_path, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    key_id = hashlib.md5(line.encode()).hexdigest()
                    parts = line.split()
                    key_type = parts[0] if parts else ""
                    fingerprint = hashlib.md5(
                        parts[1].encode() if len(parts) > 1 else b""
                    ).hexdigest()

                    # Extract name from jabali comment: # jabali:{name}:{timestamp}
                    name = ""
                    added_at = ""
                    for i, part in enumerate(parts):
                        if part == "#" and i + 1 < len(parts):
                            comment = " ".join(parts[i + 1 :])
                            if comment.startswith("jabali:"):
                                jabali_parts = comment.split(":")
                                if len(jabali_parts) >= 2:
                                    name = jabali_parts[1]
                                if len(jabali_parts) >= 3:
                                    added_at = jabali_parts[2]
                            break

                    keys.append(SshKey(
                        id=key_id,
                        name=name,
                        key_type=key_type,
                        fingerprint=fingerprint,
                        added_at=added_at,
                    ))
        except OSError as exc:
            logger.warning("Failed to read authorized_keys for %s: %s", username, exc)

        return keys

    async def add_key(self, username: str, name: str, public_key: str) -> SshKey:
        """Append a public key to the user's authorized_keys file."""
        username = validate_username(username)
        name = validate_key_name(name)
        public_key = validate_public_key(public_key)

        await self._verify_user(username)

        async with self._lock:
            pw = pwd.getpwnam(username)
            ssh_dir = f"/home/{username}/.ssh"
            ak_path = f"{ssh_dir}/authorized_keys"

            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
            os.chown(ssh_dir, pw.pw_uid, pw.pw_gid)

            timestamp = str(int(time.time()))
            entry = f"{public_key} # jabali:{name}:{timestamp}\n"

            key_id = hashlib.md5(entry.strip().encode()).hexdigest()

            with open(ak_path, "a") as fh:
                fh.write(entry)

            os.chmod(ak_path, 0o600)
            os.chown(ak_path, pw.pw_uid, pw.pw_gid)

        parts = public_key.split()
        fingerprint = hashlib.md5(
            parts[1].encode() if len(parts) > 1 else b""
        ).hexdigest()

        return SshKey(
            id=key_id,
            name=name,
            key_type=parts[0] if parts else "",
            fingerprint=fingerprint,
            added_at=timestamp,
        )

    async def delete_key(self, username: str, key_id: str) -> bool:
        """Remove a key from authorized_keys by its MD5 id."""
        username = validate_username(username)
        key_id = validate_key_id(key_id)

        await self._verify_user(username)

        ak_path = f"/home/{username}/.ssh/authorized_keys"

        async with self._lock:
            if not os.path.isfile(ak_path):
                return False

            try:
                with open(ak_path, "r") as fh:
                    lines = fh.readlines()
            except OSError as exc:
                logger.warning("Failed to read authorized_keys for %s: %s", username, exc)
                return False

            new_lines: list[str] = []
            found = False
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    new_lines.append(line)
                    continue
                if hashlib.md5(stripped.encode()).hexdigest() == key_id:
                    found = True
                    continue
                new_lines.append(line)

            if not found:
                return False

            pw = pwd.getpwnam(username)
            dir_name = os.path.dirname(ak_path)
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".authorized_keys.")
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.writelines(new_lines)
                os.chmod(tmp_path, 0o600)
                os.chown(tmp_path, pw.pw_uid, pw.pw_gid)
                os.rename(tmp_path, ak_path)
            except OSError:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

        return True

    async def generate_key(
        self, name: str, key_type: str, passphrase: str = ""
    ) -> SshKeyGenResult:
        """Generate an SSH key pair in a temp dir and return results in memory."""
        name = validate_key_name(name)
        key_type = validate_key_type(key_type)

        tmp_dir = tempfile.mkdtemp(prefix="jabali-keygen-")
        key_path = os.path.join(tmp_dir, "key")

        try:
            cmd = [
                "ssh-keygen",
                "-t", key_type,
                "-f", key_path,
                "-N", passphrase,
                "-C", name,
            ]
            rc, stdout, stderr = await self._run(cmd)
            if rc != 0:
                raise RuntimeError("ssh-keygen failed")

            with open(key_path, "r") as fh:
                private_key = fh.read()
            with open(f"{key_path}.pub", "r") as fh:
                public_key = fh.read().strip()

            # Extract fingerprint
            rc_fp, fp_out, _ = await self._run(
                ["ssh-keygen", "-lf", key_path]
            )
            fingerprint = ""
            if rc_fp == 0 and fp_out.strip():
                fp_parts = fp_out.strip().split()
                if len(fp_parts) >= 2:
                    fingerprint = fp_parts[1]

            # Try to generate PPK via puttygen
            ppk_key = ""
            if shutil.which("puttygen"):
                ppk_path = os.path.join(tmp_dir, "key.ppk")
                ppk_cmd = ["puttygen", key_path, "-o", ppk_path, "-O", "private"]
                rc_ppk, _, _ = await self._run(ppk_cmd)
                if rc_ppk == 0 and os.path.isfile(ppk_path):
                    with open(ppk_path, "r") as fh:
                        ppk_key = fh.read()

            return SshKeyGenResult(
                name=name,
                key_type=key_type,
                private_key=private_key,
                public_key=public_key,
                ppk_key=ppk_key,
                fingerprint=fingerprint,
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # sshd_config management
    # ------------------------------------------------------------------

    _SSHD_CONFIG = "/etc/ssh/sshd_config"

    # Settings we manage, with their sshd_config key and default value
    _SSHD_SETTINGS = {
        "password_auth": ("PasswordAuthentication", True),
        "pubkey_auth": ("PubkeyAuthentication", True),
        "port": ("Port", 22),
    }

    async def get_sshd_settings(self) -> dict:
        """Read managed settings from sshd_config."""
        defaults = {k: v[1] for k, v in self._SSHD_SETTINGS.items()}
        result = dict(defaults)

        try:
            with open(self._SSHD_CONFIG, "r") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    parts = stripped.split()
                    if len(parts) < 2:
                        continue
                    key_lower = parts[0].lower()
                    for name, (sshd_key, _default) in self._SSHD_SETTINGS.items():
                        if key_lower == sshd_key.lower():
                            if isinstance(_default, bool):
                                result[name] = parts[1].lower() == "yes"
                            elif isinstance(_default, int):
                                try:
                                    result[name] = int(parts[1])
                                except ValueError:
                                    pass
        except OSError as exc:
            logger.warning("Failed to read sshd_config: %s", exc)

        return result

    async def set_sshd_settings(self, settings: dict) -> bool:
        """Update sshd_config settings and reload sshd.

        Accepts a dict with keys: password_auth (bool), pubkey_auth (bool), port (int).
        Only provided keys are updated; omitted keys are left unchanged.
        """
        # Build key -> value map for the settings to write
        updates: dict[str, str] = {}
        for name, value in settings.items():
            if name not in self._SSHD_SETTINGS:
                continue
            sshd_key, default = self._SSHD_SETTINGS[name]
            if isinstance(default, bool):
                updates[sshd_key] = "yes" if value else "no"
            elif isinstance(default, int):
                updates[sshd_key] = str(value)

        if not updates:
            return True

        # PasswordAuthentication must be updated in Match blocks too,
        # otherwise sshd uses its default (yes) inside them.
        match_block_keys = {"PasswordAuthentication"}

        async with self._lock:
            try:
                with open(self._SSHD_CONFIG, "r") as fh:
                    lines = fh.readlines()
            except OSError as exc:
                logger.error("Failed to read sshd_config: %s", exc)
                return False

            applied: set[str] = set()
            new_lines: list[str] = []
            for line in lines:
                stripped = line.strip()
                # Match both active and commented-out directives
                parts = stripped.lstrip("#").strip().split()
                if len(parts) >= 2:
                    replaced = False
                    for sshd_key, new_val in updates.items():
                        if parts[0].lower() == sshd_key.lower():
                            # For match-block keys, replace ALL occurrences
                            # For other keys, replace only the first (global) one
                            if sshd_key in match_block_keys or sshd_key not in applied:
                                indent = line[: len(line) - len(line.lstrip())]
                                new_lines.append(f"{indent}{sshd_key} {new_val}\n")
                                applied.add(sshd_key)
                                replaced = True
                                break
                    if not replaced:
                        new_lines.append(line)
                else:
                    new_lines.append(line)

            # Append any settings not found in the file
            for sshd_key, new_val in updates.items():
                if sshd_key not in applied:
                    new_lines.append(f"{sshd_key} {new_val}\n")

            # Atomic write
            fd, tmp_path = tempfile.mkstemp(
                dir="/etc/ssh", prefix=".sshd_config.jabali."
            )
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.writelines(new_lines)
                os.chmod(tmp_path, 0o600)
                os.rename(tmp_path, self._SSHD_CONFIG)
            except OSError:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

        # Validate config before reloading
        rc, _, stderr = await self._run(["sshd", "-t"])
        if rc != 0:
            logger.error("sshd config test failed: %s", stderr)
            return False

        # Reload sshd
        rc, _, _ = await self._run(["systemctl", "reload", "sshd"])
        if rc != 0:
            # Try ssh service name (Debian/Ubuntu)
            rc, _, _ = await self._run(["systemctl", "reload", "ssh"])

        return rc == 0

    # ------------------------------------------------------------------
    # Shell management
    # ------------------------------------------------------------------

    async def shell_status(self, username: str) -> SshUserStatus:
        """Check user's shell and group membership."""
        username = validate_username(username)

        rc, stdout, _ = await self._run(["getent", "passwd", username])
        if rc != 0:
            raise ValueError(f"User {username!r} does not exist")

        fields = stdout.strip().split(":")
        shell = fields[6] if len(fields) > 6 else ""

        rc_groups, groups_out, _ = await self._run(["id", "-Gn", username])
        groups: list[str] = []
        if rc_groups == 0:
            groups = groups_out.strip().split()

        shell_enabled = "shellusers" in groups
        sftp_only = "sftpusers" in groups

        return SshUserStatus(
            username=username,
            shell=shell,
            shell_enabled=shell_enabled,
            sftp_only=sftp_only,
            groups=groups,
        )

    async def enable_shell(self, username: str) -> bool:
        """Enable shell access for user: add to shellusers, remove from sftpusers, set bash."""
        username = validate_username(username)
        await self._verify_user(username)

        async with self._lock:
            rc, stdout, stderr = await self._run(
                ["usermod", "-aG", "shellusers", username]
            )
            if rc != 0:
                logger.warning("Failed to add %s to shellusers (rc=%d): %s", username, rc, stderr)
                return False

            # Remove from sftpusers -- ignore error if not a member
            await self._run(["gpasswd", "-d", username, "sftpusers"])

            rc, _, _ = await self._run(
                ["usermod", "-s", "/bin/bash", username]
            )
            if rc != 0:
                logger.warning("Failed to set shell for %s", username)
                return False

            await self._setup_jail_home(username)
            await self._add_jail_user(username)

        return True

    async def disable_shell(self, username: str) -> bool:
        """Disable shell access: remove from shellusers, add to sftpusers, set nologin."""
        username = validate_username(username)
        await self._verify_user(username)

        async with self._lock:
            # Remove from shellusers -- ignore error if not a member
            await self._run(["gpasswd", "-d", username, "shellusers"])

            rc, _, _ = await self._run(
                ["usermod", "-aG", "sftpusers", username]
            )
            if rc != 0:
                logger.warning("Failed to add %s to sftpusers", username)
                return False

            rc, _, _ = await self._run(
                ["usermod", "-s", "/usr/sbin/nologin", username]
            )
            if rc != 0:
                logger.warning("Failed to set nologin for %s", username)
                return False

            await self._teardown_jail_home(username)
            await self._remove_jail_user(username)

        return True

    # ------------------------------------------------------------------
    # Jail home bind mount
    # ------------------------------------------------------------------

    async def _setup_jail_home(self, username: str) -> None:
        """Create jail home dir, add fstab bind mount entry, and mount."""
        jail_home = os.path.join(self._jail_dir, "home", username)
        real_home = f"/home/{username}"

        os.makedirs(jail_home, mode=0o755, exist_ok=True)
        # Ensure /tmp exists in jail (needed by PHP proc_open / wp-cli)
        os.makedirs(os.path.join(self._jail_dir, "tmp"), mode=0o1777, exist_ok=True)

        fstab_line = (
            f"{real_home} {jail_home} none bind 0 0"
            f" # jabali-ssh:{username}\n"
        )

        await self._add_fstab_entry(username, fstab_line)

        rc, _, _ = await self._run(
            ["mount", "--bind", real_home, jail_home]
        )
        if rc != 0:
            logger.warning("Failed to bind mount jail home for %s", username)

    async def _teardown_jail_home(self, username: str) -> None:
        """Unmount jail home, remove fstab entry, remove directory."""
        jail_home = os.path.join(self._jail_dir, "home", username)

        await self._run(["umount", jail_home])
        await self._remove_fstab_entry(username)

        try:
            os.rmdir(jail_home)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Jail passwd/group management
    # ------------------------------------------------------------------

    async def _add_jail_user(self, username: str) -> None:
        """Append user's passwd and group entries to jail etc files."""
        try:
            pw = pwd.getpwnam(username)
        except KeyError:
            logger.warning("User %s not found in passwd", username)
            return

        jail_passwd = os.path.join(self._jail_dir, "etc", "passwd")
        jail_group = os.path.join(self._jail_dir, "etc", "group")

        os.makedirs(os.path.join(self._jail_dir, "etc"), mode=0o755, exist_ok=True)

        passwd_line = (
            f"{pw.pw_name}:x:{pw.pw_uid}:{pw.pw_gid}:"
            f"{pw.pw_gecos}:{pw.pw_dir}:{pw.pw_shell}\n"
        )

        rc, group_out, _ = await self._run(
            ["getent", "group", str(pw.pw_gid)]
        )
        group_line = ""
        if rc == 0 and group_out.strip():
            group_line = group_out.strip() + "\n"

        await self._append_jail_file(jail_passwd, username, passwd_line)
        if group_line:
            await self._append_jail_file(jail_group, username, group_line)

    async def _remove_jail_user(self, username: str) -> None:
        """Remove user's entries from jail passwd and group files."""
        jail_passwd = os.path.join(self._jail_dir, "etc", "passwd")
        jail_group = os.path.join(self._jail_dir, "etc", "group")

        await self._filter_file(jail_passwd, username)
        await self._filter_file(jail_group, username)

    # ------------------------------------------------------------------
    # File helpers (atomic writes)
    # ------------------------------------------------------------------

    async def _add_fstab_entry(self, username: str, fstab_line: str) -> None:
        """Atomically add a bind mount entry to /etc/fstab."""
        fstab_path = "/etc/fstab"
        marker = f"# jabali-ssh:{username}"

        try:
            with open(fstab_path, "r") as fh:
                lines = fh.readlines()
        except OSError:
            lines = []

        # Don't add duplicate
        for line in lines:
            if marker in line:
                return

        lines.append(fstab_line)

        fd, tmp_path = tempfile.mkstemp(
            dir="/etc", prefix=".fstab.jabali."
        )
        try:
            with os.fdopen(fd, "w") as fh:
                fh.writelines(lines)
            os.chmod(tmp_path, 0o644)
            os.rename(tmp_path, fstab_path)
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    async def _remove_fstab_entry(self, username: str) -> None:
        """Atomically remove user's bind mount entry from /etc/fstab."""
        fstab_path = "/etc/fstab"
        marker = f"# jabali-ssh:{username}"

        try:
            with open(fstab_path, "r") as fh:
                lines = fh.readlines()
        except OSError:
            return

        new_lines = [line for line in lines if marker not in line]
        if len(new_lines) == len(lines):
            return

        fd, tmp_path = tempfile.mkstemp(
            dir="/etc", prefix=".fstab.jabali."
        )
        try:
            with os.fdopen(fd, "w") as fh:
                fh.writelines(new_lines)
            os.chmod(tmp_path, 0o644)
            os.rename(tmp_path, fstab_path)
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    async def _append_jail_file(
        self, path: str, username: str, entry: str
    ) -> None:
        """Atomically append an entry to a jail file, skipping duplicates."""
        try:
            with open(path, "r") as fh:
                lines = fh.readlines()
        except OSError:
            lines = []

        # Don't add duplicate -- check if username is the first field
        for line in lines:
            if line.split(":")[0] == username:
                return

        lines.append(entry)

        dir_name = os.path.dirname(path)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".jabali.")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.writelines(lines)
            os.chmod(tmp_path, 0o644)
            os.rename(tmp_path, path)
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    async def _filter_file(self, path: str, username: str) -> None:
        """Atomically remove lines for a given username from a colon-delimited file."""
        if not os.path.isfile(path):
            return

        try:
            with open(path, "r") as fh:
                lines = fh.readlines()
        except OSError:
            return

        new_lines = [
            line for line in lines if line.split(":")[0] != username
        ]
        if len(new_lines) == len(lines):
            return

        dir_name = os.path.dirname(path)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".jabali.")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.writelines(new_lines)
            os.chmod(tmp_path, 0o644)
            os.rename(tmp_path, path)
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _verify_user(self, username: str) -> None:
        """Verify that user exists and has UID >= 1000."""
        rc, stdout, _ = await self._run(["getent", "passwd", username])
        if rc != 0:
            raise ValueError(f"User {username!r} does not exist")

        fields = stdout.strip().split(":")
        if len(fields) < 3:
            raise ValueError(f"Malformed passwd entry for {username!r}")

        try:
            uid = int(fields[2])
        except ValueError:
            raise ValueError(f"Invalid UID for {username!r}")

        if uid < 1000:
            raise ValueError(f"System user {username!r} (UID {uid}) is not allowed")

    @staticmethod
    async def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
        """Run a command, return (exit_code, stdout, stderr). Never uses shell.

        Note: stdout/stderr may contain internal system details and must
        never be returned directly to API clients.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (
                proc.returncode or 0,
                stdout.decode(errors="replace"),
                stderr.decode(errors="replace"),
            )
        except asyncio.TimeoutError:
            logger.error("SSH jail command timed out: %s", cmd[0] if cmd else "?")
            proc.kill()
            await proc.wait()
            return (1, "", "Command timed out")
        except OSError as exc:
            logger.error("SSH jail command failed: %s -- %s", cmd[0] if cmd else "?", exc)
            return (1, "", "Command execution failed")
