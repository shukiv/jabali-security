"""Safe subprocess wrappers — all use list args, never shell=True."""

from __future__ import annotations

import asyncio


def _validate_path(path: str) -> None:
    """Reject paths with null bytes to prevent injection."""
    if "\x00" in path:
        raise ValueError("Path contains null byte")


async def get_mime_type(path: str) -> str | None:
    """Run ``file --mime-type -b <path>`` and return the MIME string."""
    _validate_path(path)
    try:
        proc = await asyncio.create_subprocess_exec(
            "file", "--mime-type", "-b", path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0 and stdout:
            result = stdout.decode().strip()
            # Validate it looks like a MIME type (type/subtype)
            if "/" in result and not result.startswith("cannot"):
                return result
    except OSError:
        pass
    return None


async def run_freshclam() -> tuple[bool, str]:
    """Run ``freshclam --quiet`` and return (success, output)."""
    from lib.privilege import sudo_prefix
    cmd = [*sudo_prefix(), "freshclam", "--quiet"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode() if stdout else ""
        return (proc.returncode == 0, output)
    except OSError as exc:
        return (False, str(exc))


