"""Version and path constants for jabali-security."""

from __future__ import annotations

import os
from pathlib import Path

VERSION = "0.1.0"
APP_NAME = "jabali-security"

_is_root = os.getuid() == 0

if _is_root:
    CONFIG_DIR = Path("/etc/jabali-security")
    LOG_DIR = Path("/var/log/jabali-security")
    DATA_DIR = Path("/var/lib/jabali-security")
    QUARANTINE_DIR = Path("/var/security/quarantine")
    RULES_DIR = Path("/usr/local/jabali-security/rules")
else:
    _base = Path.home() / ".config" / "jabali-security"
    CONFIG_DIR = _base
    LOG_DIR = _base / "logs"
    DATA_DIR = _base / "data"
    QUARANTINE_DIR = _base / "quarantine"
    RULES_DIR = _base / "rules"

CONFIG_FILE = CONFIG_DIR / "jabali-security.conf"
