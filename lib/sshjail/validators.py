"""SSH jail input validators -- allowlist-based, no injection possible."""
from __future__ import annotations

import re

VALID_KEY_TYPES = frozenset({"ed25519", "rsa"})
VALID_KEY_PREFIXES = ("ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-")

_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_KEY_NAME_RE = re.compile(r"^[\x20-\x7E]+$")
_KEY_ID_RE = re.compile(r"^[a-f0-9]{32}$")


_BLOCKED_USERS = frozenset({"root", "admin"})


def validate_username(s: str) -> str:
    """Validate a Linux username. Returns cleaned string or raises ValueError."""
    cleaned = s.strip()
    if not cleaned:
        raise ValueError("Username must not be empty")
    if not _USERNAME_RE.match(cleaned):
        raise ValueError("Invalid username format")
    if cleaned in _BLOCKED_USERS:
        raise ValueError("Privileged user is not allowed")
    return cleaned


def validate_key_name(s: str) -> str:
    """Validate an SSH key name. Returns stripped string or raises ValueError."""
    cleaned = s.strip()
    if not cleaned:
        raise ValueError("Key name must not be empty")
    if len(cleaned) > 50:
        raise ValueError("Key name must be 50 characters or fewer")
    if not _KEY_NAME_RE.match(cleaned):
        raise ValueError("Key name must contain only printable ASCII characters")
    if ":" in cleaned:
        raise ValueError("Key name must not contain colons")
    return cleaned


def validate_public_key(s: str) -> str:
    """Validate an SSH public key. Returns stripped string or raises ValueError."""
    cleaned = s.strip()
    if not cleaned:
        raise ValueError("Public key must not be empty")
    # Reject newlines/nulls to prevent authorized_keys injection
    if "\n" in cleaned or "\r" in cleaned or "\0" in cleaned:
        raise ValueError("Public key must not contain newline or null characters")
    if not any(cleaned.startswith(prefix) for prefix in VALID_KEY_PREFIXES):
        raise ValueError(
            "Public key must start with ssh-rsa, ssh-ed25519, ssh-dss, or ecdsa-sha2-"
        )
    parts = cleaned.split()
    if len(parts) < 2:
        raise ValueError("Public key must have at least 2 space-separated parts")
    return cleaned


def validate_key_type(s: str) -> str:
    """Validate an SSH key type. Returns lowercase string or raises ValueError."""
    cleaned = s.strip().lower()
    if cleaned not in VALID_KEY_TYPES:
        raise ValueError("Key type must be one of: ed25519, rsa")
    return cleaned


def validate_key_id(s: str) -> str:
    """Validate an SSH key ID (hex string). Returns cleaned string or raises ValueError."""
    cleaned = s.strip().lower()
    if not _KEY_ID_RE.match(cleaned):
        raise ValueError("Key ID must be a 32-character hex string")
    return cleaned
