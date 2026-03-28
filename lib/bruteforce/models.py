"""Brute-force protection data models."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hex_id() -> str:
    return uuid.uuid4().hex[:16]


class AuthEvent(BaseModel):
    id: str = Field(default_factory=_hex_id)
    timestamp: datetime = Field(default_factory=_utcnow)
    ip: str
    service: str          # "ssh", "dovecot", "exim", "postfix"
    username: str = ""
    success: bool = False
    raw_line: str = ""


class BlockDecision(BaseModel):
    ip: str
    duration: int         # seconds, 0=permanent
    reason: str
    service: str
    attempt_count: int
    offense_number: int
