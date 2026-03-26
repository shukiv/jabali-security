"""Cleanup data models."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CleanupResult(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: datetime = Field(default_factory=_utcnow)
    path: str
    strategy: str          # "cms_wordpress", "cms_joomla", "injection_removal", "quarantine_fallback"
    success: bool
    backup_path: str = ""
    changes_made: list[str] = Field(default_factory=list)
    error: str = ""
    username: str | None = None


class DBFinding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    database: str
    table: str
    column: str
    row_id: str = ""
    payload_type: str      # "script_injection", "spam_link", "base64_payload", "rogue_admin"
    payload_preview: str = ""
    cleaned: bool = False


class ScheduledScan(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    paths: list[str]
    interval_hours: int = 24
    time_of_day: str = "03:00"
    last_run: datetime | None = None
    next_run: datetime | None = None
    enabled: bool = True
    files_scanned: int = 0
    threats_found: int = 0
