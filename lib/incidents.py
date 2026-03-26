"""SQLite incident store for persistent incident tracking."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import aiosqlite

from lib.models import Incident, QuarantineRecord

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    username TEXT,
    event_type TEXT NOT NULL,
    total_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    file_event_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    notes TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(username);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);

CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    username TEXT,
    sha256 TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    restored INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    blocked_at TEXT NOT NULL,
    expires_at TEXT,
    blocked_by TEXT DEFAULT 'auto'
);

CREATE TABLE IF NOT EXISTS waf_events (
    id TEXT PRIMARY KEY,
    client_ip TEXT NOT NULL,
    uri TEXT NOT NULL,
    method TEXT NOT NULL,
    rule_id INTEGER,
    rule_msg TEXT,
    severity TEXT,
    action TEXT,
    hostname TEXT,
    username TEXT,
    matched_data TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_waf_events_ip ON waf_events(client_ip);
CREATE INDEX IF NOT EXISTS idx_waf_events_created ON waf_events(created_at);
"""


class IncidentStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def open(self) -> None:
        """Open database and create schema."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def save(self, incident: Incident) -> None:
        """Insert or update an incident."""
        assert self._db is not None  # noqa: S101
        await self._db.execute(
            """INSERT OR REPLACE INTO incidents
               (id, path, username, event_type, total_score, severity, action_taken,
                findings_json, file_event_json, created_at, resolved, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident.id,
                incident.file_event.path,
                incident.username,
                incident.file_event.event_type,
                incident.total_score,
                incident.severity,
                incident.action_taken,
                json.dumps([f.model_dump() for f in incident.findings]),
                incident.file_event.model_dump_json(),
                incident.timestamp.isoformat(),
                int(incident.resolved),
                incident.notes,
            ),
        )
        await self._db.commit()

    async def save_quarantine(self, record: QuarantineRecord) -> None:
        """Insert a quarantine record."""
        assert self._db is not None  # noqa: S101
        await self._db.execute(
            """INSERT OR REPLACE INTO quarantine
               (id, incident_id, original_path, quarantine_path, username, sha256,
                reason, created_at, restored, deleted)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.id,
                record.incident_id,
                record.original_path,
                record.quarantine_path,
                record.username,
                record.sha256,
                record.reason,
                record.timestamp.isoformat(),
                int(record.restored),
                int(record.deleted),
            ),
        )
        await self._db.commit()

    async def get(self, incident_id: str) -> Incident | None:
        """Get a single incident by ID."""
        assert self._db is not None  # noqa: S101
        async with self._db.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return self._row_to_incident(row, cursor.description)

    async def list_incidents(
        self,
        limit: int = 50,
        username: str | None = None,
        severity: str | None = None,
        since: str | None = None,
    ) -> list[Incident]:
        """List incidents with optional filters."""
        assert self._db is not None  # noqa: S101
        conditions: list[str] = []
        params: list[str | int] = []

        if username:
            conditions.append("username = ?")
            params.append(username)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if since:
            conditions.append("created_at >= ?")
            params.append(since)

        where = " AND ".join(conditions)
        query = "SELECT * FROM incidents"
        if where:
            query += " WHERE " + where
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        results: list[Incident] = []
        async with self._db.execute(query, params) as cursor:
            async for row in cursor:
                incident = self._row_to_incident(row, cursor.description)
                if incident:
                    results.append(incident)
        return results

    async def count_recent(self, hours: int = 24) -> int:
        """Count incidents in the last N hours."""
        assert self._db is not None  # noqa: S101
        async with self._db.execute(
            "SELECT COUNT(*) FROM incidents WHERE created_at >= datetime('now', ?)",
            ("-%d hours" % hours,),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def resolve(self, incident_id: str, notes: str = "") -> bool:
        """Mark an incident as resolved."""
        assert self._db is not None  # noqa: S101
        cursor = await self._db.execute(
            "UPDATE incidents SET resolved = 1, notes = ? WHERE id = ?",
            (notes, incident_id),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def list_quarantine(self, username: str | None = None) -> list[QuarantineRecord]:
        """List quarantine records."""
        assert self._db is not None  # noqa: S101
        if username:
            query = "SELECT * FROM quarantine WHERE username = ? AND deleted = 0 ORDER BY created_at DESC"
            params: tuple = (username,)
        else:
            query = "SELECT * FROM quarantine WHERE deleted = 0 ORDER BY created_at DESC"
            params = ()

        results: list[QuarantineRecord] = []
        async with self._db.execute(query, params) as cursor:
            async for row in cursor:
                record = self._row_to_quarantine(row, cursor.description)
                if record:
                    results.append(record)
        return results

    async def mark_quarantine_restored(self, record_id: str) -> bool:
        assert self._db is not None  # noqa: S101
        cursor = await self._db.execute(
            "UPDATE quarantine SET restored = 1 WHERE id = ?", (record_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def mark_quarantine_deleted(self, record_id: str) -> bool:
        assert self._db is not None  # noqa: S101
        cursor = await self._db.execute(
            "UPDATE quarantine SET deleted = 1 WHERE id = ?", (record_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    @staticmethod
    def _row_to_incident(row, description) -> Incident | None:
        """Convert a database row to an Incident model."""
        try:
            cols = [d[0] for d in description]
            data = dict(zip(cols, row))
            from lib.models import FileEvent, Finding

            file_event = FileEvent.model_validate_json(data["file_event_json"])
            findings = [Finding.model_validate(f) for f in json.loads(data["findings_json"])]
            return Incident(
                id=data["id"],
                file_event=file_event,
                findings=findings,
                total_score=data["total_score"],
                severity=data["severity"],
                action_taken=data["action_taken"],
                username=data["username"],
                resolved=bool(data["resolved"]),
                notes=data["notes"] or "",
            )
        except Exception:
            logger.exception("Failed to deserialize incident row")
            return None

    @staticmethod
    def _row_to_quarantine(row, description) -> QuarantineRecord | None:
        """Convert a database row to a QuarantineRecord model."""
        try:
            cols = [d[0] for d in description]
            data = dict(zip(cols, row))
            return QuarantineRecord(
                id=data["id"],
                original_path=data["original_path"],
                quarantine_path=data["quarantine_path"],
                username=data["username"],
                reason=data["reason"],
                incident_id=data["incident_id"],
                sha256=data["sha256"],
                restored=bool(data["restored"]),
                deleted=bool(data["deleted"]),
            )
        except Exception:
            logger.exception("Failed to deserialize quarantine row")
            return None
