"""Notification engine — email and webhook alerts for security incidents."""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
from email.message import EmailMessage

from lib.config import JabaliConfig
from lib.models import Incident

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class NotificationEngine:
    """Send notifications for security incidents via email and/or webhook."""

    def __init__(self, config: JabaliConfig) -> None:
        self._email = config.notify_email
        self._webhook = config.notify_webhook
        self._min_severity = config.notify_min_severity
        self._enabled = bool(self._email or self._webhook)
        if self._enabled:
            logger.info(
                "Notifications enabled: email=%s webhook=%s min_severity=%s",
                "yes" if self._email else "no",
                "yes" if self._webhook else "no",
                self._min_severity,
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _should_notify(self, severity: str) -> bool:
        """Check if severity meets minimum threshold."""
        return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(self._min_severity, 2)

    async def notify(self, incident: Incident) -> None:
        """Send notification for an incident if severity threshold met."""
        if not self._enabled:
            return
        if not self._should_notify(incident.severity):
            return

        tasks = []
        if self._email:
            tasks.append(self._send_email(incident))
        if self._webhook:
            tasks.append(self._send_webhook(incident))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.error("Notification error: %s", result)

    async def _send_email(self, incident: Incident) -> None:
        """Send email notification via SMTP (localhost:25 by default)."""
        msg = EmailMessage()
        msg["Subject"] = "[Jabali Security] %s: %s on %s" % (
            incident.severity.upper(),
            incident.action_taken,
            incident.file_event.path,
        )
        msg["From"] = "jabali-security@localhost"
        msg["To"] = self._email

        body_lines = [
            "Security Incident Detected",
            "=" * 40,
            "",
            "ID:        %s" % incident.id,
            "Severity:  %s" % incident.severity,
            "Score:     %d" % incident.total_score,
            "Action:    %s" % incident.action_taken,
            "Path:      %s" % incident.file_event.path,
            "User:      %s" % (incident.username or "unknown"),
            "Time:      %s" % incident.timestamp.isoformat(),
            "",
            "Findings:",
        ]
        for f in incident.findings[:10]:
            body_lines.append("  [%s] %s (score=%d) %s" % (f.scanner, f.rule, f.score, f.description))

        body_lines.extend([
            "",
            "---",
            "Jabali Security - https://jabali-panel.com",
        ])

        msg.set_content("\n".join(body_lines))

        # Send via local SMTP (non-blocking via executor)
        await asyncio.to_thread(self._smtp_send, msg)

    def _smtp_send(self, msg: EmailMessage) -> None:
        """Synchronous SMTP send — runs in executor."""
        try:
            with smtplib.SMTP("localhost", 25, timeout=10) as smtp:
                smtp.send_message(msg)
            logger.info("Email notification sent to %s", self._email)
        except (smtplib.SMTPException, OSError) as exc:
            logger.error("Failed to send email to %s: %s", self._email, exc)

    async def _send_webhook(self, incident: Incident) -> None:
        """Send webhook POST with incident data."""
        import urllib.error
        import urllib.request

        payload = {
            "event": "security_incident",
            "incident": {
                "id": incident.id,
                "severity": incident.severity,
                "score": incident.total_score,
                "action": incident.action_taken,
                "path": incident.file_event.path,
                "username": incident.username,
                "timestamp": incident.timestamp.isoformat(),
                "summary": incident.summary,
            },
        }

        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(self._webhook, data=data, headers=headers, method="POST")  # noqa: S310

        try:

            def _do_post():
                with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                    return resp.status

            status = await asyncio.to_thread(_do_post)
            logger.info("Webhook notification sent to %s (status=%d)", self._webhook, status)
        except (urllib.error.URLError, OSError) as exc:
            logger.error("Failed to send webhook to %s: %s", self._webhook, exc)
