"""CrowdSec data models."""

from __future__ import annotations

from pydantic import BaseModel


class CrowdSecDecision(BaseModel):
    """A single LAPI decision (ban, captcha, etc.)."""

    id: int = 0
    origin: str = ""  # "crowdsec", "cscli", "CAPI", "lists"
    type: str = "ban"  # "ban", "captcha", custom
    scope: str = "Ip"  # "Ip", "Range"
    value: str = ""  # IP address or CIDR
    duration: str = ""  # Go duration format, e.g. "4h0m0s"
    scenario: str = ""  # e.g. "crowdsecurity/ssh-bf"


class CrowdSecStatus(BaseModel):
    """CrowdSec integration status for API responses."""

    enabled: bool = False
    connected: bool = False
    lapi_url: str = ""
    active_decisions: int = 0
    blocked_ips: int = 0
    last_poll: str = ""
    error: str = ""
