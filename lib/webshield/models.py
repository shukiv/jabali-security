"""WebShield data models."""
from __future__ import annotations

from pydantic import BaseModel


class WebShieldStatus(BaseModel):
    installed: bool = False
    nginx_available: bool = False
    rate_limiting: bool = False
    bot_filtering: bool = False
    challenge_enabled: bool = False
    blocked_ips_count: int = 0
    config_dir: str = ""


class BotRule(BaseModel):
    name: str
    pattern: str
    action: str = "block"    # "block", "challenge", "allow"
    category: str = ""       # "malicious", "suspicious", "crawler", "verified"
    enabled: bool = True
