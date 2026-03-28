"""SSH jail data models."""
from __future__ import annotations

from pydantic import BaseModel


class SshKey(BaseModel):
    id: str
    name: str
    key_type: str
    fingerprint: str
    added_at: str


class SshUserStatus(BaseModel):
    username: str
    shell: str
    shell_enabled: bool
    sftp_only: bool
    groups: list[str]


class SshKeyGenResult(BaseModel):
    name: str
    key_type: str
    private_key: str
    public_key: str
    ppk_key: str
    fingerprint: str
