"""GeoIP country lookup and MaxMind database management."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shutil
import tarfile
import tempfile
from pathlib import Path

import maxminddb

logger = logging.getLogger(__name__)

_DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id={edition}&license_key={key}&suffix=tar.gz"
)


class GeoIPManager:
    """MaxMind GeoLite2/GeoIP2 country database manager."""

    def __init__(
        self,
        db_path: str = "/var/lib/jabali-security/GeoLite2-Country.mmdb",
        license_key: str = "",
        edition: str = "GeoLite2-Country",
    ) -> None:
        self._db_path = Path(db_path)
        self._license_key = license_key
        self._edition = edition
        self._reader: maxminddb.Reader | None = None

    def _open(self) -> maxminddb.Reader | None:
        """Lazy-load the database on first lookup."""
        if self._reader is not None:
            return self._reader
        if not self._db_path.is_file():
            return None
        try:
            self._reader = maxminddb.open_database(str(self._db_path))
            logger.info("GeoIP database loaded: %s", self._db_path)
            return self._reader
        except Exception:
            logger.exception("Failed to open GeoIP database: %s", self._db_path)
            return None

    def lookup(self, ip: str) -> str | None:
        """Return ISO 3166-1 alpha-2 country code for an IP, or None."""
        reader = self._open()
        if reader is None:
            return None
        try:
            ipaddress.ip_address(ip)
            result = reader.get(ip)
            if result and isinstance(result, dict):
                country = result.get("country", {})
                return country.get("iso_code")
        except (ValueError, maxminddb.InvalidDatabaseError):
            pass
        return None

    def is_available(self) -> bool:
        """Check if the database file exists."""
        return self._db_path.is_file()

    def db_info(self) -> dict:
        """Return database metadata."""
        if not self.is_available():
            return {"available": False, "path": str(self._db_path)}
        reader = self._open()
        meta: dict = {
            "available": True,
            "path": str(self._db_path),
            "size_bytes": self._db_path.stat().st_size,
            "modified": self._db_path.stat().st_mtime,
        }
        if reader:
            md = reader.metadata()
            meta["build_epoch"] = md.build_epoch
            meta["database_type"] = md.database_type
            meta["node_count"] = md.node_count
        return meta

    async def download_database(self) -> tuple[bool, str]:
        """Download GeoLite2-Country.mmdb from MaxMind. Returns (success, message)."""
        if not self._license_key:
            return False, "No MaxMind license key configured"

        url = _DOWNLOAD_URL.format(edition=self._edition, key=self._license_key)

        try:
            return await asyncio.to_thread(self._download_sync, url)
        except Exception as exc:
            msg = "GeoIP download failed: %s" % exc
            logger.exception(msg)
            return False, msg

    def _download_sync(self, url: str) -> tuple[bool, str]:
        """Synchronous download + extract (runs in executor)."""
        import urllib.request

        tmp_dir = tempfile.mkdtemp(prefix="jabali-geoip-")
        tar_path = os.path.join(tmp_dir, "geoip.tar.gz")

        try:
            req = urllib.request.Request(url)  # noqa: S310
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
                with open(tar_path, "wb") as f:
                    shutil.copyfileobj(resp, f)

            with tarfile.open(tar_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith(".mmdb"):
                        member_file = tar.extractfile(member)
                        if member_file:
                            self._db_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(self._db_path, "wb") as out:
                                shutil.copyfileobj(member_file, out)
                            # Reload reader
                            if self._reader:
                                self._reader.close()
                                self._reader = None
                            logger.info("GeoIP database updated: %s", self._db_path)
                            return True, "Database updated: %s" % self._db_path
            return False, "No .mmdb file found in archive"
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def check_ip(self, ip: str, blocked_countries: list[str], allowed_countries: list[str]) -> str:
        """Check if an IP should be blocked/allowed based on country rules.

        Returns: "block", "allow", or "pass"
        - If allowed_countries is set (whitelist mode): block everything NOT in the list
        - If blocked_countries is set (blocklist mode): block IPs from those countries
        - Otherwise: pass
        """
        country = self.lookup(ip)
        if not country:
            return "pass"

        if allowed_countries:
            return "pass" if country in allowed_countries else "block"
        if blocked_countries:
            return "block" if country in blocked_countries else "pass"
        return "pass"

    def close(self) -> None:
        """Close the database reader."""
        if self._reader:
            self._reader.close()
            self._reader = None
