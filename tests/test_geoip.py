"""Tests for lib.webshield.geoip — GeoIPManager and config generation."""

from __future__ import annotations

from pathlib import Path

from lib.webshield.config_generator import NginxConfigGenerator
from lib.webshield.geoip import GeoIPManager
from lib.webshield.models import GeoRule


class TestGeoIPManager:
    def test_not_available_without_db(self, tmp_path: Path) -> None:
        mgr = GeoIPManager(db_path=str(tmp_path / "nonexistent.mmdb"))
        assert mgr.is_available() is False

    def test_lookup_returns_none_without_db(self, tmp_path: Path) -> None:
        mgr = GeoIPManager(db_path=str(tmp_path / "nonexistent.mmdb"))
        assert mgr.lookup("8.8.8.8") is None

    def test_db_info_not_available(self, tmp_path: Path) -> None:
        mgr = GeoIPManager(db_path=str(tmp_path / "nonexistent.mmdb"))
        info = mgr.db_info()
        assert info["available"] is False

    def test_check_ip_pass_without_rules(self, tmp_path: Path) -> None:
        mgr = GeoIPManager(db_path=str(tmp_path / "nonexistent.mmdb"))
        assert mgr.check_ip("8.8.8.8", [], []) == "pass"

    def test_download_fails_without_key(self, tmp_path: Path) -> None:
        import asyncio
        mgr = GeoIPManager(db_path=str(tmp_path / "test.mmdb"), license_key="")
        ok, msg = asyncio.get_event_loop().run_until_complete(mgr.download_database())
        assert ok is False
        assert "license key" in msg.lower()

    def test_close_without_open(self, tmp_path: Path) -> None:
        mgr = GeoIPManager(db_path=str(tmp_path / "nonexistent.mmdb"))
        mgr.close()  # should not raise


class TestGeoRule:
    def test_valid_rule(self) -> None:
        rule = GeoRule(country_code="CN", country_name="China", action="block")
        assert rule.country_code == "CN"
        assert rule.enabled is True

    def test_default_action(self) -> None:
        rule = GeoRule(country_code="RU")
        assert rule.action == "block"


class TestGeoIPNginxConfig:
    def test_no_geoip_by_default(self, tmp_path) -> None:
        gen = NginxConfigGenerator(str(tmp_path))
        http = gen.generate_http_config()
        assert "geoip2" not in http
        server = gen.generate_server_config()
        assert "jabali_geo_action" not in server

    def test_geoip_blocklist_mode(self, tmp_path) -> None:
        gen = NginxConfigGenerator(
            str(tmp_path),
            geoip_enabled=True,
            geoip_db_path="/var/lib/jabali-security/GeoLite2-Country.mmdb",
            geoip_blocked_countries=["CN", "RU"],
            geoip_action="block",
        )
        http = gen.generate_http_config()
        assert "geoip2 /var/lib/jabali-security/GeoLite2-Country.mmdb" in http
        assert "CN 'block'" in http
        assert "RU 'block'" in http
        assert "default 'pass'" in http

    def test_geoip_whitelist_mode(self, tmp_path) -> None:
        gen = NginxConfigGenerator(
            str(tmp_path),
            geoip_enabled=True,
            geoip_db_path="/test.mmdb",
            geoip_allowed_countries=["US", "IL"],
            geoip_action="block",
        )
        http = gen.generate_http_config()
        assert "default 'block'" in http
        assert "US 'pass'" in http
        assert "IL 'pass'" in http

    def test_geoip_server_config(self, tmp_path) -> None:
        gen = NginxConfigGenerator(
            str(tmp_path),
            geoip_enabled=True,
            geoip_db_path="/test.mmdb",
            geoip_blocked_countries=["CN"],
        )
        server = gen.generate_server_config()
        assert "$jabali_geo_action = 'block'" in server

    def test_geoip_challenge_action(self, tmp_path) -> None:
        gen = NginxConfigGenerator(
            str(tmp_path),
            geoip_enabled=True,
            geoip_db_path="/test.mmdb",
            geoip_blocked_countries=["KP"],
            geoip_action="challenge",
        )
        http = gen.generate_http_config()
        assert "KP 'challenge'" in http

    def test_geoip_no_countries_configured(self, tmp_path) -> None:
        gen = NginxConfigGenerator(
            str(tmp_path),
            geoip_enabled=True,
            geoip_db_path="/test.mmdb",
        )
        http = gen.generate_http_config()
        assert "geoip2" in http
        assert "no rules configured" in http
        assert "default 'pass'" in http

    def test_country_code_sanitized(self, tmp_path) -> None:
        gen = NginxConfigGenerator(
            str(tmp_path),
            geoip_enabled=True,
            geoip_db_path="/test.mmdb",
            geoip_blocked_countries=["CN;evil", "RU'bad"],
        )
        http = gen.generate_http_config()
        # Injection characters stripped
        assert ";" not in http.split("$jabali_geo_action")[1].split("}")[0].replace("';", "")
