"""Generate nginx configuration snippets for WebShield."""
from __future__ import annotations

import logging
from pathlib import Path

from lib.webshield.bot_rules import get_rules

logger = logging.getLogger(__name__)


class NginxConfigGenerator:
    """Generate nginx configuration for bot filtering, rate limiting, and GeoIP blocking."""

    def __init__(
        self,
        config_dir: str,
        rate_limit: int = 10,
        rate_burst: int = 20,
        rate_limiting: bool = False,
        geoip_enabled: bool = False,
        geoip_db_path: str = "",
        geoip_blocked_countries: list[str] | None = None,
        geoip_allowed_countries: list[str] | None = None,
        geoip_action: str = "block",
    ) -> None:
        self._config_dir = Path(config_dir)
        self._rate_limit = rate_limit
        self._rate_burst = rate_burst
        self._rate_limiting = rate_limiting
        self._geoip_enabled = geoip_enabled
        self._geoip_db_path = geoip_db_path
        self._geoip_blocked = geoip_blocked_countries or []
        self._geoip_allowed = geoip_allowed_countries or []
        self._geoip_action = geoip_action

    def generate_http_config(self) -> str:
        """Generate config for the nginx http{} block."""
        lines = [
            "# Jabali Security WebShield -- HTTP-level config",
            "# Include this in your nginx http{} block",
            "",
        ]

        if self._rate_limiting:
            lines += [
                "# Rate limiting zone",
                "limit_req_zone $binary_remote_addr zone=jabali_ratelimit:10m rate=%dr/s;" % self._rate_limit,
                "",
            ]

        # Bot detection map
        rules = get_rules()
        lines.append("# Bot detection map")
        lines.append("map $http_user_agent $jabali_bot_action {")
        lines.append("    default 'pass';")
        for rule in rules:
            if not rule.enabled:
                continue
            # Sanitize pattern to prevent nginx config injection
            safe_pattern = rule.pattern.replace("'", "").replace(";", "").replace("{", "").replace("}", "").replace("\n", "")
            if rule.action == "block":
                lines.append("    '~*%s' 'block';" % safe_pattern)
            elif rule.action == "challenge":
                lines.append("    '~*%s' 'challenge';" % safe_pattern)
            # "allow" rules don't need map entries (default is pass)
        lines.append("}")
        lines.append("")

        # GeoIP country detection
        if self._geoip_enabled and self._geoip_db_path:
            lines += [
                "# GeoIP country detection (MaxMind GeoLite2)",
                "geoip2 %s {" % self._geoip_db_path,
                "    auto_reload 60m;",
                "    $geoip2_country_code country iso_code;",
                "}",
                "",
            ]

            # Build country action map
            countries = self._geoip_blocked or []
            action = self._geoip_action or "block"

            if self._geoip_allowed:
                # Whitelist mode: block everything, allow listed countries
                lines.append("# GeoIP country filter (whitelist mode)")
                lines.append("map $geoip2_country_code $jabali_geo_action {")
                lines.append("    default '%s';" % action)
                for cc in self._geoip_allowed:
                    safe_cc = cc.upper().replace("'", "").replace(";", "")[:2]
                    lines.append("    %s 'pass';" % safe_cc)
                lines.append("}")
            elif countries:
                # Blocklist mode: allow everything, block listed countries
                lines.append("# GeoIP country filter (blocklist mode)")
                lines.append("map $geoip2_country_code $jabali_geo_action {")
                lines.append("    default 'pass';")
                for cc in countries:
                    safe_cc = cc.upper().replace("'", "").replace(";", "")[:2]
                    lines.append("    %s '%s';" % (safe_cc, action))
                lines.append("}")
            else:
                lines.append("# GeoIP country filter (no rules configured)")
                lines.append("map $geoip2_country_code $jabali_geo_action {")
                lines.append("    default 'pass';")
                lines.append("}")
            lines.append("")

        return "\n".join(lines) + "\n"

    def generate_server_config(self) -> str:
        """Generate config for nginx server{} blocks."""
        lines = [
            "# Jabali Security WebShield -- server-level config",
            "# Include this in your nginx server{} blocks",
            "",
        ]

        if self._rate_limiting:
            lines += [
                "# Rate limiting",
                "limit_req zone=jabali_ratelimit burst=%d nodelay;" % self._rate_burst,
                "limit_req_status 429;",
                "",
            ]

        lines += [
            "# Bot blocking",
            "if ($jabali_bot_action = 'block') {",
            "    return 403;",
            "}",
            "",
            "# Bot challenge (redirect to JS challenge page)",
            "if ($jabali_bot_action = 'challenge') {",
            "    return 503;",
            "}",
        ]

        # GeoIP blocking in server context
        if self._geoip_enabled and self._geoip_db_path:
            lines += [
                "",
                "# GeoIP country blocking",
                "if ($jabali_geo_action = 'block') {",
                "    return 403;",
                "}",
                "",
                "if ($jabali_geo_action = 'challenge') {",
                "    return 503;",
                "}",
            ]

        lines += [
            "",
            "# Custom error page for challenge",
            "error_page 503 /jabali-challenge.html;",
            "location = /jabali-challenge.html {",
            "    root %s;" % self._config_dir,
            "    internal;",
            "}",
        ]

        return "\n".join(lines) + "\n"

    def generate_blocked_ips_conf(self, ips: list[str]) -> str:
        """Generate nginx geo-block include file."""
        lines = ["# Jabali Security -- blocked IPs (auto-generated)"]
        for ip in ips:
            lines.append("%s 1;" % ip)
        return "\n".join(lines) + "\n"

    def write_configs(self) -> list[str]:
        """Write all config files to the config directory. Returns list of paths written."""
        self._config_dir.mkdir(parents=True, exist_ok=True)
        written: list[str] = []

        http_path = self._config_dir / "jabali-webshield-http.conf"
        http_path.write_text(self.generate_http_config(), encoding="utf-8")
        written.append(str(http_path))

        server_path = self._config_dir / "jabali-webshield-server.conf"
        server_path.write_text(self.generate_server_config(), encoding="utf-8")
        written.append(str(server_path))

        return written
