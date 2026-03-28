"""WebShield manager -- install, uninstall, and manage nginx bot filtering."""
from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path

from lib.webshield.bot_rules import get_rules
from lib.webshield.config_generator import NginxConfigGenerator
from lib.webshield.models import WebShieldStatus

logger = logging.getLogger(__name__)


class WebShieldManager:
    """Manage WebShield nginx configuration."""

    def __init__(
        self,
        config_dir: str = "/etc/nginx/jabali-security",
        rate_limit: int = 10,
        rate_burst: int = 20,
        challenge_enabled: bool = True,
        bot_filtering: bool = True,
    ) -> None:
        self._config_dir = Path(config_dir)
        self._rate_limit = rate_limit
        self._rate_burst = rate_burst
        self._challenge_enabled = challenge_enabled
        self._bot_filtering = bot_filtering
        self._generator = NginxConfigGenerator(
            config_dir=config_dir,
            rate_limit=rate_limit,
            rate_burst=rate_burst,
        )

    async def install(self) -> dict:
        """Install WebShield nginx configs. Returns status dict."""
        if not shutil.which("nginx"):
            return {"success": False, "error": "nginx not found"}

        try:
            written = self._generator.write_configs()

            # Write challenge page
            challenge_src = Path(__file__).parent.parent.parent / "etc" / "webshield" / "challenge.html"
            challenge_dst = self._config_dir / "jabali-challenge.html"
            if challenge_src.is_file():
                shutil.copy2(str(challenge_src), str(challenge_dst))
                written.append(str(challenge_dst))
            else:
                # Generate a minimal challenge page
                challenge_dst.write_text(self._default_challenge_page(), encoding="utf-8")
                written.append(str(challenge_dst))

            # Add http-level include to nginx.conf if not present
            self._add_nginx_http_include()

            # Test nginx config
            test_ok = await self._test_nginx_config()

            return {
                "success": True,
                "files_written": written,
                "nginx_config_valid": test_ok,
            }
        except OSError as exc:
            return {"success": False, "error": str(exc)}

    async def uninstall(self) -> dict:
        """Remove WebShield nginx configs."""
        removed: list[str] = []
        for name in ("jabali-webshield-http.conf", "jabali-webshield-server.conf",
                      "jabali-challenge.html", "blocked_ips.conf"):
            p = self._config_dir / name
            if p.is_file():
                p.unlink()
                removed.append(str(p))

        # Remove http-level include from nginx.conf
        self._remove_nginx_http_include()

        return {"success": True, "files_removed": removed}

    async def update_blocked_ips(self, ips: list[str]) -> bool:
        """Write blocked IPs to nginx include file."""
        try:
            content = self._generator.generate_blocked_ips_conf(ips)
            (self._config_dir / "blocked_ips.conf").write_text(content, encoding="utf-8")
            return True
        except OSError:
            return False

    def get_status(self) -> WebShieldStatus:
        """Get current WebShield status."""
        http_conf = self._config_dir / "jabali-webshield-http.conf"
        server_conf = self._config_dir / "jabali-webshield-server.conf"
        blocked_conf = self._config_dir / "blocked_ips.conf"

        blocked_count = 0
        if blocked_conf.is_file():
            blocked_count = sum(1 for line in blocked_conf.read_text().splitlines()
                                if line.strip() and not line.startswith("#"))

        return WebShieldStatus(
            installed=http_conf.is_file() and server_conf.is_file(),
            nginx_available=shutil.which("nginx") is not None,
            rate_limiting=server_conf.is_file(),
            bot_filtering=http_conf.is_file(),
            challenge_enabled=self._challenge_enabled,
            blocked_ips_count=blocked_count,
            config_dir=str(self._config_dir),
        )

    def get_rules(self) -> list[dict]:
        """Get bot rules as dicts."""
        return [r.model_dump() for r in get_rules()]

    _NGINX_CONF = Path("/etc/nginx/nginx.conf")

    def _add_nginx_http_include(self) -> None:
        """Add WebShield http-level include to nginx.conf if not present."""
        include_line = "\tinclude %s/jabali-webshield-http.conf;" % self._config_dir
        if not self._NGINX_CONF.is_file():
            return
        content = self._NGINX_CONF.read_text()
        if "jabali-webshield-http.conf" in content:
            return
        # Insert after 'modsecurity on;' or after 'http {' line
        for marker in ("modsecurity on;", "http {"):
            if marker in content:
                content = content.replace(marker, marker + "\n" + include_line, 1)
                self._NGINX_CONF.write_text(content)
                logger.info("Added WebShield http include to nginx.conf")
                return

    def _remove_nginx_http_include(self) -> None:
        """Remove WebShield http-level include from nginx.conf."""
        if not self._NGINX_CONF.is_file():
            return
        lines = self._NGINX_CONF.read_text().splitlines()
        filtered = [l for l in lines if "jabali-webshield-http.conf" not in l]
        if len(filtered) < len(lines):
            self._NGINX_CONF.write_text("\n".join(filtered) + "\n")
            logger.info("Removed WebShield http include from nginx.conf")

    @staticmethod
    async def _test_nginx_config() -> bool:
        """Test nginx configuration. Returns True if valid."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nginx", "-t",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except OSError:
            return False

    @staticmethod
    def _default_challenge_page() -> str:
        """Generate a minimal JS challenge page."""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Security Check</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .box { background: white; padding: 40px; border-radius: 8px; display: inline-block; box-shadow: 0 2px 10px rgba(0,0,0,.1); }
        h1 { color: #333; }
        p { color: #666; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="box">
        <h1>Security Check</h1>
        <div class="spinner"></div>
        <p>Verifying your browser...</p>
        <p id="status">Please wait</p>
    </div>
    <script>
        (function() {
            var t = Date.now();
            var c = 0;
            for (var i = 0; i < 1000000; i++) c += i;
            var d = Date.now() - t;
            if (d > 0 && d < 10000 && c > 0) {
                document.cookie = "jabali_verified=" + btoa(t + ":" + d) + "; path=/; max-age=3600";
                document.getElementById("status").textContent = "Verified! Redirecting...";
                setTimeout(function() { location.reload(); }, 500);
            } else {
                document.getElementById("status").textContent = "Verification failed.";
            }
        })();
    </script>
</body>
</html>"""
