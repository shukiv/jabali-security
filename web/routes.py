"""Flask dashboard routes."""
from __future__ import annotations

import hmac
import logging
import subprocess

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from lib.config import load_config, update_conf_key
from lib.constants import CONFIG_FILE
from web.api_client import api_call
from web.app import login_required

logger = logging.getLogger(__name__)

# Packages required by each feature (apt package names)
# Only features that REQUIRE packages to function at all
_FEATURE_DEPS: dict[str, list[str]] = {
    "waf": ["libnginx-mod-http-modsecurity"],
    "webshield": [],
}
# All other features work without extra packages

# Config keys that map to protection toggles
_TOGGLE_KEYS = {
    "waf": "WAF_ENABLED",
    "bruteforce": "BRUTEFORCE_ENABLED",
    "process_kill": "PROCESS_KILL_ENABLED",
    "cleanup": "CLEANUP_ENABLED",
    "cleanup_auto": "CLEANUP_AUTO",
    "scheduled_scan": "SCHEDULED_SCAN_ENABLED",
    "threat_intel": "THREAT_INTEL_ENABLED",
    "webshield": "WEBSHIELD_ENABLED",
    "ufw": "UFW_ENABLED",
    "auto_quarantine": "AUTO_QUARANTINE",
    "auto_suspend": "AUTO_SUSPEND",
    "sshjail": "SSHJAIL_ENABLED",
}


def _is_pkg_installed(pkg: str) -> bool:
    """Check if an apt/dpkg package is installed."""
    try:
        result = subprocess.run(  # noqa: S603
            ["/usr/bin/dpkg", "-s", pkg],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _install_packages(packages: list[str]) -> bool:
    """Install apt packages. Returns True on success."""
    try:
        env = dict(DEBIAN_FRONTEND="noninteractive")
        subprocess.run(  # noqa: S603
            ["/usr/bin/apt-get", "update", "-qq"],
            capture_output=True, timeout=60, env=env,
        )
        result = subprocess.run(  # noqa: S603
            ["/usr/bin/apt-get", "install", "-y", "-qq", *packages],
            capture_output=True, timeout=120, env=env,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        logger.exception("Failed to install packages: %s", packages)
        return False


def register_routes(app):
    """Register all dashboard routes."""

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            password = request.form.get("password", "")
            config = load_config()
            if password and hmac.compare_digest(password, config.api_key):
                session["logged_in"] = True
                return redirect(url_for("dashboard"))
            flash("Invalid password.", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def dashboard():
        status = api_call("GET", "/api/v1/status") or {}
        return render_template("dashboard.html", status=status, config=_config())

    @app.route("/toggle/<feature>", methods=["POST"])
    @login_required
    def toggle_feature(feature):
        if feature not in _TOGGLE_KEYS:
            flash("Unknown feature: %s" % feature, "error")
            return redirect(url_for("dashboard"))
        conf_key = _TOGGLE_KEYS[feature]

        # Read current value from config file directly
        from lib.config import parse_conf
        raw = parse_conf(CONFIG_FILE)
        current_raw = raw.get(conf_key, "no")
        is_enabled = current_raw.lower() in ("yes", "true", "1")
        label = feature.replace("_", " ").title()

        if is_enabled:
            # Disabling — no confirmation needed
            update_conf_key(CONFIG_FILE, conf_key, "no")
            api_call("PATCH", "/api/v1/config", {conf_key: "no"})
            flash("%s disabled." % label, "success")
            return redirect(request.referrer or url_for("dashboard"))

        # Enabling — check if deps need installing, show confirm page
        deps = _FEATURE_DEPS.get(feature, [])
        missing = [p for p in deps if not _is_pkg_installed(p)]
        if missing:
            return render_template("confirm_toggle.html",
                feature=feature, label=label, deps=missing)

        # No deps needed — enable directly
        update_conf_key(CONFIG_FILE, conf_key, "yes")
        api_call("PATCH", "/api/v1/config", {conf_key: "yes"})
        flash("%s enabled." % label, "success")
        return redirect(request.referrer or url_for("dashboard"))

    @app.route("/toggle/<feature>/confirm", methods=["POST"])
    @login_required
    def toggle_confirm(feature):
        """Confirm enabling a feature — install deps and enable."""
        if feature not in _TOGGLE_KEYS:
            flash("Unknown feature.", "error")
            return redirect(url_for("dashboard"))
        conf_key = _TOGGLE_KEYS[feature]
        label = feature.replace("_", " ").title()

        # Install missing packages
        deps = _FEATURE_DEPS.get(feature, [])
        missing = [p for p in deps if not _is_pkg_installed(p)]
        if missing:
            ok = _install_packages(missing)
            if ok:
                flash("Installed: %s" % ", ".join(missing), "success")
            else:
                flash("Failed to install: %s" % ", ".join(missing), "error")
                return redirect(url_for("dashboard"))

        # Enable
        update_conf_key(CONFIG_FILE, conf_key, "yes")
        api_call("PATCH", "/api/v1/config", {conf_key: "yes"})
        flash("%s enabled." % label, "success")
        return redirect(url_for("dashboard"))

    @app.route("/incidents")
    @login_required
    def incidents():
        limit = request.args.get("limit", "50")
        user = request.args.get("user", "")
        severity = request.args.get("severity", "")
        params = "limit=%s" % limit
        if user:
            params += "&user=%s" % user
        if severity:
            params += "&severity=%s" % severity
        data = api_call("GET", "/api/v1/incidents?%s" % params)
        items = data if isinstance(data, list) else []
        return render_template("incidents.html", incidents=items)

    @app.route("/incidents/<incident_id>")
    @login_required
    def incident_detail(incident_id):
        data = api_call("GET", "/api/v1/incidents/%s" % incident_id) or {}
        return render_template("incident_detail.html", incident=data)

    @app.route("/incidents/<incident_id>/resolve", methods=["POST"])
    @login_required
    def resolve_incident(incident_id):
        notes = request.form.get("notes", "")
        api_call("POST", "/api/v1/incidents/%s/resolve" % incident_id, {"notes": notes})
        flash("Incident resolved.", "success")
        return redirect(url_for("incidents"))

    @app.route("/quarantine")
    @login_required
    def quarantine():
        user = request.args.get("user", "")
        query = "?user=%s" % user if user else ""
        data = api_call("GET", "/api/v1/quarantine%s" % query)
        items = data if isinstance(data, list) else []
        return render_template("quarantine.html", records=items)

    @app.route("/quarantine/<record_id>/restore", methods=["POST"])
    @login_required
    def restore_quarantine(record_id):
        api_call("POST", "/api/v1/quarantine/%s/restore" % record_id)
        flash("File restored.", "success")
        return redirect(url_for("quarantine"))

    @app.route("/quarantine/<record_id>/delete", methods=["POST"])
    @login_required
    def delete_quarantine(record_id):
        api_call("DELETE", "/api/v1/quarantine/%s" % record_id)
        flash("File deleted.", "success")
        return redirect(url_for("quarantine"))

    @app.route("/scan", methods=["GET", "POST"])
    @login_required
    def scan():
        result = None
        if request.method == "POST":
            path = request.form.get("path", "")
            if path:
                result = api_call("POST", "/api/v1/scan", {"path": path})
        return render_template("scan.html", result=result)

    @app.route("/users")
    @login_required
    def users():
        data = api_call("GET", "/api/v1/users")
        items = data if isinstance(data, list) else []
        return render_template("users.html", users=items)

    @app.route("/users/<username>")
    @login_required
    def user_detail(username):
        data = api_call("GET", "/api/v1/users/%s" % username) or {}
        return render_template("user_detail.html", user=data, username=username)

    @app.route("/blocklist")
    @login_required
    def blocklist():
        data = api_call("GET", "/api/v1/blocklist")
        items = data if isinstance(data, list) else []
        return render_template("blocklist.html", blocked=items)

    @app.route("/block", methods=["POST"])
    @login_required
    def block_ip():
        ip = request.form.get("ip", "")
        reason = request.form.get("reason", "manual")
        duration = request.form.get("duration", "0")
        if ip:
            api_call("POST", "/api/v1/block", {"ip": ip, "reason": reason, "duration": int(duration)})
            flash("IP %s blocked." % ip, "success")
        return redirect(url_for("blocklist"))

    @app.route("/unblock/<ip>", methods=["POST"])
    @login_required
    def unblock_ip(ip):
        api_call("DELETE", "/api/v1/block/%s" % ip)
        flash("IP %s unblocked." % ip, "success")
        return redirect(url_for("blocklist"))

    def _config():
        """Read config from file (not API) so toggles reflect latest changes."""
        from lib.config import DEFAULTS, parse_conf
        raw = dict(DEFAULTS)
        raw.update(parse_conf(CONFIG_FILE))
        return raw

    def _restart_daemon():
        """Restart the jabali-security daemon to pick up config changes."""
        import time
        try:
            subprocess.run(
                ["/usr/bin/systemctl", "stop", "jabali-security"],
                capture_output=True, timeout=10,
            )
            time.sleep(1)
            subprocess.run(
                ["/usr/bin/systemctl", "start", "jabali-security"],
                capture_output=True, timeout=10,
            )
            # Wait for API to become ready (up to 15s)
            for _ in range(15):
                time.sleep(1)
                try:
                    result = api_call("GET", "/api/v1/health")
                    if result:
                        return
                except Exception:
                    pass
        except (OSError, subprocess.TimeoutExpired):
            logger.warning("Failed to restart jabali-security daemon")

    @app.route("/waf")
    @login_required
    def waf():
        events = api_call("GET", "/api/v1/waf/events?limit=50")
        stats = api_call("GET", "/api/v1/waf/stats")
        rules = api_call("GET", "/api/v1/waf/rules")
        return render_template("waf.html",
            events=events if isinstance(events, list) else [],
            stats=stats or {},
            rules=rules or {},
            config=_config(),
        )

    @app.route("/bruteforce")
    @login_required
    def bruteforce():
        stats = api_call("GET", "/api/v1/bruteforce/stats") or {}
        # Get blocked IPs from general blocklist, filter to bruteforce only
        all_blocked = api_call("GET", "/api/v1/blocklist")
        all_blocked = all_blocked if isinstance(all_blocked, list) else []
        bf_blocked = [b for b in all_blocked if b.get("blocked_by") == "bruteforce"]
        blocked = {"blocked_ips": bf_blocked}
        return render_template("bruteforce.html", stats=stats, blocked=blocked, config=_config())

    @app.route("/proactive")
    @login_required
    def proactive():
        status = api_call("GET", "/api/v1/proactive/status") or {}
        kills = api_call("GET", "/api/v1/proactive/kills")
        kills = kills if isinstance(kills, list) else []
        return render_template("proactive.html", status=status, kills=kills, config=_config())

    @app.route("/cleanup")
    @login_required
    def cleanup():
        records = api_call("GET", "/api/v1/cleanup/records")
        records = records if isinstance(records, list) else []
        scheduled = api_call("GET", "/api/v1/scan/scheduled") or {}
        return render_template("cleanup.html", records=records, scheduled=scheduled, config=_config())

    @app.route("/threat-intel")
    @login_required
    def threat_intel():
        feeds = api_call("GET", "/api/v1/threat-intel/feeds")
        feeds = feeds if isinstance(feeds, list) else []
        return render_template("threat_intel.html", feeds=feeds, config=_config())

    @app.route("/threat-intel/update", methods=["POST"])
    @login_required
    def threat_intel_update():
        api_call("POST", "/api/v1/threat-intel/update")
        flash("Feed update triggered.", "success")
        return redirect(url_for("threat_intel"))

    @app.route("/webshield")
    @login_required
    def webshield():
        status = api_call("GET", "/api/v1/webshield/status") or {}
        rules = api_call("GET", "/api/v1/webshield/rules")
        rules = rules if isinstance(rules, list) else []
        return render_template("webshield.html", status=status, rules=rules, config=_config())

    @app.route("/webshield/install", methods=["POST"])
    @login_required
    def webshield_install():
        result = api_call("POST", "/api/v1/webshield/install") or {}
        if result.get("success"):
            flash("WebShield installed. Add the nginx includes to your server config.", "success")
        else:
            flash("Install failed: %s" % result.get("error", "unknown"), "error")
        return redirect(url_for("webshield"))

    @app.route("/webshield/uninstall", methods=["POST"])
    @login_required
    def webshield_uninstall():
        api_call("POST", "/api/v1/webshield/uninstall")
        flash("WebShield uninstalled.", "success")
        return redirect(url_for("webshield"))

    @app.route("/reset", methods=["POST"])
    @login_required
    def reset_stats():
        """Reset all incidents, quarantine records, WAF events, and blocked IPs."""
        from lib.config import parse_conf
        from lib.constants import CONFIG_FILE as cf
        raw = parse_conf(cf)
        db_path = raw.get("DATA_DIR", "/var/lib/jabali-security") + "/incidents.db"

        import asyncio

        import aiosqlite
        async def _reset():
            db = await aiosqlite.connect(db_path)
            await db.execute("DELETE FROM incidents")
            await db.execute("DELETE FROM quarantine")
            await db.execute("DELETE FROM blocked_ips")
            await db.execute("DELETE FROM waf_events")
            await db.execute("DELETE FROM cleanup_records")
            await db.commit()
            await db.close()
        try:
            asyncio.run(_reset())
            flash("All stats and records have been reset.", "success")
        except Exception as exc:
            flash("Reset failed: %s" % exc, "error")
        return redirect(url_for("dashboard"))

    @app.route("/config")
    @login_required
    def config_page():
        return render_template("config.html", config=_config())

    @app.route("/config/update", methods=["POST"])
    @login_required
    def config_update():
        key = request.form.get("key", "").strip()
        value = request.form.get("value", "").strip()
        if not key:
            flash("Key is required.", "error")
            return redirect(url_for("config_page"))
        # Validate key exists in defaults
        from lib.config import DEFAULTS
        if key not in DEFAULTS:
            flash("Unknown config key: %s" % key, "error")
            return redirect(url_for("config_page"))
        update_conf_key(CONFIG_FILE, key, value)
        api_call("PATCH", "/api/v1/config", {key: value})
        flash("%s updated." % key, "success")
        return redirect(url_for("config_page"))

    @app.route("/firewall")
    @login_required
    def firewall():
        config = _config()
        ufw_enabled = config.get("UFW_ENABLED", "no") in ("yes", "true", "1")
        status = {}
        rules = []
        apps = []
        if ufw_enabled:
            status = api_call("GET", "/api/v1/firewall/ufw/status") or {}
            rules = api_call("GET", "/api/v1/firewall/ufw/rules")
            rules = rules if isinstance(rules, list) else []
            apps = api_call("GET", "/api/v1/firewall/ufw/apps")
            apps = apps if isinstance(apps, list) else []
        return render_template("firewall.html",
            ufw_enabled=ufw_enabled, status=status, rules=rules, apps=apps, config=config)

    @app.route("/firewall/toggle", methods=["POST"])
    @login_required
    def firewall_toggle():
        """Single toggle: enables/disables both UFW_ENABLED config and ufw itself."""
        config = _config()
        is_enabled = config.get("UFW_ENABLED", "no") in ("yes", "true", "1")

        if is_enabled:
            # Disable: turn off ufw, then disable module, restart daemon
            api_call("POST", "/api/v1/firewall/ufw/disable")
            update_conf_key(CONFIG_FILE, "UFW_ENABLED", "no")
            _restart_daemon()
            flash("UFW firewall disabled.", "success")
        else:
            # Enable: set config, restart daemon to load module, then enable ufw
            update_conf_key(CONFIG_FILE, "UFW_ENABLED", "yes")
            _restart_daemon()
            result = api_call("POST", "/api/v1/firewall/ufw/enable")
            if result and result.get("enabled"):
                flash("UFW firewall enabled.", "success")
            else:
                flash("UFW firewall enabled.", "success")
        return redirect(url_for("firewall"))

    @app.route("/firewall/reload", methods=["POST"])
    @login_required
    def firewall_reload():
        result = api_call("POST", "/api/v1/firewall/ufw/reload")
        if result:
            flash("UFW reloaded.", "success")
        else:
            flash("UFW reload failed.", "error")
        return redirect(url_for("firewall"))

    @app.route("/firewall/rules/add", methods=["POST"])
    @login_required
    def firewall_add_rule():
        body = {"action": request.form.get("action", "allow")}
        port = request.form.get("port", "").strip()
        protocol = request.form.get("protocol", "").strip()
        from_ip = request.form.get("from_ip", "").strip()
        direction = request.form.get("direction", "").strip()
        comment = request.form.get("comment", "").strip()
        if port:
            body["port"] = port
        if protocol:
            body["protocol"] = protocol
        if from_ip:
            body["from_ip"] = from_ip
        if direction:
            body["direction"] = direction
        if comment:
            body["comment"] = comment
        result = api_call("POST", "/api/v1/firewall/ufw/rules", body)
        if result and result.get("added"):
            flash("Rule added.", "success")
        else:
            flash("Failed to add rule.", "error")
        return redirect(url_for("firewall"))

    @app.route("/firewall/rules/<int:number>/delete", methods=["POST"])
    @login_required
    def firewall_delete_rule(number):
        result = api_call("DELETE", "/api/v1/firewall/ufw/rules/%d" % number)
        if result and result.get("deleted"):
            flash("Rule #%d deleted." % number, "success")
        else:
            flash("Failed to delete rule.", "error")
        return redirect(url_for("firewall"))

    @app.route("/firewall/apps/<name>/<action>", methods=["POST"])
    @login_required
    def firewall_app_action(name, action):
        if action not in ("allow", "deny"):
            flash("Unknown action.", "error")
            return redirect(url_for("firewall"))
        result = api_call("POST", "/api/v1/firewall/ufw/apps/%s/%s" % (name, action))
        if result:
            flash("%s %sed." % (name, action), "success")
        else:
            flash("Failed to %s %s." % (action, name), "error")
        return redirect(url_for("firewall"))

    @app.route("/rules")
    @login_required
    def rules_page():
        data = api_call("GET", "/api/v1/rules") or {}
        return render_template("rules.html", rules=data)

    @app.route("/ssh")
    @login_required
    def ssh_jail():
        config = _config()
        sshjail_enabled = config.get("SSHJAIL_ENABLED", "no") in ("yes", "true", "1")
        users_data = []
        if sshjail_enabled:
            users = api_call("GET", "/api/v1/users")
            users = users if isinstance(users, list) else []
            for u in users:
                username = u.get("username", "")
                if not username:
                    continue
                status = api_call("GET", "/api/v1/ssh/shell/status?username=%s" % username) or {}
                keys = api_call("GET", "/api/v1/ssh/keys?username=%s" % username)
                keys = keys if isinstance(keys, list) else []
                users_data.append({
                    "username": username,
                    "shell": status.get("shell", "/usr/sbin/nologin"),
                    "shell_enabled": status.get("shell_enabled", False),
                    "sftp_only": status.get("sftp_only", True),
                    "key_count": len(keys),
                })
        return render_template("ssh_jail.html",
            sshjail_enabled=sshjail_enabled, users=users_data, config=config)

    @app.route("/ssh/toggle/<username>", methods=["POST"])
    @login_required
    def ssh_toggle_shell(username):
        action = request.form.get("action", "enable")
        endpoint = "/api/v1/ssh/shell/enable" if action == "enable" else "/api/v1/ssh/shell/disable"
        result = api_call("POST", endpoint, {"username": username})
        if result is not None:
            flash("Shell %sd for %s." % (action, username), "success")
        else:
            flash("Failed to %s shell for %s." % (action, username), "error")
        return redirect(url_for("ssh_jail"))
