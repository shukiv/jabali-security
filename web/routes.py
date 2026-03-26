"""Flask dashboard routes."""
from __future__ import annotations

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

# Config keys that map to protection toggles
_TOGGLE_KEYS = {
    "waf": "WAF_ENABLED",
    "bruteforce": "BRUTEFORCE_ENABLED",
    "proactive": "PROACTIVE_ENABLED",
    "php_hardening": "PHP_HARDENING_ENABLED",
    "process_kill": "PROCESS_KILL_ENABLED",
    "cleanup": "CLEANUP_ENABLED",
    "cleanup_auto": "CLEANUP_AUTO",
    "scheduled_scan": "SCHEDULED_SCAN_ENABLED",
    "threat_intel": "THREAT_INTEL_ENABLED",
    "webshield": "WEBSHIELD_ENABLED",
    "auto_quarantine": "AUTO_QUARANTINE",
    "auto_suspend": "AUTO_SUSPEND",
    "heuristic": "HEURISTIC_ENABLED",
    "entropy": "ENTROPY_ENABLED",
    "yara": "YARA_ENABLED",
    "process_monitor": "PROCESS_MONITOR_ENABLED",
    "behavior_tracking": "BEHAVIOR_TRACKING_ENABLED",
}


def register_routes(app):
    """Register all dashboard routes."""

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            password = request.form.get("password", "")
            config = load_config()
            if password and password == config.api_key:
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
        config = api_call("GET", "/api/v1/config") or {}
        return render_template("dashboard.html", status=status, config=config)

    @app.route("/toggle/<feature>", methods=["POST"])
    @login_required
    def toggle_feature(feature):
        if feature not in _TOGGLE_KEYS:
            flash("Unknown feature: %s" % feature, "error")
            return redirect(url_for("dashboard"))
        conf_key = _TOGGLE_KEYS[feature]
        config = load_config()
        # Get current value and flip it
        current = getattr(config, feature, None)
        if current is None:
            # Try the config key directly
            current = getattr(config, conf_key.lower(), False)
        new_val = "no" if current else "yes"
        update_conf_key(CONFIG_FILE, conf_key, new_val)
        # Also push to running daemon
        api_call("PATCH", "/api/v1/config", {conf_key: new_val})
        flash("%s %s." % (feature.replace("_", " ").title(), "enabled" if new_val == "yes" else "disabled"), "success")
        return redirect(request.referrer or url_for("dashboard"))

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
        return api_call("GET", "/api/v1/config") or {}

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
        blocked = api_call("GET", "/api/v1/bruteforce/blocked") or {}
        return render_template("bruteforce.html", stats=stats, blocked=blocked, config=_config())

    @app.route("/proactive")
    @login_required
    def proactive():
        status = api_call("GET", "/api/v1/proactive/status") or {}
        pools = api_call("GET", "/api/v1/proactive/php/pools")
        pools = pools if isinstance(pools, list) else []
        kills = api_call("GET", "/api/v1/proactive/kills")
        kills = kills if isinstance(kills, list) else []
        return render_template("proactive.html", status=status, pools=pools, kills=kills, config=_config())

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

    @app.route("/config")
    @login_required
    def config_page():
        data = api_call("GET", "/api/v1/config") or {}
        return render_template("config.html", config=data)

    @app.route("/rules")
    @login_required
    def rules_page():
        data = api_call("GET", "/api/v1/rules") or {}
        return render_template("rules.html", rules=data)
