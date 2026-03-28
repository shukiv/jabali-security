"""Flask web dashboard for Jabali Security."""
from __future__ import annotations

import hashlib
import secrets
from functools import wraps
from pathlib import Path

from flask import Flask, redirect, session, url_for

from lib.config import load_config
from lib.constants import VERSION


def login_required(f):
    """Decorator: redirect to login if not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def create_app():
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parent / "templates"),
        static_folder=str(Path(__file__).resolve().parent / "static"),
    )

    config = load_config()
    app.secret_key = secrets.token_urlsafe(32)
    app.config["API_URL"] = "http://%s:%d" % (config.api_bind, config.api_port)
    app.config["API_KEY"] = config.api_key
    app.config["VERSION"] = VERSION
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True
    from datetime import timedelta
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    # Security headers
    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Template context
    @app.context_processor
    def inject_globals():
        return {"version": VERSION, "app_name": "Jabali Security"}

    # Register routes
    from web.routes import register_routes
    register_routes(app)

    return app
