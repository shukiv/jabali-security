"""aiohttp application factory for the REST API."""

from __future__ import annotations

import logging

from aiohttp import web

from api.middleware import api_key_auth, request_logger
from api.routes import setup_routes

logger = logging.getLogger(__name__)


def create_app(
    config,
    daemon=None,
    incidents=None,
    quarantine=None,
    scanner=None,
    scoring=None,
) -> web.Application:
    """Create and configure the aiohttp web application."""
    app = web.Application(middlewares=[request_logger, api_key_auth])

    # Store references for route handlers
    app["config"] = config
    app["daemon"] = daemon
    app["incidents"] = incidents
    app["quarantine"] = quarantine
    app["scanner"] = scanner
    app["scoring"] = scoring

    setup_routes(app)

    return app
