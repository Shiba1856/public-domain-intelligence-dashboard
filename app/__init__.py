"""Application factory for the Public Domain Intelligence Dashboard."""
import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask

BASE_DIR = Path(__file__).resolve().parent.parent


def _int_env(name, default):
    """Read an integer setting from the environment, falling back safely."""
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _path_env(name, default):
    """Resolve a path setting relative to the project folder."""
    return str((BASE_DIR / os.getenv(name, default)).resolve())


def create_app():
    """Build and configure the Flask application."""
    load_dotenv(BASE_DIR / ".env")

    secret_key = os.getenv("FLASK_SECRET_KEY", "")
    if not secret_key or secret_key.startswith("change-me"):
        # This message appears in the terminal only, never in the browser.
        raise RuntimeError(
            "FLASK_SECRET_KEY is missing or still the placeholder. "
            "Edit your .env file and set a long random value (see README)."
        )

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secret_key,
        USER_AGENT=os.getenv("USER_AGENT", "PublicDomainDashboard/1.0 (educational project)"),
        REQUEST_TIMEOUT=_int_env("REQUEST_TIMEOUT", 8),
        DNS_TIMEOUT=_int_env("DNS_TIMEOUT", 4),
        CT_TIMEOUT=_int_env("CT_TIMEOUT", 20),
        MAX_RESPONSE_BYTES=_int_env("MAX_RESPONSE_BYTES", 262144),
        CT_MAX_RESPONSE_BYTES=_int_env("CT_MAX_RESPONSE_BYTES", 5242880),
        MAX_REDIRECTS=_int_env("MAX_REDIRECTS", 3),
        CT_MAX_ENTRIES=_int_env("CT_MAX_ENTRIES", 15),
        COOLDOWN_SECONDS=_int_env("COOLDOWN_SECONDS", 10),
        DATABASE_PATH=_path_env("DATABASE_PATH", "data/investigations.db"),
        REPORTS_DIR=_path_env("REPORTS_DIR", "reports"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=4096,  # our forms are tiny; reject anything bigger
    )

    Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    Path(app.config["REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)

    from .database import init_db
    from .routes import bp

    app.register_blueprint(bp)

    with app.app_context():
        init_db()  # creates the table if it does not exist yet

    @app.cli.command("init-db")
    def init_db_command():
        """Create the SQLite database (safe to run more than once)."""
        init_db()
        print("Database ready:", app.config["DATABASE_PATH"])

    @app.after_request
    def add_security_headers(response):
        """Browser-side protections. We use no inline scripts or styles."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'"
        )
        return response

    return app