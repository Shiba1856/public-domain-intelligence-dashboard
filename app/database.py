"""SQLite storage for investigation history (parameterised SQL only)."""
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from flask import current_app

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    created_at TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    results_json TEXT NOT NULL
)
"""


def _connect():
    conn = sqlite3.connect(current_app.config["DATABASE_PATH"])
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the table if it is missing."""
    with closing(_connect()) as conn:
        conn.execute(SCHEMA)
        conn.commit()


def save_investigation(domain, summary, results):
    """Store one finished investigation and return its id.

    Only public technical records are stored. No registrant contact details,
    credentials or user information are ever collected.
    """
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with closing(_connect()) as conn:
        cur = conn.execute(
            "INSERT INTO investigations (domain, created_at, summary_json, results_json) "
            "VALUES (?, ?, ?, ?)",
            (domain, created, json.dumps(summary), json.dumps(results)),
        )
        conn.commit()
        return cur.lastrowid


def get_investigation(inv_id):
    """Return one investigation as a dict, or None if it does not exist."""
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT * FROM investigations WHERE id = ?", (inv_id,)
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "domain": row["domain"],
        "created_at": row["created_at"],
        "summary": json.loads(row["summary_json"]),
        "results": json.loads(row["results_json"]),
    }


def list_recent(limit=10):
    """Return the most recent investigations (id, domain, date)."""
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT id, domain, created_at FROM investigations ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def clear_history():
    """Delete every stored investigation."""
    with closing(_connect()) as conn:
        conn.execute("DELETE FROM investigations")
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'investigations'")
        conn.commit()