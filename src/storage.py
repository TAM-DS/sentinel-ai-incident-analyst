"""Local SQLite evidence storage for SENTINEL."""

import hashlib
import json
import sqlite3
from pathlib import Path

DATABASE = Path(__file__).resolve().parent.parent / "data" / "sentinel.db"


def initialize_db(db_path=DATABASE):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT NOT NULL UNIQUE,
                timestamp TEXT,
                source TEXT NOT NULL,
                priority TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)


def save_events(events, db_path=DATABASE):
    """Store records; ignore exact duplicates."""
    initialize_db(db_path)
    inserted = 0

    with sqlite3.connect(db_path) as conn:
        for event in events:
            payload = {
                "timestamp": event.get("timestamp"),
                "source": event.get("source", "unknown"),
                "priority": event.get("priority", "unknown"),
                "message": event.get("message", ""),
            }

            event_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode()
            ).hexdigest()

            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO events
                (event_hash, timestamp, source, priority, message)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event_hash,
                    payload["timestamp"],
                    payload["source"],
                    payload["priority"],
                    payload["message"],
                ),
            )

            inserted += cursor.rowcount

    return inserted


def count_events(db_path=DATABASE):
    initialize_db(db_path)

    with sqlite3.connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
