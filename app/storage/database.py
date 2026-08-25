import sqlite3
from pathlib import Path

DB_PATH = Path("sentinelsoc.db")


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                description TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                UNIQUE(timestamp, rule, ip, username)
            )
        """)

        connection.commit()


def save_alert(alert):
    with get_connection() as connection:

        cursor = connection.execute("""
            INSERT OR IGNORE INTO alerts
            (
                timestamp,
                severity,
                rule,
                ip,
                username,
                attempts,
                description,
                risk_score,
                risk_level
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.timestamp.isoformat(),
            alert.severity,
            alert.rule,
            alert.ip,
            alert.username,
            alert.attempts,
            alert.description,
            alert.risk_score,
            alert.risk_level,
        ))

        connection.commit()

        return cursor.rowcount == 1


def get_alerts():
    with get_connection() as connection:

        return connection.execute("""
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC
        """).fetchall()