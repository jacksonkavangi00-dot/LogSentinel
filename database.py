
import sqlite3
from datetime import datetime

DB_NAME = "logsentinel.db"


def initialize_database():
    connection = sqlite3.connect(DB_NAME)

    try:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event TEXT NOT NULL,
                username TEXT,
                ip TEXT,
                service TEXT,
                severity TEXT,
                attempts INTEGER,
                detected_at TEXT
            )
        """)

        # Remove existing exact duplicates, keeping the oldest record.
        cursor.execute("""
            DELETE FROM incidents
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM incidents
                GROUP BY
                    timestamp,
                    event,
                    COALESCE(username, ''),
                    COALESCE(ip, ''),
                    COALESCE(service, ''),
                    COALESCE(severity, ''),
                    COALESCE(attempts, -1)
            )
        """)

        # Prevent the same incident fingerprint from being inserted again.
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_incidents
            ON incidents (
                timestamp,
                event,
                COALESCE(username, ''),
                COALESCE(ip, ''),
                COALESCE(service, ''),
                COALESCE(severity, ''),
                COALESCE(attempts, -1)
            )
        """)

        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()


def save_incidents(incidents):
    connection = sqlite3.connect(DB_NAME)
    inserted = 0

    try:
        cursor = connection.cursor()

        for incident in incidents:
            cursor.execute("""
                INSERT OR IGNORE INTO incidents (
                    timestamp,
                    event,
                    username,
                    ip,
                    service,
                    severity,
                    attempts,
                    detected_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.get("timestamp"),
                incident.get("event"),
                incident.get("username"),
                incident.get("ip"),
                incident.get("service"),
                incident.get("severity"),
                incident.get("attempts"),
                datetime.now().isoformat(timespec="seconds")
            ))

            inserted += cursor.rowcount

        connection.commit()

        print(f"New incidents saved: {inserted}")
        print(f"Duplicate incidents skipped: {len(incidents) - inserted}")

        return inserted

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_incidents():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT * FROM incidents
            ORDER BY id DESC
        """)

        return [dict(row) for row in cursor.fetchall()]

    finally:
        connection.close()


def get_incident_statistics():
    connection = sqlite3.connect(DB_NAME)

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM incidents
            GROUP BY severity
        """)

        return dict(cursor.fetchall())

    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()
    print("LogSentinel database initialized successfully.")
