import sqlite3
from werkzeug.security import generate_password_hash

from config import DATABASE

# Database helpers for creating the SQLite schema and opening connections.

def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(conn, table_name, column_name):
    return any(row[1] == column_name for row in conn.execute(f"PRAGMA table_info({table_name})"))


def migrate_user_scoping(conn):
    # Ensure older database rows get the new user_id column and are assigned safely.
    table_columns = {
        "targets": [("user_id", "INTEGER")],
        "landing_pages": [("content_html", "TEXT"), ("user_id", "INTEGER")],
        "groups": [("member_emails", "TEXT"), ("user_id", "INTEGER")],
        "campaigns": [("subject", "TEXT"), ("message_body", "TEXT"), ("user_id", "INTEGER")],
        "campaign_recipients": [("user_id", "INTEGER")],
    }
    default_user = conn.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
    default_user_id = default_user["id"] if default_user else None

    for table_name, columns in table_columns.items():
        for column_name, column_type in columns:
            if not column_exists(conn, table_name, column_name):
                conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")

    if default_user_id is not None:
        for table_name in ["targets", "landing_pages", "groups", "campaigns"]:
            conn.execute(f"UPDATE {table_name} SET user_id = ? WHERE user_id IS NULL", (default_user_id,))

        conn.execute(
            """
            UPDATE campaign_recipients
            SET user_id = (
                SELECT c.user_id
                FROM campaigns c
                WHERE c.id = campaign_recipients.campaign_id
            )
            WHERE user_id IS NULL
            """
        )

    conn.commit()


def init_db():
    # Create the database tables if they do not exist yet and seed the default admin user.
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS targets (
            tracking_id TEXT PRIMARY KEY,
            email TEXT,
            status TEXT,
            user_id INTEGER
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS landing_pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            path TEXT NOT NULL,
            content_html TEXT,
            user_id INTEGER
        );

        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            member_emails TEXT,
            user_id INTEGER
        );

        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            group_id INTEGER,
            landing_page_id INTEGER,
            subject TEXT,
            message_body TEXT,
            user_id INTEGER
        );

        CREATE TABLE IF NOT EXISTS campaign_recipients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            tracking_id TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'Envoyé',
            user_id INTEGER
        );
        """
    )
    conn.commit()

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", generate_password_hash("password123")),
        )

    migrate_user_scoping(conn)
    conn.commit()
    conn.close()
