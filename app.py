# Main Flask application entrypoint for the phishing simulation demo.
# This file contains the full app logic for auth, campaigns, groups, landing pages, and tracking.

import os
import smtplib
import sqlite3
import uuid
from datetime import timedelta
from functools import wraps

from flask import Flask, redirect, render_template, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import config

app = Flask(__name__)
app.config.from_object(config)

# Ensure session cookies are treated as sensitive and rotated for login/logout.
app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "phishing.db")
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_FROM = os.getenv("SMTP_FROM", "simulator@example.com")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "false").lower() == "true"
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(conn, table_name, column_name):
    return any(row[1] == column_name for row in conn.execute(f"PRAGMA table_info({table_name})"))


def migrate_user_scoping(conn):
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

    admin_user = conn.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
    admin_user_id = admin_user["id"] if admin_user else None

    conn.commit()
    conn.close()


init_db()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))

        if (
            session.get("ip") != request.remote_addr
            or session.get("user_agent") != request.headers.get("User-Agent")
        ):
            session.clear()
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


@app.before_request
def make_session_permanent():
    if session.get("user_id"):
        session.permanent = True


def send_simulation_email(to_email, tracking_id, subject, message_body):
    track_link = f"{BASE_URL}/track/{tracking_id}"
    body = message_body.strip() if message_body else "Please review this security alert."
    message = (
        f"Subject: {subject}\n\n"
        f"{body}\n\n"
        f"Verification link: {track_link}\n\n"
        "This is a simulated phishing email sent as part of an authorized training exercise."
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.starttls() if SMTP_USE_TLS else None
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_email], message)
        return True
    except (ConnectionRefusedError, OSError, smtplib.SMTPException) as error:
        print(f"Email delivery skipped: no SMTP server listening on {SMTP_HOST}:{SMTP_PORT} ({error})")
        return False


@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@app.route("/signin", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_connection()
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["ip"] = request.remote_addr
            session["user_agent"] = request.headers.get("User-Agent")
            return redirect(url_for("dashboard"))

        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "Username and password are required"
        else:
            conn = get_connection()
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if existing:
                error = "That username already exists"
            else:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                conn.commit()
                user_id = conn.execute(
                    "SELECT id FROM users WHERE username = ?",
                    (username,),
                ).fetchone()["id"]
                conn.close()
                session["user_id"] = user_id
                session["username"] = username
                return redirect(url_for("dashboard"))
            conn.close()

    return render_template("signup.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@login_required
@app.route("/dashboard")
def dashboard():
    conn = get_connection()
    user_id = session["user_id"]
    target_count = conn.execute("SELECT COUNT(*) AS count FROM targets WHERE user_id = ?", (user_id,)).fetchone()["count"]
    recipient_count = conn.execute("SELECT COUNT(*) AS count FROM campaign_recipients WHERE user_id = ?", (user_id,)).fetchone()["count"]
    clicked_count = conn.execute(
        "SELECT COUNT(*) AS count FROM campaign_recipients WHERE user_id = ? AND status = 'Lien cliqué'",
        (user_id,),
    ).fetchone()["count"]
    submitted_count = conn.execute(
        "SELECT COUNT(*) AS count FROM campaign_recipients WHERE user_id = ? AND status = 'Identifiants compromis'",
        (user_id,),
    ).fetchone()["count"]
    landing_count = conn.execute("SELECT COUNT(*) AS count FROM landing_pages WHERE user_id = ?", (user_id,)).fetchone()["count"]
    group_count = conn.execute("SELECT COUNT(*) AS count FROM groups WHERE user_id = ?", (user_id,)).fetchone()["count"]
    campaign_count = conn.execute("SELECT COUNT(*) AS count FROM campaigns WHERE user_id = ?", (user_id,)).fetchone()["count"]
    recent_campaigns = conn.execute(
        "SELECT name, status FROM campaigns WHERE user_id = ? ORDER BY id DESC LIMIT 5",
        (user_id,),
    ).fetchall()
    recent_targets = conn.execute(
        """
        SELECT cr.email, cr.status, cr.tracking_id, c.name AS campaign_name
        FROM campaign_recipients cr
        LEFT JOIN campaigns c ON cr.campaign_id = c.id
        WHERE cr.user_id = ?
        ORDER BY cr.id DESC
        LIMIT 10
        """,
        (user_id,),
    ).fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        target_count=target_count,
        recipient_count=recipient_count,
        clicked_count=clicked_count,
        submitted_count=submitted_count,
        landing_count=landing_count,
        group_count=group_count,
        campaign_count=campaign_count,
        recent_campaigns=recent_campaigns,
        recent_targets=recent_targets,
    )


@login_required
@app.route("/landing", methods=["GET", "POST"])
def landing_pages():
    conn = get_connection()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        content = request.form.get("content", "")
        if name:
            conn.execute(
                "INSERT INTO landing_pages (name, description, path, content_html, user_id) VALUES (?, ?, ?, ?, ?)",
                (name, description, "/landing", content, session["user_id"]),
            )
            conn.commit()
        conn.close()
        return redirect(url_for("landing_pages"))

    landing_pages = conn.execute(
        "SELECT id, name, description, path, content_html FROM landing_pages WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template("landing_pages.html", landing_pages=landing_pages)


@login_required
@app.route("/groups", methods=["GET", "POST"])
def groups():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        member_emails = request.form.get("member_emails", "").strip()
        if name:
            conn = get_connection()
            conn.execute(
                "INSERT INTO groups (name, description, member_emails, user_id) VALUES (?, ?, ?, ?)",
                (name, description, member_emails, session["user_id"]),
            )
            conn.commit()
            conn.close()
        return redirect(url_for("groups"))

    conn = get_connection()
    groups = conn.execute(
        "SELECT id, name, description, member_emails FROM groups WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template("groups.html", groups=groups)


@login_required
@app.route("/campaigns", methods=["GET", "POST"])
def campaigns():
    if request.method == "POST":
        campaign_name = request.form.get("campaign_name", "").strip()
        recipient_text = request.form.get("recipient_emails", "")
        subject = request.form.get("subject", "Security Awareness Training").strip() or "Security Awareness Training"
        message_body = request.form.get("message_body", "")
        group_id = request.form.get("group_id") or None
        landing_page_id = request.form.get("landing_page_id") or None

        if campaign_name and recipient_text:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO campaigns (name, status, group_id, landing_page_id, subject, message_body, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (campaign_name, "Running", group_id, landing_page_id, subject, message_body, session["user_id"]),
            )
            campaign_id = cursor.lastrowid

            recipients = [email.strip() for email in recipient_text.replace("\n", ",").split(",") if email.strip()]
            if group_id:
                group_row = conn.execute(
                    "SELECT member_emails FROM groups WHERE id = ? AND user_id = ?",
                    (group_id, session["user_id"]),
                ).fetchone()
                if group_row and group_row["member_emails"]:
                    group_emails = [email.strip() for email in group_row["member_emails"].replace("\n", ",").split(",") if email.strip()]
                    recipients.extend(group_emails)

            seen = set()
            final_recipients = []
            for email in recipients:
                if email.lower() not in seen:
                    seen.add(email.lower())
                    final_recipients.append(email)

            for email in final_recipients:
                tracking_id = str(uuid.uuid4())[:8]
                cursor.execute(
                    "INSERT INTO campaign_recipients (campaign_id, email, tracking_id, status, user_id) VALUES (?, ?, ?, ?, ?)",
                    (campaign_id, email, tracking_id, "Envoyé", session["user_id"]),
                )
                conn.commit()
                send_simulation_email(email, tracking_id, subject, message_body)

            cursor.execute("UPDATE campaigns SET status = ? WHERE id = ?", ("Completed", campaign_id))
            conn.commit()
            conn.close()

        return redirect(url_for("campaigns"))

    conn = get_connection()
    campaigns_data = conn.execute(
        """
        SELECT c.id, c.name, c.status, g.name AS group_name, l.name AS landing_name,
               (SELECT COUNT(*) FROM campaign_recipients cr WHERE cr.campaign_id = c.id) AS recipient_count,
               (SELECT COUNT(*) FROM campaign_recipients cr WHERE cr.campaign_id = c.id AND cr.status = 'Lien cliqué') AS clicked_count,
               (SELECT COUNT(*) FROM campaign_recipients cr WHERE cr.campaign_id = c.id AND cr.status = 'Identifiants compromis') AS submitted_count
        FROM campaigns c
        LEFT JOIN groups g ON c.group_id = g.id
        LEFT JOIN landing_pages l ON c.landing_page_id = l.id
        WHERE c.user_id = ?
        ORDER BY c.id DESC
        """,
        (session["user_id"],),
    ).fetchall()
    recipient_rows = conn.execute(
        "SELECT campaign_id, email, status FROM campaign_recipients WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    groups_data = conn.execute(
        "SELECT id, name FROM groups WHERE user_id = ? ORDER BY id",
        (session["user_id"],),
    ).fetchall()
    landing_pages_data = conn.execute(
        "SELECT id, name FROM landing_pages WHERE user_id = ? ORDER BY id",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template(
        "campaigns.html",
        campaigns=campaigns_data,
        recipient_rows=recipient_rows,
        groups=groups_data,
        landing_pages=landing_pages_data,
    )


@login_required
@app.route("/simulator", methods=["GET", "POST"])
def simulator_dashboard():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if email:
            tracking_id = str(uuid.uuid4())[:8]

            conn = get_connection()
            conn.execute(
                "INSERT INTO targets (tracking_id, email, status, user_id) VALUES (?, ?, ?, ?)",
                (tracking_id, email, "Envoyé", session["user_id"]),
            )
            conn.commit()
            conn.close()

            send_simulation_email(email, tracking_id, "Security Awareness Training", "Please review this security alert.")

        return redirect(url_for("simulator_dashboard"))

    conn = get_connection()
    targets = conn.execute(
        "SELECT * FROM targets WHERE user_id = ? ORDER BY tracking_id",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template("simulator_dashboard.html", targets=targets)


@app.route("/track/<tracking_id>", methods=["GET"])
def track(tracking_id):
    conn = get_connection()
    conn.execute(
        "UPDATE targets SET status = ? WHERE tracking_id = ?",
        ("Lien cliqué", tracking_id),
    )
    conn.execute(
        "UPDATE campaign_recipients SET status = ? WHERE tracking_id = ?",
        ("Lien cliqué", tracking_id),
    )
    conn.commit()

    row = conn.execute(
        """
        SELECT lp.content_html
        FROM campaign_recipients cr
        JOIN campaigns c ON cr.campaign_id = c.id
        LEFT JOIN landing_pages lp ON c.landing_page_id = lp.id
        WHERE cr.tracking_id = ?
        """,
        (tracking_id,),
    ).fetchone()
    conn.close()

    content_html = row["content_html"] if row and row["content_html"] else """
    <div class=\"container py-5\">
      <div class=\"card shadow-sm\">
        <div class=\"card-body\">
          <h2 class=\"h4\">Security Verification</h2>
          <p>Please confirm your identity to continue.</p>
          <form method=\"post\" action=\"/submit/{{ tracking_id }}\">
            <div class=\"mb-3\">
              <label class=\"form-label\">Email</label>
              <input class=\"form-control\" name=\"email\" type=\"email\" required>
            </div>
            <div class=\"mb-3\">
              <label class=\"form-label\">Password</label>
              <input class=\"form-control\" name=\"password\" type=\"password\" required>
            </div>
            <button class=\"btn btn-primary\">Submit</button>
          </form>
        </div>
      </div>
    </div>
    """

    return render_template_string(content_html, tracking_id=tracking_id)


@app.route("/submit/<tracking_id>", methods=["POST"])
def submit(tracking_id):
    conn = get_connection()
    conn.execute(
        "UPDATE targets SET status = ? WHERE tracking_id = ?",
        ("Identifiants compromis", tracking_id),
    )
    conn.execute(
        "UPDATE campaign_recipients SET status = ? WHERE tracking_id = ?",
        ("Identifiants compromis", tracking_id),
    )
    conn.commit()
    conn.close()

    return redirect("https://wikipedia.org")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
