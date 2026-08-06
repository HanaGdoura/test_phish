import uuid
from functools import wraps

from flask import redirect, render_template, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from db import get_connection, init_db
from email_service import send_simulation_email

# Route definitions for authentication, dashboard, campaigns, groups, and landing pages.

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def register_routes(app):
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
                session["user_id"] = user["id"]
                session["username"] = user["username"]
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
                existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                if existing:
                    error = "That username already exists"
                else:
                    conn.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, generate_password_hash(password)),
                    )
                    conn.commit()
                    user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
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

    @app.route("/dashboard")
    @login_required
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

    @app.route("/landing", methods=["GET", "POST"])
    @login_required
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

    @app.route("/groups", methods=["GET", "POST"])
    @login_required
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

    @app.route("/campaigns", methods=["GET", "POST"])
    @login_required
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

    @app.route("/simulator", methods=["GET", "POST"])
    @login_required
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
