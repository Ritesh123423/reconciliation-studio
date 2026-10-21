import os
import secrets
import sqlite3
import time
from functools import wraps
from pathlib import Path

from flask import Flask, Response, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DB_PATH", BASE_DIR / "data" / "users.db"))
TOOL_PATH = BASE_DIR / "index.html"

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable must be set (used to sign session cookies)."
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") != "development",
)

# In-memory login throttling: {username: (fail_count, locked_until_ts)}.
# Resets on process restart - fine for a single-instance deployment.
_login_attempts = {}


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()

    user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if user_count == 0:
        admin_user = os.environ.get("ADMIN_USERNAME")
        admin_pass = os.environ.get("ADMIN_PASSWORD")
        if admin_user and admin_pass:
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                    (admin_user, generate_password_hash(admin_pass)),
                )
                conn.commit()
                app.logger.warning("Seeded initial admin user '%s'.", admin_user)
            except sqlite3.IntegrityError:
                # Another worker process won the race to seed the first admin; fine.
                pass
        else:
            app.logger.warning(
                "No users exist yet and ADMIN_USERNAME/ADMIN_PASSWORD are not set - "
                "no one will be able to log in until an admin is seeded."
            )
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


def require_csrf():
    token = session.get("csrf_token")
    if not token or not secrets.compare_digest(token, request.form.get("csrf_token", "")):
        abort(400, description="Invalid or missing CSRF token.")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        require_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        attempt = _login_attempts.get(username)
        if attempt and attempt[1] > time.time():
            error = "Too many failed attempts. Try again in a few minutes."
        else:
            conn = get_db()
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            conn.close()

            if row and check_password_hash(row["password_hash"], password):
                _login_attempts.pop(username, None)
                session.clear()
                session["user_id"] = row["id"]
                session["username"] = row["username"]
                session["is_admin"] = bool(row["is_admin"])
                next_url = request.args.get("next") or url_for("index")
                return redirect(next_url)

            fails = (attempt[0] + 1) if attempt else 1
            locked_until = time.time() + LOCKOUT_SECONDS if fails >= MAX_LOGIN_ATTEMPTS else 0
            _login_attempts[username] = (fails, locked_until)
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    conn = get_db()
    error = None

    if request.method == "POST":
        require_csrf()
        action = request.form.get("action")

        if action == "create":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            is_admin = 1 if request.form.get("is_admin") else 0

            if not username or not password:
                error = "Username and password are required."
            elif len(password) < 8:
                error = "Password must be at least 8 characters."
            else:
                try:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password), is_admin),
                    )
                    conn.commit()
                except sqlite3.IntegrityError:
                    error = f"Username '{username}' already exists."

        elif action == "delete":
            user_id = request.form.get("user_id", "")
            if str(session.get("user_id")) == user_id:
                error = "You can't delete the account you're currently logged in as."
            else:
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()

    users = conn.execute(
        "SELECT id, username, is_admin, created_at FROM users ORDER BY created_at"
    ).fetchall()
    conn.close()
    return render_template("admin.html", users=users, error=error)


_tool_html_cache = {}


def get_tool_html(is_admin):
    """Serve index.html byte-for-byte, with a small floating session badge
    injected before </body>. Cached per variant so the 12MB file is only
    read and patched once per process, not on every request."""
    variant = "admin" if is_admin else "user"
    if variant not in _tool_html_cache:
        html = TOOL_PATH.read_text(encoding="utf-8")
        admin_link = (
            '<a href="/admin" style="color:#ea580c;text-decoration:none;font-weight:600">Admin</a>'
            if is_admin
            else ""
        )
        badge = f"""
<div style="position:fixed;top:10px;right:14px;z-index:99999;display:flex;align-items:center;gap:10px;
  font-family:'Inter',-apple-system,'Segoe UI',Roboto,sans-serif;font-size:12.5px;color:#4a5472;
  background:#fff;border:1px solid #e3e8f2;border-radius:8px;padding:6px 10px;box-shadow:0 2px 8px rgba(18,26,53,.1)">
  {admin_link}
  <a href="/logout" style="color:#4a5472;text-decoration:none;font-weight:500">Log out</a>
</div>
"""
        html = html.replace("</body>", badge + "</body>")
        _tool_html_cache[variant] = html
    return _tool_html_cache[variant]


@app.route("/")
@login_required
def index():
    return Response(get_tool_html(session.get("is_admin", False)), mimetype="text/html")


init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_ENV") == "development")
