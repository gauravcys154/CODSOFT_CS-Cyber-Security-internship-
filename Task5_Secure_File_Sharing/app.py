"""
Secure File Sharing System — CODSOFT Cyber Security Internship, Task 5
------------------------------------------------------------------------
Features:
  - User authentication (bcrypt password hashing)
  - Role-Based Access Control (admin / user)
  - Files encrypted at rest with Fernet (AES-128-CBC + HMAC) symmetric encryption
  - Authenticated upload/download
  - Bonus: temporary download links with expiration timestamps
  - Per-request audit log (who accessed what, when)

Run:
    pip install -r requirements.txt
    python app.py
Then visit http://127.0.0.1:5000
"""

import os
import sqlite3
import secrets
import datetime
from functools import wraps

from flask import (Flask, request, redirect, session, render_template,
                    send_file, flash, url_for, abort)
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import bcrypt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "filesharing.db")
KEY_PATH = os.path.join(BASE_DIR, "secret.key")
LINK_EXPIRY_MINUTES = 30

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", secrets.token_hex(32))


# ---------------------------------------------------------------- encryption
def load_or_create_key():
    """Load the Fernet encryption key, generating one on first run."""
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key


FERNET = Fernet(load_or_create_key())


# ---------------------------------------------------------------- database
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'   -- 'user' or 'admin'
    );
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        uploaded_at TEXT NOT NULL,
        visibility TEXT NOT NULL DEFAULT 'private'  -- 'private' or 'shared'
    );
    CREATE TABLE IF NOT EXISTS share_links (
        token TEXT PRIMARY KEY,
        file_id INTEGER NOT NULL,
        created_by TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(file_id) REFERENCES files(id)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT,
        action TEXT,
        detail TEXT,
        ts TEXT
    );
    """)
    # seed a default admin (change password on first login in real use)
    existing = conn.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone()
    if not existing:
        pw_hash = bcrypt.hashpw(b"Admin@12345", bcrypt.gensalt()).decode()
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                     ("admin", pw_hash))
    conn.commit()
    conn.close()


def log_action(actor, action, detail=""):
    conn = get_db()
    conn.execute("INSERT INTO audit_log (actor, action, detail, ts) VALUES (?, ?, ?, ?)",
                 (actor, action, detail, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- auth helpers
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get("role") != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------- routes
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or len(password) < 8:
            flash("Username required; password must be at least 8 characters.")
            return redirect(url_for("register"))
        conn = get_db()
        try:
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                         (username, pw_hash))
            conn.commit()
            log_action(username, "REGISTER")
        except sqlite3.IntegrityError:
            flash("Username already taken.")
            return redirect(url_for("register"))
        finally:
            conn.close()
        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            session["user"] = username
            session["role"] = user["role"]
            log_action(username, "LOGIN_SUCCESS")
            return redirect(url_for("dashboard"))
        log_action(username, "LOGIN_FAILED")
        flash("Invalid credentials.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    log_action(session.get("user", "?"), "LOGOUT")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    if session["role"] == "admin":
        files = conn.execute("SELECT * FROM files ORDER BY uploaded_at DESC").fetchall()
    else:
        files = conn.execute(
            "SELECT * FROM files WHERE owner = ? OR visibility = 'shared' ORDER BY uploaded_at DESC",
            (session["user"],)).fetchall()
    conn.close()
    return render_template("dashboard.html", files=files, role=session["role"], user=session["user"])


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    visibility = request.form.get("visibility", "private")
    if not f or f.filename == "":
        flash("No file selected.")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(f.filename)
    stored_name = f"{secrets.token_hex(16)}.enc"   # random name on disk, real name kept only in DB
    plaintext = f.read()

    # FIX/feature: encrypt file contents before writing to disk
    ciphertext = FERNET.encrypt(plaintext)
    with open(os.path.join(UPLOAD_DIR, stored_name), "wb") as out:
        out.write(ciphertext)

    conn = get_db()
    conn.execute(
        "INSERT INTO files (owner, original_name, stored_name, uploaded_at, visibility) VALUES (?, ?, ?, ?, ?)",
        (session["user"], original_name, stored_name, datetime.datetime.utcnow().isoformat(), visibility))
    conn.commit()
    conn.close()
    log_action(session["user"], "UPLOAD", original_name)
    flash(f"'{original_name}' uploaded and encrypted successfully.")
    return redirect(url_for("dashboard"))


def _can_access(file_row, user, role):
    return role == "admin" or file_row["owner"] == user or file_row["visibility"] == "shared"


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    conn = get_db()
    file_row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    if not file_row:
        abort(404)
    if not _can_access(file_row, session["user"], session["role"]):
        log_action(session["user"], "DOWNLOAD_DENIED", file_row["original_name"])
        abort(403)

    return _decrypt_and_send(file_row)


def _decrypt_and_send(file_row):
    enc_path = os.path.join(UPLOAD_DIR, file_row["stored_name"])
    with open(enc_path, "rb") as f:
        ciphertext = f.read()
    plaintext = FERNET.decrypt(ciphertext)

    tmp_path = os.path.join(UPLOAD_DIR, f"_tmp_{secrets.token_hex(8)}_{file_row['original_name']}")
    with open(tmp_path, "wb") as f:
        f.write(plaintext)
    log_action(session.get("user", "link"), "DOWNLOAD", file_row["original_name"])

    response = send_file(tmp_path, as_attachment=True, download_name=file_row["original_name"])
    response.call_on_close(lambda: os.remove(tmp_path) if os.path.exists(tmp_path) else None)
    return response


# ------------------------------------------------------- bonus: expiring links
@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def create_share_link(file_id):
    conn = get_db()
    file_row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row or not _can_access(file_row, session["user"], session["role"]):
        conn.close()
        abort(403)

    token = secrets.token_urlsafe(24)
    expires_at = (datetime.datetime.utcnow() +
                  datetime.timedelta(minutes=LINK_EXPIRY_MINUTES)).isoformat()
    conn.execute("INSERT INTO share_links (token, file_id, created_by, expires_at) VALUES (?, ?, ?, ?)",
                 (token, file_id, session["user"], expires_at))
    conn.commit()
    conn.close()
    log_action(session["user"], "CREATE_SHARE_LINK", file_row["original_name"])
    link = url_for("shared_download", token=token, _external=True)
    flash(f"Temporary link (expires in {LINK_EXPIRY_MINUTES} min): {link}")
    return redirect(url_for("dashboard"))


@app.route("/s/<token>")
def shared_download(token):
    conn = get_db()
    link = conn.execute("SELECT * FROM share_links WHERE token = ?", (token,)).fetchone()
    if not link:
        conn.close()
        abort(404)
    if datetime.datetime.fromisoformat(link["expires_at"]) < datetime.datetime.utcnow():
        conn.close()
        log_action("anonymous", "SHARE_LINK_EXPIRED", token)
        return "This link has expired.", 410

    file_row = conn.execute("SELECT * FROM files WHERE id = ?", (link["file_id"],)).fetchone()
    conn.close()
    if not file_row:
        abort(404)
    session_user_backup = session.get("user", "anonymous_link_user")
    log_action(session_user_backup, "SHARE_LINK_DOWNLOAD", file_row["original_name"])
    return _decrypt_and_send(file_row)


@app.route("/admin/audit")
@login_required
@role_required("admin")
def audit():
    conn = get_db()
    logs = conn.execute("SELECT * FROM audit_log ORDER BY ts DESC LIMIT 200").fetchall()
    conn.close()
    return render_template("audit.html", logs=logs)


if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="127.0.0.1", port=5000)
