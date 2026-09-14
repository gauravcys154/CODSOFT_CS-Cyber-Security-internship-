"""
Sample Application: User Login & Notes Manager
------------------------------------------------
THIS IS THE 'AFTER' (FIXED) VERSION — all vulnerabilities identified
in vulnerable_app_BEFORE.py have been remediated here.

Fixes applied:
  1. Parameterized SQL queries (prevents SQL Injection)
  2. bcrypt password hashing with per-user salt (prevents weak-hash cracking)
  3. Auto-generated secret key loaded from environment variable
  4. Jinja2 auto-escaping via render_template_string (prevents XSS)
  5. Debug endpoint removed / gated behind auth
  6. debug=False for any non-dev run; basic login attempt limiting
"""

import os
import sqlite3
from flask import Flask, request, redirect, session, render_template_string
import bcrypt

app = Flask(__name__)
# FIX: secret key comes from environment, never hardcoded
app.secret_key = os.environ.get("APP_SECRET_KEY", os.urandom(32))

DB = "users.db"
failed_attempts = {}          # simple in-memory throttle: {username: count}
MAX_ATTEMPTS = 5


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS notes
                     (id INTEGER PRIMARY KEY, user TEXT, content TEXT)""")
    conn.commit()
    conn.close()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"].strip()
    password = request.form["password"]

    if not username or len(password) < 8:
        return "Username required and password must be >= 8 characters", 400

    # FIX: bcrypt with automatic per-user salt, adaptive cost factor
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    conn = get_db()
    try:
        # FIX: parameterized query — no string interpolation of user input
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
    except sqlite3.IntegrityError:
        return "Username already exists", 409
    finally:
        conn.close()
    return "Registered!"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"].strip()
    password = request.form["password"]

    # FIX: basic brute-force throttling
    if failed_attempts.get(username, 0) >= MAX_ATTEMPTS:
        return "Account temporarily locked due to repeated failed attempts", 429

    conn = get_db()
    # FIX: parameterized query
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
        failed_attempts.pop(username, None)
        session["user"] = username
        session.permanent = False
        return redirect("/notes")

    failed_attempts[username] = failed_attempts.get(username, 0) + 1
    return "Invalid credentials", 401


@app.route("/notes", methods=["GET", "POST"])
def notes():
    user = session.get("user")
    if not user:
        return "Not logged in", 401

    conn = get_db()
    if request.method == "POST":
        content = request.form["content"]
        # FIX: parameterized insert
        conn.execute("INSERT INTO notes (user, content) VALUES (?, ?)", (user, content))
        conn.commit()

    # FIX: parameterized select
    rows = conn.execute("SELECT content FROM notes WHERE user = ?", (user,)).fetchall()
    conn.close()

    # FIX: render_template_string auto-escapes {{ content }}, preventing stored XSS
    template = """
    <h1>Your Notes</h1>
    {% for r in rows %}
      <p>{{ r['content'] }}</p>
    {% endfor %}
    """
    return render_template_string(template, rows=rows)


# FIX: debug endpoint removed entirely — never expose secrets/internal config


if __name__ == "__main__":
    init_db()
    # FIX: debug disabled, bind restricted to localhost for local testing
    app.run(debug=False, host="127.0.0.1", port=5000)
