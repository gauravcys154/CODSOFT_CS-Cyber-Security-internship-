"""
Sample Application: User Login & Notes Manager
------------------------------------------------
THIS IS THE 'BEFORE' VERSION — intentionally written with common
real-world security flaws, for the purpose of Task 3: Secure Code
Assessment (CODSOFT Cyber Security Internship).

DO NOT deploy this file. See security_assessment_report.md for the
full list of vulnerabilities found here, and secure_app_AFTER.py for
the fixed version.
"""

from flask import Flask, request, redirect, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "12345"                     # (VULN) Hardcoded, weak secret key

DB = "users.db"


def get_db():
    return sqlite3.connect(DB)


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, username TEXT, password TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS notes
                     (id INTEGER PRIMARY KEY, user TEXT, content TEXT)""")
    conn.commit()
    conn.close()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()      # (VULN) MD5 is broken for passwords
    conn = get_db()
    # (VULN) SQL Injection - raw string formatting into query
    conn.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed}')")
    conn.commit()
    return "Registered!"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    # (VULN) SQL Injection - user input concatenated directly into query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
    user = conn.execute(query).fetchone()
    if user:
        session["user"] = username
        return redirect("/notes")
    return "Invalid credentials"                              # (VULN) No rate limiting / lockout


@app.route("/notes", methods=["GET", "POST"])
def notes():
    user = session.get("user")
    if not user:
        return "Not logged in"
    conn = get_db()
    if request.method == "POST":
        content = request.form["content"]
        conn.execute(f"INSERT INTO notes (user, content) VALUES ('{user}', '{content}')")
        conn.commit()
    # (VULN) No output encoding -> stored XSS when notes are rendered
    rows = conn.execute(f"SELECT content FROM notes WHERE user='{user}'").fetchall()
    html = "<h1>Your Notes</h1>"
    for r in rows:
        html += f"<p>{r[0]}</p>"                              # (VULN) reflected/stored XSS
    return html


@app.route("/admin/debug")
def debug():
    # (VULN) Debug endpoint leaks internal info, no auth check
    return {"secret_key": app.secret_key, "db_path": DB}


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0")                       # (VULN) debug=True + bind to all interfaces in "prod"
