# Task 5 — Secure File Sharing System

A Flask web application demonstrating secure file storage and sharing, built for the
CODSOFT Cyber Security Internship.

## Features
- **Authentication** — user registration and login with `bcrypt` password hashing.
- **Encryption at rest** — every uploaded file is encrypted with a `Fernet`
  (AES-128-CBC + HMAC) symmetric key before being written to disk; files are
  decrypted only in memory at download time and never stored in plaintext.
- **Role-Based Access Control (RBAC)** — `admin` role can view/download all files and
  the audit log; regular `user` role can only access their own files plus files marked
  `shared`.
- **Bonus: temporary download links** — any file owner can generate a one-time token
  link (`/s/<token>`) that expires automatically after 30 minutes, usable without login.
- **Audit logging** — every login, upload, download, and share-link event is recorded
  with actor, action, and UTC timestamp; visible to admins at `/admin/audit`.

## Setup
```bash
cd Task5_Secure_File_Sharing
pip install -r requirements.txt
python app.py
```
Visit `http://127.0.0.1:5000`. A default admin account is auto-created on first run:
- username: `admin`
- password: `Admin@12345`

*(Change this password immediately in any real deployment — it exists here only to
demonstrate the RBAC admin view.)*

## How the security features were verified
This app was tested end-to-end during development:
1. Uploaded a file and confirmed the on-disk copy in `uploads/` is unreadable
   ciphertext (Fernet token), not the original content.
2. Downloaded the same file as the owner and confirmed correct decryption.
3. Generated a temporary share link and downloaded the file through it with
   **no login cookie at all** — confirming public, time-boxed access works.
4. Registered a second user ("bob") and confirmed he receives **HTTP 403** when
   trying to access another user's private file directly by ID.
5. Confirmed the `admin` account can access any file and the audit log, while a
   regular user gets **403** on `/admin/audit`.

## Project structure
```
Task5_Secure_File_Sharing/
├── app.py              # main Flask application
├── requirements.txt
├── templates/           # Jinja2 templates (auto-escaped -> no XSS)
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── audit.html
└── uploads/              # encrypted file blobs live here (.enc, gitignored)
```

## Notes / production hardening ideas
- Swap the in-process Fernet key file for a proper secrets manager (AWS KMS,
  HashiCorp Vault) in production.
- Move from SQLite to a managed database for concurrent access at scale.
- Add HTTPS termination (reverse proxy / TLS certs) — this demo runs on plain HTTP
  locally only.
- Add per-file access-control lists instead of the simplified private/shared model.
