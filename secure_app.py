"""
SECURED VERSION — demonstrates defense techniques:
  1. Parameterized SQL queries (no SQL injection)
  2. Output escaping (no XSS) via Jinja2 autoescaping
  3. A mini WAF middleware that pattern-matches malicious input and blocks it
  4. Rate limiting / IP lockout after repeated failed logins (brute-force defense)
  5. Security logging to a file (SIEM-style audit trail)
"""

from flask import Flask, request, render_template_string, abort
import sqlite3
import os
import re
import time
import logging
from collections import defaultdict

app = Flask(__name__)
DB = "secure.db"

# ---------- Logging setup (defense: audit trail) ----------
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


def log_event(event_type, ip, details):
    logging.info(f"{event_type} | IP={ip} | {details}")


# ---------- DB setup ----------
def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'SuperSecret123')")
    conn.execute("INSERT INTO users (username, password) VALUES ('veeee', 'mypassword')")
    conn.commit()
    conn.close()


# ---------- WAF: simple malicious-pattern detector ----------
SQLI_PATTERNS = [
    r"(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",  # OR 1=1
    r"--",            # SQL comment
    r";\s*DROP\s",    # stacked query drop
    r"UNION\s+SELECT",
    r"'\s*OR\s*'",
]
XSS_PATTERNS = [
    r"<script.*?>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
]


def is_malicious(value: str) -> str | None:
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return "SQL_INJECTION_ATTEMPT"
    for pattern in XSS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return "XSS_ATTEMPT"
    return None


@app.before_request
def waf_middleware():
    """Inspect every incoming request's form fields for attack patterns."""
    ip = request.remote_addr
    for field_name, value in request.form.items():
        threat = is_malicious(value)
        if threat:
            log_event(threat, ip, f"field={field_name} value={value!r} BLOCKED")
            abort(403, description="Request blocked by WAF: suspicious input detected.")


# ---------- Rate limiting / brute-force lockout ----------
failed_attempts = defaultdict(list)  # ip -> list of failure timestamps
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60
LOCKOUT_SECONDS = 120
blocked_until = {}


def is_locked_out(ip):
    until = blocked_until.get(ip)
    if until and time.time() < until:
        return True
    return False


def register_failure(ip):
    now = time.time()
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < WINDOW_SECONDS]
    failed_attempts[ip].append(now)
    if len(failed_attempts[ip]) >= MAX_ATTEMPTS:
        blocked_until[ip] = now + LOCKOUT_SECONDS
        log_event("BRUTE_FORCE_LOCKOUT", ip, f"{MAX_ATTEMPTS} failures in {WINDOW_SECONDS}s, locked for {LOCKOUT_SECONDS}s")


LOGIN_PAGE = """
<h2>Secure Login</h2>
<form method="POST">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
<p>{{ message }}</p>
"""
# NOTE: no |safe filter here -> Jinja2 auto-escapes output, defeating XSS


@app.route("/", methods=["GET", "POST"])
def login():
    ip = request.remote_addr
    message = ""

    if is_locked_out(ip):
        log_event("BLOCKED_LOGIN_ATTEMPT", ip, "IP currently locked out")
        return render_template_string(LOGIN_PAGE, message="Too many failed attempts. Try again later."), 429

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # DEFENSE: parameterized query, never string-concatenated
        conn = sqlite3.connect(DB)
        cursor = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            message = f"Welcome, {username}!"
            log_event("LOGIN_SUCCESS", ip, f"user={username}")
            failed_attempts[ip] = []  # reset on success
        else:
            message = "Invalid username or password."
            register_failure(ip)
            log_event("LOGIN_FAILURE", ip, f"attempted_user={username}")

    return render_template_string(LOGIN_PAGE, message=message)


@app.errorhandler(403)
def forbidden(e):
    return {"error": "Blocked by WAF", "detail": str(e.description)}, 403


if __name__ == "__main__":
    init_db()
    print("Secure app running on http://127.0.0.1:5000")
    print("Security events are logged to security.log")
    app.run(port=5000)
