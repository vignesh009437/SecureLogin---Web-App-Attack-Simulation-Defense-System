# SecureLogin — Attack Simulation & Defense System
A beginner-friendly cybersecurity project demonstrating common web attacks (SQL Injection, XSS, brute-force) and the defenses that stop them (WAF middleware, parameterized queries, rate limiting, security logging).

## Files
- `vulnerable_app.py` — intentionally insecure login app (your "attack" demo target)
- `attack_demo.py` — script that attacks the vulnerable app automatically
- `secure_app.py` — hardened version of the same app (your "defense" showcase)
- `requirements.txt` — Python dependencies

## Step 1 — Set up your environment
1. Install Python 3.10+ if you don't have it.
2. Open a terminal in the project folder.
3. Create a virtual environment (recommended, not required):
   ```
   python -m venv venv
   venv\Scripts\activate      (Windows)
   source venv/bin/activate   (Mac/Linux)
   ```
4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Step 2 — Run and demonstrate the ATTACK side (30%)
1. Start the vulnerable app:
   ```
   python vulnerable_app.py
   ```
2. In a second terminal, run the attack script:
   ```
   python attack_demo.py
   ```
3. You'll see the script:
   - Bypass the login using `admin' -- ` as the username (classic SQL Injection)
   - Reflect a raw `<script>` tag back in the page (XSS)
   - Brute-force a weak password with no lockout
4. For your project defense, you can also show this manually in a browser at `http://127.0.0.1:5000`:
   - Username: `admin' -- `, Password: anything → logs in without a real password
   - Username: `<script>alert('XSS')</script>` → the alert may pop up or the raw tag shows in the response

This is the part where you explain to evaluators: "This is what an unprotected web login looks like, and here's how an attacker would exploit it."

## Step 3 — Run and demonstrate the DEFENSE side (70%)
1. Stop the vulnerable app (Ctrl+C).
2. Start the secure app:
   ```
   python secure_app.py
   ```
3. Try the exact same attacks from Step 2 against this app — they will now fail:
   - SQL Injection input gets blocked by the WAF middleware with a `403 Forbidden`
   - XSS payloads are either blocked by the WAF or auto-escaped so the script never executes
   - After 5 failed logins within 60 seconds, that IP is locked out for 2 minutes
4. Open `security.log` in the project folder — show that every login attempt, WAF block, and lockout event was recorded with a timestamp and IP. This is your "SIEM-style" audit trail.

## Step 4 — Explain the defense mechanisms (use this for your viva/report)
| Layer | What it does | Why it matters |
|---|---|---|
| Parameterized SQL queries | Uses `?` placeholders instead of string concatenation | Makes SQL Injection structurally impossible |
| Jinja2 auto-escaping | Output isn't marked `\|safe`, so HTML is escaped | Prevents XSS from executing in the browser |
| WAF middleware (`before_request`) | Regex-matches incoming form data against known attack signatures | Catches attacks before they even reach your logic |
| Rate limiting / lockout | Tracks failed logins per IP, locks out after threshold | Stops brute-force password guessing |
| Security logging | Every event is logged with timestamp, IP, and type | Enables after-the-fact investigation (like a mini SIEM) |

## Step 5 — Optional extensions (if you want to go further)
- Add password hashing with `bcrypt` instead of storing plaintext passwords
- Add HTTPS via a self-signed cert to show encryption-in-transit
- Export `security.log` into a simple dashboard (Flask route that reads and displays recent events)
- Run OWASP ZAP against both apps and include the scan report comparison in your project report
- Add CSRF protection with `flask-wtf`

## How to present this in your resume
> "Built and demonstrated a web application security project showing common attack vectors (SQL Injection, XSS, brute-force) and implemented matching defenses (WAF-style input filtering, parameterized queries, rate limiting, audit logging) using Python/Flask."

## Safety note
Only run these attack scripts against your own local app. Never point `attack_demo.py` at a server you don't own or have permission to test.
