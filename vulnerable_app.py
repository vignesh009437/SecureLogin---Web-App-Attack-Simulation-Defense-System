"""
VULNERABLE VERSION — for demo purposes only.
Shows SQL Injection, XSS, and brute-force vulnerabilities.
Run this first to show the "attack" side of your project.
"""

from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)
DB = "vulnerable.db"


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'SuperSecret123')")
    conn.execute("INSERT INTO users (username, password) VALUES ('veeee', 'mypassword')")
    conn.commit()
    conn.close()


LOGIN_PAGE = """
<h2>Vulnerable Login</h2>
<form method="POST">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
<p>{{ message|safe }}</p>
"""
# NOTE: {{ message|safe }} above intentionally disables auto-escaping -> XSS vulnerable


@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE: raw string concatenation -> SQL Injection
        conn = sqlite3.connect(DB)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("Running query:", query)
        try:
            cursor = conn.execute(query)
            user = cursor.fetchone()
        except sqlite3.Error as e:
            user = None
            message = f"DB error: {e}"
        conn.close()

        if user:
            message = f"Welcome, {username}!"  # also reflects input unescaped -> XSS
        else:
            message = message or f"Login failed for user: {username}"

    return render_template_string(LOGIN_PAGE, message=message)


if __name__ == "__main__":
    init_db()
    print("Vulnerable app running on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
