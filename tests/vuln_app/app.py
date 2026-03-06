"""
Intentionally vulnerable Flask app for testing Senshi.

DO NOT DEPLOY THIS IN PRODUCTION. It has intentional vulnerabilities:
- SQL injection in /search
- Reflected XSS in /greet
- SSRF in /fetch
- IDOR in /api/users/<id>
- Hardcoded API key
- Command injection in /ping
- Missing auth on /admin/users
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import urllib.request

from flask import Flask, jsonify, redirect, request

app = Flask(__name__)

# VULN: Hardcoded API key
API_KEY = "sk-senshi-test-key-12345-do-not-use-in-production"
SECRET_TOKEN = "super_secret_admin_token_abc123"

# Initialize SQLite database
DB_PATH = os.path.join(os.path.dirname(__file__), "test.db")


def init_db() -> None:
    """Create test database with sample data."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL
        )
    """)

    # Sample data
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'alice', 'alice@example.com', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'bob', 'bob@example.com', 'user')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'charlie', 'charlie@example.com', 'user')")
    c.execute("INSERT OR IGNORE INTO products VALUES (1, 'Widget', 9.99)")
    c.execute("INSERT OR IGNORE INTO products VALUES (2, 'Gadget', 19.99)")

    conn.commit()
    conn.close()


@app.route("/")
def index():
    """Home page."""
    return """
    <html>
    <head><title>Vuln Test App</title></head>
    <body>
        <h1>Senshi Test Application</h1>
        <p>This app has intentional vulnerabilities for testing.</p>
        <ul>
            <li><a href="/search?q=test">Search</a> (SQLi)</li>
            <li><a href="/greet?name=World">Greet</a> (XSS)</li>
            <li><a href="/fetch?url=https://example.com">Fetch</a> (SSRF)</li>
            <li><a href="/api/users/1">User API</a> (IDOR)</li>
            <li><a href="/ping?host=127.0.0.1">Ping</a> (Command Injection)</li>
            <li><a href="/admin/users">Admin</a> (Missing Auth)</li>
        </ul>
    </body>
    </html>
    """


@app.route("/search")
def search():
    """VULN: SQL Injection — query parameter directly in SQL."""
    query = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULN: Direct string concatenation in SQL query
    try:
        c.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
        results = c.fetchall()
        conn.close()
        return jsonify({"results": results, "query": query})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e), "query": query}), 500


@app.route("/greet")
def greet():
    """VULN: Reflected XSS — name parameter reflected without encoding."""
    name = request.args.get("name", "World")
    # VULN: User input directly in HTML without escaping
    return f"""
    <html>
    <head><title>Greeting</title></head>
    <body>
        <h1>Hello, {name}!</h1>
        <p>Welcome to the test app.</p>
    </body>
    </html>
    """


@app.route("/fetch")
def fetch_url():
    """VULN: SSRF — server makes request to user-supplied URL."""
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400

    # VULN: No URL validation, server makes request to arbitrary URL
    try:
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode("utf-8", errors="ignore")[:2000]
        return jsonify({
            "url": url,
            "status": response.status,
            "content": content,
        })
    except Exception as e:
        return jsonify({"error": str(e), "url": url}), 500


@app.route("/api/users/<int:user_id>")
def get_user(user_id: int):
    """VULN: IDOR — no auth check, any user ID accessible."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()

    if user:
        # VULN: Returns all user data including email without auth
        return jsonify({
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "role": user[3],
        })
    return jsonify({"error": "User not found"}), 404


@app.route("/ping")
def ping():
    """VULN: Command Injection — host parameter used in shell command."""
    host = request.args.get("host", "")
    if not host:
        return jsonify({"error": "host parameter required"}), 400

    # VULN: Shell injection via unsanitized input
    try:
        result = subprocess.run(
            f"ping -c 1 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return jsonify({
            "host": host,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/users")
def admin_users():
    """VULN: Missing authentication — admin endpoint accessible without auth."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()

    return jsonify({
        "users": [
            {"id": u[0], "username": u[1], "email": u[2], "role": u[3]}
            for u in users
        ]
    })


@app.route("/api/config")
def config():
    """VULN: Exposes internal configuration."""
    return jsonify({
        "debug": True,
        "api_key": API_KEY,
        "database": DB_PATH,
        "version": "1.0.0-test",
    })


@app.route("/redirect")
def open_redirect():
    """VULN: Open redirect — no validation on redirect target."""
    target = request.args.get("url", "/")
    return redirect(target)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
