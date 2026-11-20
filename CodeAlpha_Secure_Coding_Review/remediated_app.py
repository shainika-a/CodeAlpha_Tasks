"""Remediated local review example; see AUDIT_REPORT.md for production limits."""
import getpass
import sqlite3
from pathlib import Path
from flask import Flask, jsonify, render_template_string, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
DB = Path(__file__).with_name("remediated_demo.db")


def init_db():
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")
        if not db.execute("SELECT 1 FROM users WHERE username = ?", ("student",)).fetchone():
            password = getpass.getpass("Set local demo password for student (12-128 characters): ")
            if not 12 <= len(password) <= 128:
                raise ValueError("Password must be 12-128 characters")
            db.execute("INSERT INTO users VALUES (?, ?)", ("student", generate_password_hash(password)))


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def home():
    return "Local security review example. POST /login or GET /greet?name=Student"


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not 1 <= len(username) <= 64 or not 1 <= len(password) <= 128:
        return jsonify(error="Invalid input length"), 400
    with sqlite3.connect(DB) as db:
        user = db.execute("SELECT username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if user and check_password_hash(user[1], password):
        return jsonify(message="Credentials accepted", username=user[0])
    return jsonify(error="Invalid credentials"), 401


@app.get("/greet")
def greet():
    name = request.args.get("name", "Student")
    if len(name) > 100:
        return "Name too long", 400
    return render_template_string("<h1>Hello, {{ name }}</h1>", name=name)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=False)
