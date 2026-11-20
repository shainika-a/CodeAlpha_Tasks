"""Intentionally vulnerable review specimen. Use only locally with dummy data."""
import sqlite3
from pathlib import Path
from flask import Flask, jsonify, request

app = Flask(__name__)
DB = Path(__file__).with_name("vulnerable_demo.db")


def init_db():
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)")
        db.execute("INSERT OR IGNORE INTO users VALUES (?, ?)", ("student", "DemoPassword123!"))


@app.get("/")
def home():
    return "Local security review specimen. POST /login or GET /greet?name=Student"


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
    with sqlite3.connect(DB) as db:
        user = db.execute(query).fetchone()
    if user:
        return jsonify(message="Credentials accepted", username=user[0])
    return jsonify(error="Invalid credentials"), 401


@app.get("/greet")
def greet():
    name = request.args.get("name", "Student")
    return f"<h1>Hello, {name}</h1>"


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
