
import os
import sqlite3
from functools import wraps

from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

DB = os.environ.get("DB_PATH", "users.db")

def connect_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db

with connect_db() as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0
        )
    """)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify(error="Please log in"), 401
        return fn(*args, **kwargs)
    return wrapper

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/")
def home():
    return jsonify(
        site="ROCKY WS EARN",
        status="Backend is running",
        note="No real payments or earnings are enabled."
    )

@app.post("/api/signup")
def signup():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not 3 <= len(username) <= 30:
        return jsonify(error="Username must be 3-30 characters"), 400
    if len(password) < 12:
        return jsonify(error="Use a password of at least 12 characters"), 400

    try:
        with connect_db() as db:
            cur = db.execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(error="Username already exists"), 409

    session.clear()
    session["user_id"] = user_id
    return jsonify(message="Account created", username=username), 201

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    with connect_db() as db:
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Invalid username or password"), 401

    session.clear()
    session["user_id"] = user["id"]
    return jsonify(message="Logged in", username=user["username"])

@app.get("/api/dashboard")
@login_required
def dashboard():
    with connect_db() as db:
        user = db.execute(
            "SELECT username, balance FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    if user is None:
        session.clear()
        return jsonify(error="Account not found"), 404

    return jsonify(
        username=user["username"],
        balance=user["balance"],
        currency="INR",
        note="Balance is not withdrawable earnings."
    )

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(message="Logged out")

if __name__ == "__main__":
    app.run(debug=False)
