import os
import re
import sqlite3
import secrets
import hmac
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).resolve().parent
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("APP_SECRET") or secrets.token_hex(32),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1")
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_posts():
    if request.method == "POST":
        expected = session.get("csrf", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(400, "Invalid request token.")
PAGE = """<!doctype html><title>App Security Lab</title><h1>App Security Lab</h1>
{% for m in get_flashed_messages() %}<p role="status">{{ m }}</p>{% endfor %}
{% if session.get('uid') %}<form method="post" action="/notes"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label>Note <input name="body" maxlength="300" required></label><button>Add</button></form>
<ul>{% for note in notes %}<li>{{ note }}</li>{% endfor %}</ul><form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button>Log out</button></form>
{% else %}<form method="post" action="/register"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input name="email" type="email" required><input name="password" type="password" minlength="12" required><button>Register</button></form>
<form method="post" action="/login"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input name="email" type="email" required><input name="password" type="password" required><button>Sign in</button></form>{% endif %}"""


@app.after_request
def headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    return response


@contextmanager
def db():
    path = BASE / "instance" / "app.sqlite3"
    path.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,hash TEXT NOT NULL); CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),body TEXT NOT NULL)")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


@app.get("/")
def index():
    notes = []
    if session.get("uid"):
        with db() as conn:
            notes = [r[0] for r in conn.execute("SELECT body FROM notes WHERE user_id=? ORDER BY id DESC", (session["uid"],))]
    return render_template_string(PAGE, notes=notes)


@app.post("/register")
def register():
    email, password = request.form.get("email", "").strip().lower(), request.form.get("password", "")
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or not 12 <= len(password) <= 256:
        abort(400, "Provide a valid email and a password between 12 and 256 characters.")
    try:
        with db() as conn:
            cur = conn.execute("INSERT INTO users(email,hash) VALUES (?,?)", (email, generate_password_hash(password)))
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        flash("Account could not be created with those details.")
        return redirect(url_for("index"))
    session.clear()
    session["uid"] = uid
    return redirect(url_for("index"))


@app.post("/login")
def login():
    email = request.form.get("email", "").strip().lower()
    with db() as conn:
        row = conn.execute("SELECT id,hash FROM users WHERE email=?", (email,)).fetchone()
    if not row or not check_password_hash(row[1], request.form.get("password", "")):
        flash("Email or password is incorrect.")
        return redirect(url_for("index"))
    session.clear()
    session["uid"] = row[0]
    return redirect(url_for("index"))


@app.post("/notes")
def add_note():
    if not session.get("uid"):
        abort(401)
    body = request.form.get("body", "").strip()
    if not body or len(body) > 300:
        abort(400)
    with db() as conn:
        conn.execute("INSERT INTO notes(user_id,body) VALUES (?,?)", (session["uid"], body))
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)

