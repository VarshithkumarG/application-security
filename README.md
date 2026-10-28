# Application Security Lab

A deliberately small Flask web application demonstrating validation, authentication, authorization, secure password storage, CSRF protection, and safe error responses.

## Problem and objective

Application vulnerabilities often arise when untrusted inputs cross trust boundaries or when authenticated users receive excessive access. This project shows secure defaults in a small account and notes app.

## Features

- Registration and login with PBKDF2 password hashes.
- Session-bound CSRF tokens on state-changing forms.
- Login-required, owner-scoped notes; parameterized SQLite queries.
- Strict length limits, output escaping through Jinja, and generic login errors.
- Security headers and secure cookie configuration.

## Technology

Python 3.10+, Flask, Flask-WTF, SQLite.

## Setup and run

```bash
python -m venv .venv
# Activate it, then:
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5001. Set a random `APP_SECRET`; set `COOKIE_SECURE=1` behind HTTPS. This app is a local educational demo.

## How it works

Users register with a hashed password, then authenticate into a signed session. A session-bound CSRF token is required for every POST. Each note query includes the current user's ID so another user's records cannot be fetched by changing a URL parameter.

## Screenshots and demo

No screenshots or hosted demo are included. Capture registration, owned notes, and an unauthorized request response from a local run.

## Tests

Run `python -m unittest discover -s tests -v` from this repository root.

## Security considerations

The demo omits production account recovery, rate limits, email verification, centralized monitoring, and hardened deployment. Signed cookie sessions are not server-side revocable before expiry. Do not put real personal data or passwords in it.

## Future improvements

Add role-based administration, audit events, security tests, dependency scanning, and deployment with HTTPS and a managed database.

