"""
demo_app.app
~~~~~~~~~~~~

Intentionally vulnerable Flask application used to demonstrate Python
Shield WAF's protection capabilities.

Security note
-------------
This application is a **controlled testing target** — it is deliberately
designed to be placed *behind* the WAF.  The WAF is what makes deploying
this application safe in the demo environment.

Vulnerabilities present (for WAF demonstration only)
-----------------------------------------------------
* ``/login`` echoes form input — reflected XSS if reached directly.
* No CSRF protection, no session management.
* No database — purely for HTTP traffic interception testing.

DO NOT deploy this application directly on a public-facing port.
"""

from __future__ import annotations

import os

from flask import Flask, Response, request
from markupsafe import escape

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/", methods=["GET"])
def home() -> str:
    """Landing page with a login form that posts to ``/login``."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Vulnerable Bank — WAF Demo Target</title>
    </head>
    <body>
        <h1>Vulnerable Bank — WAF Demo Target</h1>
        <p>
            This app sits <strong>behind</strong> the Python Shield WAF (port 8000).
            Attack payloads sent to port 8000 will be intercepted; requests to
            port 5000 (direct) will reach this handler unfiltered.
        </p>
        <form method="POST" action="/login">
            <label for="username">Username:</label>
            <input id="username" type="text" name="username"><br><br>
            <label for="password">Password:</label>
            <input id="password" type="password" name="password"><br><br>
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    """


@app.route("/login", methods=["POST"])
def login() -> str:
    """
    Echo the submitted username back to the page.

    The ``markupsafe.escape()`` call demonstrates secure output encoding
    that would prevent XSS even if a payload slipped through the WAF.

    Note: this is a **demonstration stub** — there is no real authentication.
    """
    username = escape(request.form.get("username", ""))
    return f"<h2>Login attempt for user: {username}</h2>"


@app.route("/health", methods=["GET"])
def health() -> Response:
    """Liveness probe consumed by Docker Compose and the WAF proxy."""
    return Response('{"status": "ok"}', status=200, mimetype="application/json")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)