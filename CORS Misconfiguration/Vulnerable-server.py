"""
CORS Misconfiguration Lab — VULNERABLE VERSION
================================================
For local learning use only. Runs entirely on localhost.

Run:
    pip install flask
    python vulnerable_server.py

Then follow INSTRUCTIONS.md.
"""
from flask import Flask, request, jsonify, make_response
import secrets

app = Flask(__name__)

# Lab-only in-memory "session store" — do NOT do this in a real app
SESSIONS = {}

FAKE_USER_DATA = {
    "username": "alice",
    "email": "alice@example-lab.local",
    "api_key": "FAKE-LAB-SECRET-KEY-1234567890"
}


@app.route("/login")
def login():
    """Simulates a logged-in user by setting a session cookie."""
    token = secrets.token_hex(16)
    SESSIONS[token] = "alice"
    resp = make_response(
        "Logged in! A session cookie has been set for 'alice'.\n"
        "Now open the PoC page from a DIFFERENT origin (see INSTRUCTIONS.md) "
        "and click 'Attempt Cross-Origin Read'."
    )
    # samesite="None" + secure=False is itself a lab simplification so this works over plain http on localhost
    resp.set_cookie("session", token, httponly=False, samesite="None", secure=False)
    return resp


@app.route("/api/profile")
def profile():
    """A 'protected' endpoint that should only be readable by the logged-in user's own origin."""
    token = request.cookies.get("session")
    if token not in SESSIONS:
        return jsonify({"error": "not logged in — visit /login first"}), 401
    return jsonify(FAKE_USER_DATA)


# ---------------- THE VULNERABLE PART ----------------
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin:
        # VULNERABLE: reflects ANY Origin header back as trusted, instead of
        # checking it against a real allowlist.
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
# -------------------------------------------------------


if __name__ == "__main__":
    print("Vulnerable CORS lab running at http://localhost:5000")
    app.run(port=5000, debug=True)
