"""
CORS Misconfiguration Lab — FIXED VERSION
===========================================
Same app as vulnerable_server.py, but with a real exact-match origin
allowlist instead of blind reflection.

Run:
    pip install flask
    python fixed_server.py

Then repeat the same PoC steps from INSTRUCTIONS.md and observe that the
cross-origin read is now blocked by the browser.
"""
from flask import Flask, request, jsonify, make_response
import secrets

app = Flask(__name__)

SESSIONS = {}

FAKE_USER_DATA = {
    "username": "alice",
    "email": "alice@example-lab.local",
    "api_key": "FAKE-LAB-SECRET-KEY-1234567890"
}

# The fix: an explicit, exact-match allowlist of origins that are actually
# trusted to read this API's authenticated responses. The PoC page's origin
# (http://localhost:8000) is deliberately NOT on this list.
ALLOWED_ORIGINS = {
    "http://localhost:5000",
}


@app.route("/login")
def login():
    token = secrets.token_hex(16)
    SESSIONS[token] = "alice"
    resp = make_response(
        "Logged in! Now try the same PoC page again — it should fail this time."
    )
    resp.set_cookie("session", token, httponly=False, samesite="None", secure=False)
    return resp


@app.route("/api/profile")
def profile():
    token = request.cookies.get("session")
    if token not in SESSIONS:
        return jsonify({"error": "not logged in — visit /login first"}), 401
    return jsonify(FAKE_USER_DATA)


# ---------------- THE FIX ----------------
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:  # exact match only — no startswith/endswith/regex
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    # If origin isn't in the allowlist, no CORS headers are added at all,
    # so the browser will not let cross-origin JS read the response.
    return response
# -------------------------------------------


if __name__ == "__main__":
    print("Fixed CORS lab running at http://localhost:5000")
    app.run(port=5000, debug=True)
