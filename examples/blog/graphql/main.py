# /// script
# dependencies = [
#   "flask",
#   "pyjwt",
#   "trappsec",
#   "graphql-core",
# ]
# ///

import jwt
import secrets
from datetime import datetime, timedelta, UTC
from flask import Flask, request, jsonify, g
import trappsec

app = Flask(__name__)

# ----------------------
# Initialize trappsec
# ----------------------

ts = trappsec.Sentry(app, service="SomeService", environment="Development")

ts.identify_user(lambda r: {
    "user": g.user_id,
    "role": "user"
})


# ---------------------------
# Mock JWT Auth and Helpers
# ---------------------------

SECRET = secrets.token_hex(32)
ALGORITHM = "HS256"

USERS = {
    "alice": {"username": "alice", "password": "password"},
}

def create_token(username: str):
    payload = {
        "sub": username,
        "exp": datetime.now(UTC) + timedelta(hours=1),
    }
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.PyJWTError:
        return None


# ----------------------
# Auth Middleware
# ----------------------

@app.before_request
def extract_user():
    g.user_id = None

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return

    token = auth_header.split(" ")[1]
    username = verify_token(token)

    if username and username in USERS:
        g.user_id = username

# ----------------------
# Real Routes
# ----------------------

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"access_token": create_token(username)})


@app.route("/me", methods=["GET"])
def me():
    if not g.user_id:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"username": g.user_id})

# ----------------------
# GraphQL Decoy Trap
# ----------------------

from custom import graphql_trap

ts.trap("/graphql") \
    .methods("POST") \
    .intent("GraphQL Reconnaissance") \
    .respond(200, graphql_trap) \
    .if_unauthenticated(
        401,
        {
            "errors": [
                {"message": "Unauthorized"}
            ]
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
