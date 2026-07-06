from flask import Flask, request, jsonify
from auth import validate_token, authorize
from config import get_config

app = Flask(__name__)


@app.route("/api/data")
def get_data():
    token = request.headers.get("Authorization")
    user = validate_token(token)
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    if not authorize(user, get_config()["allowed_groups"]):
        return jsonify({"error": "forbidden"}), 403

    return jsonify({"data": "secret stuff"})


@app.route("/admin/dashboard")
def admin_dashboard():
    token = request.headers.get("Authorization")
    user = validate_token(token)
    # No authorization check - anyone with a valid token can access admin
    return jsonify({"admin": True, "user": user})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})
