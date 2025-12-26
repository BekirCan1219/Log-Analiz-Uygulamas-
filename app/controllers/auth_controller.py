from flask import Blueprint, request, jsonify, session

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# DB/model YOK → demo auth
USERS = {
    "admin":  {"password": "admin",  "role": "admin"},
    "viewer": {"password": "viewer", "role": "viewer"},
}

def _get_login_payload():
    """
    Hem JSON hem de HTML form (x-www-form-urlencoded / multipart) destekler.
    """
    if request.is_json:
        body = request.get_json(silent=True) or {}
        return (body.get("username"), body.get("password"))
    # form submit
    return (request.form.get("username"), request.form.get("password"))

@auth_bp.post("/login")
def login():
    username, password = _get_login_payload()

    username = (username or "").strip()
    password = (password or "").strip()

    if not username or not password:
        return jsonify({"success": False, "error": "username/password required"}), 400

    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"success": False, "error": "invalid credentials"}), 401

    # ✅ KRİTİK: role session'a yaz
    session["user"] = {
        "username": username,
        "role": user["role"]
    }

    return jsonify({"success": True, "user": session["user"]})

@auth_bp.post("/logout")
def logout():
    session.clear()
    return jsonify({"success": True})

@auth_bp.get("/me")
def me():
    u = session.get("user")
    if not u:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "user": u})
