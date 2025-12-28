from flask import Blueprint, request, jsonify, session

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# DB/model YOK → demo auth (admin tamamen kaldırıldı)
USERS = {
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

    # session'a user yaz (role kalsın; admin yok)
    session["user"] = {
        "username": username,
        "role": user.get("role", "viewer")
    }

    return jsonify({"success": True, "user": session["user"]})

@auth_bp.post("/logout")
def logout():
    session.clear()
    return jsonify({"success": True})

@auth_bp.get("/me")
def me():
    # Admin/role yönetimi komple kalksın istendiği için bu endpoint devre dışı.
    # UI artık bunu çağırmamalı. İstemeden bir yerde kalmışsa net hata verir.
    return jsonify({"success": False, "error": "disabled"}), 410
