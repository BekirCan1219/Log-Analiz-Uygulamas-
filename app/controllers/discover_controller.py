from flask import Blueprint, render_template

discover_bp = Blueprint("discover", __name__)

@discover_bp.get("/discover")
def discover_page():
    return render_template("discover.html")
