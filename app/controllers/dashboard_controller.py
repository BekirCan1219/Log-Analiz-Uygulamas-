from flask import Blueprint, render_template

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.get("/")
def index():
    return render_template("dashboard.html")

@dashboard_bp.get("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")

@dashboard_bp.get("/discover")
def discover_page():
    return render_template("discover.html")

@dashboard_bp.get("/rules")
def rules_page():
    return render_template("rules.html")

@dashboard_bp.get("/alerts")
def alerts_page():
    return render_template("alerts.html")

@dashboard_bp.get("/alerts/<int:alert_id>")
def alert_detail_page(alert_id):
    return render_template("alert_detail.html", alert_id=alert_id)
