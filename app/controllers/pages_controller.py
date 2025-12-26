from flask import Blueprint, render_template, session, redirect

pages_bp = Blueprint("pages", __name__)

@pages_bp.get("/")
def root():
    if not session.get("user"):
        return redirect("/login")
    return redirect("/dashboard")



@pages_bp.get("/alerts/<int:alert_id>")
def alert_detail_page(alert_id: int):
    if not session.get("user"):
        return redirect("/login")
    return render_template("alert_detail.html", alert_id=alert_id)



@pages_bp.get("/login")
def login_page():
    # Zaten login ise dashboard'a at
    if session.get("user"):
        return redirect("/dashboard")
    return render_template("login.html")
