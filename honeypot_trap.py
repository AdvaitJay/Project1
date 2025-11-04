from flask import Blueprint, render_template, request, session
from models import db, Event

honeypot_trap = Blueprint("honeypot_trap", __name__)

def _log(kind, ip, severity, details):
    ev = Event(kind=kind, ip=ip, severity=severity, user_agent=request.headers.get("User-Agent",""), details=details)
    db.session.add(ev)
    db.session.commit()

@honeypot_trap.route("/trap/login", methods=["GET","POST"])
def trap_login():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    session.setdefault("trap_attempts", 0)
    if request.method == "POST":
        user = request.form.get("username","")
        session["trap_attempts"] = int(session.get("trap_attempts",0)) + 1
        attempts = session["trap_attempts"]
        _log("honeypot", ip, "medium", {"trap":"legacy_login","result":"failed_try","attempts":attempts,"attempt_username":user})
        if attempts >= 3:
            _log("honeypot", ip, "high", {"trap":"legacy_login","result":"threshold_exceeded","attempts":attempts,"attempt_username":user})
            session["trap_attempts"] = 0
            return render_template("trap_result.html", status="locked", username=user)
        return render_template("admin_login.html", error="Invalid credentials")
    return render_template("admin_login.html")

@honeypot_trap.route("/admin", methods=["GET","POST"])
@honeypot_trap.route("/admin/login", methods=["GET","POST"])
def admin_trap():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    session.setdefault("trap_attempts", 0)
    if request.method == "POST":
        user = request.form.get("username","")
        session["trap_attempts"] = int(session.get("trap_attempts",0)) + 1
        attempts = session["trap_attempts"]
        _log("honeypot", ip, "medium", {"trap":"admin_login","result":"failed_try","attempts":attempts,"attempt_username":user})
        if attempts >= 3:
            _log("honeypot", ip, "high", {"trap":"admin_login","result":"threshold_exceeded","attempts":attempts,"attempt_username":user})
            session["trap_attempts"] = 0
            return render_template("trap_result.html", status="locked", username=user)
        return render_template("admin_login.html", error="Invalid credentials")
    return render_template("admin_login.html")