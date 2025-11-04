from flask import Blueprint, make_response, request
from models import db, Event

honeypot = Blueprint("honeypot", __name__)

def _log(kind, ip, severity, details):
    ev = Event(kind=kind, ip=ip, severity=severity, user_agent=request.headers.get("User-Agent",""), details=details)
    db.session.add(ev)
    db.session.commit()

@honeypot.route("/admin/backup.zip")
def fake_backup():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    _log("honeypot", ip, "high", {"path": "/admin/backup.zip"})
    return make_response("Not Found", 404)

@honeypot.route("/secret-admin")
def secret_admin():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    _log("honeypot", ip, "high", {"path": "/secret-admin"})
    return make_response("Forbidden", 403)