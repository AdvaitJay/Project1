from flask import Blueprint, render_template, request
from models import db, Event

admin_trigger = Blueprint("admin_trigger", __name__, template_folder="templates")

def _log(kind, ip, severity, details):
    ev = Event(kind=kind, ip=ip, severity=severity, user_agent="simulator", details=details)
    db.session.add(ev)
    db.session.commit()
    return ev

@admin_trigger.route("/admin/trigger", methods=["GET", "POST"])
def trigger_page():
    message = None
    if request.method == "POST":
        t = request.form.get("trigger")
        ip = request.remote_addr or "127.0.0.1"
        if t == "vpn":
            ev = _log("vpn", ip, "high", {"message": "Simulated VPN detection"})
            message = f"Logged VPN event id={ev.id}"
        elif t == "honeypot":
            ev = _log("honeypot", ip, "high", {"path": "/admin/backup.zip", "message": "Simulated honeypot hit"})
            message = f"Logged Honeypot event id={ev.id}"
        elif t == "honeyfield":
            ev = _log("honeyfield", ip, "high", {"field": "__do_not_fill", "value": "simulated"})
            message = f"Logged Honeyfield event id={ev.id}"
        elif t == "behavior":
            details = {"telemetry": {"clicks": 20, "keys": 5, "moves": 150, "duration_ms": 12000, "path_samples": 120},
                       "metrics": {"cps":1.6,"kps":0.4,"mps":12.5,"total_dist":1200,"max_speed":3000,"speed_std":1300,"dir_changes_rate":7,"jitter":7000},
                       "tags":["speed-spikes","jerky-direction","erratic"]}
            ev = _log("behavior", ip, "high", details)
            message = f"Logged Behavior event id={ev.id}"
        else:
            message = "Unknown trigger"
    return render_template("admin_trigger.html", message=message)