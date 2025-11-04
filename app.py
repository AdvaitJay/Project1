import os, ipaddress
from dotenv import load_dotenv
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, make_response
from models import db, Event
from vpn_checker import is_vpn
from honeypots import honeypot
from honeypot_trap import honeypot_trap
from admin_trigger import admin_trigger
from honeyfields import check_honeyfields
from behavior_analysis import analyze_behavior

def create_app():
    # Load .env in local/dev environments
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True, template_folder="templates", static_folder="static")
    os.makedirs(app.instance_path, exist_ok=True)
    db_uri = os.getenv("DATABASE_URL") or ("sqlite:///" + os.path.join(app.instance_path, "app.db"))
    # Render / Heroku style postgres URL fix
    if db_uri.startswith("postgres://"):
        db_uri = db_uri.replace("postgres://", "postgresql://", 1)
    app.config.update(SQLALCHEMY_DATABASE_URI=db_uri, SQLALCHEMY_TRACK_MODIFICATIONS=False, SECRET_KEY=os.getenv("SECRET_KEY","dev-secret"))
    db.init_app(app)
    with app.app_context():
        db.create_all()

    def _log(kind, ip, severity, details):
        ev = Event(kind=kind, ip=ip, severity=severity, user_agent=request.headers.get("User-Agent",""), details=details)
        db.session.add(ev); db.session.commit()

    def _parse_allowlist(val):
        items=[]; 
        if not val: return items
        for p in val.split(","):
            s=p.strip(); 
            if not s: continue
            try:
                if "/" in s: items.append(ipaddress.ip_network(s, strict=False))
                else: 
                    import ipaddress as _ip
                    items.append(_ip.ip_address(s))
            except Exception: 
                continue
        return items

    def _ip_in_allowlist(ip, allow):
        try:
            import ipaddress as _ip
            ip_obj=_ip.ip_address(ip)
        except Exception:
            return False
        for it in allow:
            try:
                if hasattr(it, "network_address"):
                    if ip_obj in it: return True
                else:
                    if ip_obj == it: return True
            except Exception:
                continue
        return False

    @app.before_request
    def vpn_detection():
        path = request.path
        if path.startswith("/static") or path in {"/","/api/health"} or path.startswith("/api/"):
            return
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        detected = is_vpn(ip)
        session["vpn_detected"] = bool(detected)
        block_vpn = os.getenv("BLOCK_VPN","false").lower() in {"1","true","yes"}
        allowlist = _parse_allowlist(os.getenv("VPN_ALLOWLIST",""))
        if block_vpn and detected and not _ip_in_allowlist(ip, allowlist):
            _log("vpn", ip, "high", {"message": "Blocked due to VPN/proxy detection"})
            return render_template("blocked.html"), 403

    @app.route("/")
    def index():
        return render_template("dashboard.html", vpn_flag=session.get("vpn_detected", False))

    @app.route("/login", methods=["GET","POST"])
    def login():
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        if request.method == "POST":
            triggered, field, value = check_honeyfields(request.form)
            if triggered:
                _log("honeyfield", ip, "high", {"field": field, "value": value})
                return render_template("login_result.html", result="honeyfield")
            _log("login", ip, "medium", {"username": request.form.get("username","")})
            return render_template("login_result.html", result="failure")
        return render_template("login.html")

    @app.route("/api/behavior", methods=["POST"])
    def api_behavior():
        data = request.get_json(silent=True) or {}
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        severity, report = analyze_behavior(data)
        _log("behavior", ip, severity, report)
        return jsonify({"ok": True, "severity": severity, "tags": report.get("tags",[])})

    @app.route("/api/metrics")
    def api_metrics():
        now = datetime.utcnow(); since = now - timedelta(days=7)
        events = Event.query.filter(Event.created_at >= since).all()
        counts = {"vpn":0, "honeyfield":0, "honeypot":0, "behavior":0, "behavior_erratic":0}
        daily = {}
        for i in range(7):
            d = (now - timedelta(days=6-i)).date().isoformat()
            daily[d] = {"vpn":0, "honeyfield":0, "honeypot":0, "behavior":0}
        for e in events:
            counts[e.kind] = counts.get(e.kind,0) + 1
            try:
                if e.kind=="behavior" and isinstance(e.details, dict) and "erratic" in (e.details.get("tags") or []):
                    counts["behavior_erratic"] += 1
            except Exception: pass
            day = e.created_at.date().isoformat()
            daily.setdefault(day, {"vpn":0, "honeyfield":0, "honeypot":0, "behavior":0})
            daily[day][e.kind] += 1
        rows = [ev.as_dict() for ev in Event.query.order_by(Event.created_at.desc()).limit(100).all()]
        resp = make_response(jsonify({"counts": counts, "daily": daily, "recent": rows}))
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/api/events")
    def api_events():
        kind = request.args.get("kind"); page = int(request.args.get("page",1)); per = int(request.args.get("per",25))
        q = Event.query
        if kind in {"vpn","behavior","honeypot","honeyfield"}:
            q = q.filter(Event.kind==kind)
        q = q.order_by(Event.created_at.desc()).paginate(page=page, per_page=per, error_out=False)
        payload = {"page": page, "per": per, "total": q.total, "items": [e.as_dict() for e in q.items]}
        resp = make_response(jsonify(payload)); resp.headers["Cache-Control"] = "no-store"; return resp

    @app.route("/api/health")
    def api_health():
        return {"ok": True}

    app.register_blueprint(honeypot)
    app.register_blueprint(honeypot_trap)
    app.register_blueprint(admin_trigger)

    return app

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)), debug=True)