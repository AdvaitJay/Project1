from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(50), index=True)
    ip = db.Column(db.String(64))
    severity = db.Column(db.String(16))
    user_agent = db.Column(db.String(255))
    details = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def as_dict(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "ip": self.ip,
            "severity": self.severity,
            "user_agent": self.user_agent,
            "details": self.details,
            "created_at": self.created_at.isoformat() + "Z",
        }