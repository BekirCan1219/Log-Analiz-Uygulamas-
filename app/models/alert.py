from datetime import datetime
from ..extensions import db

class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)

    rule_id = db.Column(db.Integer, db.ForeignKey("alert_rules.id"), nullable=False, index=True)
    rule = db.relationship("AlertRule")

    alert_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False)

    title = db.Column(db.String(250), nullable=False)
    description = db.Column(db.Text)

    # aynı alarmı spamlememek için
    group_key = db.Column(db.String(200), index=True)

    event_count = db.Column(db.Integer, nullable=False)
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)

    status = db.Column(db.String(20), default="open", nullable=False)  # open/ack/closed
