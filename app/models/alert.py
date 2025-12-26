from datetime import datetime
from ..extensions import db

class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)

    rule_id = db.Column(db.Integer, nullable=False, index=True)

    status = db.Column(db.String(20), nullable=False, default="open", index=True)  # open/ack/closed
    severity = db.Column(db.String(20), nullable=False, default="medium", index=True)

    title = db.Column(db.String(255), nullable=False)
    group_key = db.Column(db.String(255), nullable=True, index=True)

    # yeni alanlar
    details_json = db.Column(db.Text, nullable=True)  # MSSQL: NVARCHAR(MAX)
    window_from = db.Column(db.DateTime, nullable=True)  # MSSQL: DATETIME2
    window_to = db.Column(db.DateTime, nullable=True)    # MSSQL: DATETIME2

    first_seen = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=True, default=datetime.utcnow, index=True)

    hit_count = db.Column(db.Integer, nullable=False, default=1)
    event_count = db.Column(db.Integer, nullable=False, default=1)
    event_id = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)

    # NEW: lifecycle kapanış zamanı (nullable, mevcut kayıtları bozmaz)
    closed_at = db.Column(db.DateTime, nullable=True, index=True)

    alert_time = db.synonym("created_at")
