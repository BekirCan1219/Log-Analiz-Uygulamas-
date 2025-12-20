from datetime import datetime
from ..extensions import db

class AlertRule(db.Model):
    __tablename__ = "alert_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    # filtre tanımı JSON string (örn: {"level":"ERROR","service":null,"http_status":500})
    query_json = db.Column(db.Text, nullable=False)

    window_minutes = db.Column(db.Integer, default=5, nullable=False)
    threshold = db.Column(db.Integer, default=50, nullable=False)

    # group_by: "service" / "src_ip" / "none"
    group_by = db.Column(db.String(50), default="service", nullable=False)

    severity = db.Column(db.String(20), default="medium", nullable=False)  # low/medium/high/critical
    cooldown_minutes = db.Column(db.Integer, default=10, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
