from datetime import datetime
from ..extensions import db

class AlertRule(db.Model):
    __tablename__ = "alert_rules"
    __table_args__ = {"schema": "dbo"}  # MSSQL dbo

    id = db.Column(db.Integer, primary_key=True)

    detection_rule_id = db.Column(db.Integer, nullable=True, index=True)

    name = db.Column(db.String(200), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    query_json = db.Column(db.Text, nullable=False, default="{}")

    spec_json = db.Column(db.Text, nullable=False, default="{}")

    # DOĞRU: "type" adlı DB kolonuna map
    rule_type = db.Column("type", db.String(64), nullable=False, default="count_threshold")

    window_minutes = db.Column(db.Integer, default=5, nullable=False)
    threshold = db.Column(db.Integer, default=50, nullable=False)

    group_by = db.Column(db.String(50), default="service", nullable=False)

    severity = db.Column(db.String(20), default="medium", nullable=False)
    cooldown_minutes = db.Column(db.Integer, default=10, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
