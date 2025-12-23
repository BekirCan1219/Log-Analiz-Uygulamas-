from datetime import datetime
from ..extensions import db

class DetectionRule(db.Model):
    __tablename__ = "detection_rules"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    name = db.Column(db.String(200), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    severity = db.Column(db.String(20), default="medium", nullable=False)

    query_json = db.Column(db.Text, nullable=False)

    cooldown_minutes = db.Column(db.Integer, default=15, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, onupdate=datetime.utcnow)
