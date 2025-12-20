from datetime import datetime
from ..extensions import db

class LogSource(db.Model):
    __tablename__ = "log_sources"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)   # nginx-web1
    type = db.Column(db.String(40), nullable=False)                 # nginx/auth/suricata/app
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
