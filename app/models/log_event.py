from datetime import datetime
from ..extensions import db

class LogEvent(db.Model):
    __tablename__ = "log_events"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)

    event_time = db.Column(db.DateTime, nullable=False, index=True)
    ingest_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    service = db.Column(db.String(100), index=True)
    host = db.Column(db.String(100))
    environment = db.Column(db.String(20))

    category = db.Column(db.String(30), index=True)     # web/auth/ids/app
    event_type = db.Column(db.String(60), index=True)   # http_request/login_failed/alert/...

    level = db.Column(db.String(10), index=True)        # INFO/WARN/ERROR/CRITICAL

    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)

    http_method = db.Column(db.String(10))
    http_status = db.Column(db.Integer, index=True)
    url = db.Column(db.String(2048))

    username = db.Column(db.String(100))
    message = db.Column(db.String(2000))

    raw_text = db.Column(db.Text)        # ham satır/json
    extra_json = db.Column(db.Text)      # değişken alanlar JSON string

    parse_status = db.Column(db.SmallInteger, default=0, nullable=False)  # 0 ok, 1 partial, 2 failed

    source_id = db.Column(db.Integer, db.ForeignKey("log_sources.id"))
    source = db.relationship("LogSource")
