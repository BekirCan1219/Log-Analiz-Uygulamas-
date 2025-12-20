from datetime import datetime
from sqlalchemy import desc
from ..extensions import db
from app.models import LogSource
from app.models.log_event import LogEvent

class LogRepository:
    def get_or_create_source(self, name: str, source_type: str) -> LogSource:
        src = LogSource.query.filter_by(name=name).first()
        if src:
            return src
        src = LogSource(name=name, type=source_type, is_active=True)
        db.session.add(src)
        db.session.commit()
        return src

    def insert_event(self, *, source_id: int, source_type: str, normalized: dict) -> LogEvent:
        ev = LogEvent(
            source_id=source_id,
            event_time=normalized["event_time"],
            ingest_time=datetime.utcnow(),
            category=normalized.get("category"),
            event_type=normalized.get("event_type"),
            level=normalized.get("level"),
            src_ip=normalized.get("src_ip"),
            dst_ip=normalized.get("dst_ip"),
            src_port=normalized.get("src_port"),
            dst_port=normalized.get("dst_port"),
            http_method=normalized.get("http_method"),
            http_status=normalized.get("http_status"),
            url=normalized.get("url"),
            username=normalized.get("username"),
            message=normalized.get("message"),
            raw_text=normalized.get("raw_text"),
            extra_json=normalized.get("extra_json"),
            parse_status=normalized.get("parse_status", 0),
            service=normalized.get("service") or source_type,  # basit varsayım
        )
        db.session.add(ev)
        db.session.commit()
        return ev

    def search(self, *, time_from, time_to, service=None, level=None, src_ip=None, http_status=None, q=None, limit=200):
        query = LogEvent.query

        if time_from:
            query = query.filter(LogEvent.event_time >= time_from)
        if time_to:
            query = query.filter(LogEvent.event_time <= time_to)
        if service:
            query = query.filter(LogEvent.service == service)
        if level:
            query = query.filter(LogEvent.level == level)
        if src_ip:
            query = query.filter(LogEvent.src_ip == src_ip)
        if http_status is not None:
            query = query.filter(LogEvent.http_status == http_status)
        if q:
            # Basit LIKE (sonra Full-Text'e geçeriz)
            query = query.filter(LogEvent.message.ilike(f"%{q}%"))

        return query.order_by(desc(LogEvent.event_time)).limit(limit).all()
