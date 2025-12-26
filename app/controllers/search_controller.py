from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import or_

from ..extensions import db
from ..models.log_event import LogEvent

search_bp = Blueprint("search", __name__, url_prefix="/api/search")


def _parse_dt(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _to_int(v: str | None):
    if v is None:
        return None
    v = str(v).strip()
    if not v:
        return None
    try:
        return int(v)
    except Exception:
        return None


@search_bp.get("/")
def search():
    """
    Discover uyumlu log arama endpoint'i

    Query parametreleri:
    - page, size
    - hours (default 24) veya from/to ISO datetime
    - q: message/raw_text/extra_json içinde genel arama
    - message_contains: sadece message içinde arama
    - url_contains: sadece url içinde arama
    - service, level, category, src_ip
    - http_status
    - http_status_min, http_status_max
    """

    # -------- pagination --------
    page = _to_int(request.args.get("page")) or 1
    size = _to_int(request.args.get("size")) or 50
    if page < 1:
        page = 1
    if size < 1:
        size = 50
    if size > 500:
        size = 500  # derste yeter, DB’yi boğmayalım

    offset = (page - 1) * size

    # -------- filters --------
    q = (request.args.get("q") or "").strip() or None
    service = (request.args.get("service") or "").strip() or None
    level = (request.args.get("level") or "").strip() or None
    category = (request.args.get("category") or "").strip() or None
    src_ip = (request.args.get("src_ip") or "").strip() or None

    http_status = _to_int(request.args.get("http_status"))
    http_status_min = _to_int(request.args.get("http_status_min"))
    http_status_max = _to_int(request.args.get("http_status_max"))

    url_contains = (request.args.get("url_contains") or "").strip() or None
    message_contains = (request.args.get("message_contains") or "").strip() or None

    hours = _to_int(request.args.get("hours")) or 24

    time_to = _parse_dt(request.args.get("to")) or datetime.utcnow()
    time_from = _parse_dt(request.args.get("from")) or (time_to - timedelta(hours=hours))

    # -------- base query --------
    base = db.session.query(LogEvent).filter(
        LogEvent.ingest_time.between(time_from, time_to)
    )

    # service contains (daha kullanışlı)
    if service:
        base = base.filter(LogEvent.service.ilike(f"%{service}%"))

    if level:
        base = base.filter(LogEvent.level == level)

    if category:
        base = base.filter(LogEvent.category == category)

    if src_ip:
        base = base.filter(LogEvent.src_ip == src_ip)

    if http_status is not None:
        base = base.filter(LogEvent.http_status == http_status)

    if http_status_min is not None:
        base = base.filter(LogEvent.http_status >= http_status_min)

    if http_status_max is not None:
        base = base.filter(LogEvent.http_status <= http_status_max)

    if url_contains:
        base = base.filter(LogEvent.url.ilike(f"%{url_contains}%"))

    if message_contains:
        base = base.filter(LogEvent.message.ilike(f"%{message_contains}%"))

    if q:
        like = f"%{q}%"
        base = base.filter(
            or_(
                LogEvent.message.ilike(like),
                LogEvent.raw_text.ilike(like),
                LogEvent.extra_json.ilike(like),
            )
        )

    total = base.count()

    rows = (
        base
        .order_by(LogEvent.ingest_time.desc())
        .offset(offset)
        .limit(size)
        .all()
    )

    results = []
    for r in rows:
        results.append({
            "id": r.id,

            "event_time": r.event_time.isoformat() if r.event_time else None,
            "ingest_time": r.ingest_time.isoformat() if r.ingest_time else None,

            "service": r.service,
            "host": r.host,
            "environment": r.environment,

            "category": r.category,
            "event_type": r.event_type,
            "level": r.level,

            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "src_port": r.src_port,
            "dst_port": r.dst_port,

            "http_method": r.http_method,
            "http_status": r.http_status,
            "url": r.url,

            "username": r.username,
            "message": r.message,

            "raw_text": r.raw_text,
            "extra_json": r.extra_json,

            "parse_status": r.parse_status,
            "source_id": r.source_id,
        })

    return jsonify({
        "success": True,
        "page": page,
        "size": size,
        "total": total,
        "data": results
    })
