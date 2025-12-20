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


@search_bp.get("/")
def search():
    """
    Discover uyumlu log arama endpoint'i

    Query parametreleri:
    - page        : sayfa numarası (default 1)
    - size        : sayfa başı kayıt (default 50)
    - q           : message / raw_text / extra_json içinde arama
    - service     : servis adı
    - level       : INFO/WARN/ERROR/CRITICAL
    - category    : web/auth/ids/app
    - src_ip      : kaynak IP
    - http_status : HTTP status code
    - hours       : son X saat (default 24)
    - from        : ISO datetime (opsiyonel)
    - to          : ISO datetime (opsiyonel)
    """

    # -------- pagination --------
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 50))
    offset = (page - 1) * size

    # -------- filters --------
    q = request.args.get("q")
    service = request.args.get("service")
    level = request.args.get("level")
    category = request.args.get("category")
    src_ip = request.args.get("src_ip")
    http_status = request.args.get("http_status")

    hours = request.args.get("hours", 24)
    try:
        hours = int(hours)
    except Exception:
        hours = 24

    time_to = _parse_dt(request.args.get("to")) or datetime.utcnow()
    time_from = _parse_dt(request.args.get("from")) or (time_to - timedelta(hours=hours))

    # -------- base query --------
    base = db.session.query(LogEvent).filter(
        LogEvent.ingest_time.between(time_from, time_to)
    )

    if service:
        base = base.filter(LogEvent.service == service)

    if level:
        base = base.filter(LogEvent.level == level)

    if category:
        base = base.filter(LogEvent.category == category)

    if src_ip:
        base = base.filter(LogEvent.src_ip == src_ip)

    if http_status:
        try:
            base = base.filter(LogEvent.http_status == int(http_status))
        except Exception:
            pass

    if q:
        like = f"%{q}%"
        base = base.filter(
            or_(
                LogEvent.message.ilike(like),
                LogEvent.raw_text.ilike(like),
                LogEvent.extra_json.ilike(like),
            )
        )

    # -------- total (CRITICAL) --------
    total = base.count()

    # -------- paged result --------
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
        "total": total,     # 🔴 Discover için şart
        "data": results
    })
