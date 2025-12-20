from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func, desc, literal_column

from ..extensions import db
from ..models.log_event import LogEvent

metrics_bp = Blueprint("metrics", __name__, url_prefix="/api/metrics")


def _parse_dt(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


@metrics_bp.get("/summary")
def summary():
    """
    Basit dashboard metrikleri:
    - total (son X saat)
    - top services
    - top src_ip
    Not: ingest_time bazlıdır (test log timestamp'i eski olsa bile çalışır).
    """
    time_to = _parse_dt(request.args.get("to")) or datetime.utcnow()

    hours = request.args.get("hours")
    try:
        hours = int(hours) if hours else 24
    except Exception:
        hours = 24

    time_from = time_to - timedelta(hours=hours)

    base = db.session.query(LogEvent).filter(LogEvent.ingest_time.between(time_from, time_to))
    total = base.count()

    top_services = (
        db.session.query(LogEvent.service, func.count(LogEvent.id).label("c"))
        .filter(LogEvent.ingest_time.between(time_from, time_to))
        .group_by(LogEvent.service)
        .order_by(desc("c"))
        .limit(10)
        .all()
    )

    top_ips = (
        db.session.query(LogEvent.src_ip, func.count(LogEvent.id).label("c"))
        .filter(LogEvent.ingest_time.between(time_from, time_to))
        .filter(LogEvent.src_ip.isnot(None))
        .group_by(LogEvent.src_ip)
        .order_by(desc("c"))
        .limit(10)
        .all()
    )

    return jsonify({
        "success": True,
        "range": {"from": time_from.isoformat(), "to": time_to.isoformat()},
        "total": total,
        "top_services": [{"service": s, "count": int(c)} for s, c in top_services if s],
        "top_ips": [{"src_ip": ip, "count": int(c)} for ip, c in top_ips if ip],
    })


@metrics_bp.get("/timeseries")
def timeseries():
    """
    /api/metrics/timeseries?hours=24&bucket=hour
    /api/metrics/timeseries?hours=6&bucket=minute

    MSSQL için: DATEDIFF birimi parametre olamaz, literal olmalı.
    Bu yüzden literal_column ile SQL ifadesini sabit yazıyoruz.
    """
    now = datetime.utcnow()

    try:
        hours = int(request.args.get("hours", 24))
    except Exception:
        hours = 24

    start = now - timedelta(hours=hours)
    bucket = (request.args.get("bucket") or "hour").lower()

    # ✅ SQL Server bucket expression (literal)
    if bucket == "minute":
        bucket_expr = literal_column(
            "DATEADD(minute, DATEDIFF(minute, 0, log_events.ingest_time), 0)"
        )
        bucket = "minute"
    else:
        bucket_expr = literal_column(
            "DATEADD(hour, DATEDIFF(hour, 0, log_events.ingest_time), 0)"
        )
        bucket = "hour"

    # (Opsiyonel filtreler - gerekirse dashboard'da kullanırsın)
    service = request.args.get("service")
    level = request.args.get("level")
    category = request.args.get("category")

    q = (
        db.session.query(
            bucket_expr.label("t"),
            func.count(LogEvent.id).label("c"),
        )
        .select_from(LogEvent)  # ✅ log_events tablo adı/alias garanti
        .filter(LogEvent.ingest_time.between(start, now))
    )

    if service:
        q = q.filter(LogEvent.service == service)
    if level:
        q = q.filter(LogEvent.level == level)
    if category:
        q = q.filter(LogEvent.category == category)

    rows = (
        q.group_by(bucket_expr)
         .order_by(bucket_expr.asc())
         .all()
    )

    data = [{"t": r[0].isoformat(), "c": int(r[1])} for r in rows if r[0] is not None]

    return jsonify({
        "success": True,
        "bucket": bucket,
        "range": {"from": start.isoformat(), "to": now.isoformat()},
        "data": data
    })
