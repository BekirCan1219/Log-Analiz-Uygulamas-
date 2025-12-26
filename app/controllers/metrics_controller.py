# app/controllers/metrics_controller.py
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify
from sqlalchemy import func, text

from ..extensions import db
from ..models.log_event import LogEvent

metrics_bp = Blueprint("metrics", __name__, url_prefix="/api/metrics")


def _utcnow():
    return datetime.utcnow()


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
    Dashboard metrikleri (ingest_time bazlı):
    - total: son X saatte toplam event
    - parse_status_counts: parse_status dağılımı
    - top_services
    - top_ips (src_ip)
    - range: from/to
    """
    time_to = _parse_dt(request.args.get("to")) or _utcnow()

    hours = request.args.get("hours")
    try:
        hours = int(hours) if hours else 24
    except Exception:
        hours = 24

    time_from = time_to - timedelta(hours=hours)

    base = db.session.query(LogEvent).filter(LogEvent.ingest_time.between(time_from, time_to))
    total = base.with_entities(func.count(LogEvent.id)).scalar() or 0

    # parse_status dağılımı
    ps_rows = (
        db.session.query(LogEvent.parse_status, func.count(LogEvent.id))
        .filter(LogEvent.ingest_time.between(time_from, time_to))
        .group_by(LogEvent.parse_status)
        .all()
    )
    parse_status_counts = []
    for ps, c in ps_rows:
        parse_status_counts.append({
            "parse_status": ps if ps is not None else -1,
            "count": int(c)
        })
    parse_status_counts.sort(key=lambda x: x["count"], reverse=True)

    # top services
    svc_rows = (
        db.session.query(LogEvent.service, func.count(LogEvent.id).label("c"))
        .filter(LogEvent.ingest_time.between(time_from, time_to))
        .group_by(LogEvent.service)
        .order_by(func.count(LogEvent.id).desc())
        .limit(10)
        .all()
    )
    top_services = [{"service": s or "unknown", "count": int(c)} for s, c in svc_rows]

    # top src_ip
    ip_rows = (
        db.session.query(LogEvent.src_ip, func.count(LogEvent.id).label("c"))
        .filter(LogEvent.ingest_time.between(time_from, time_to))
        .group_by(LogEvent.src_ip)
        .order_by(func.count(LogEvent.id).desc())
        .limit(10)
        .all()
    )
    top_ips = [{"src_ip": ip or "unknown", "count": int(c)} for ip, c in ip_rows]

    return jsonify({
        "total": int(total),
        "range": {"from": time_from.isoformat(), "to": time_to.isoformat()},
        "parse_status_counts": parse_status_counts,
        "top_services": top_services,
        "top_ips": top_ips
    })


@metrics_bp.get("/timeseries", endpoint="metrics_timeseries")
def timeseries():
    """
    GET /api/metrics/timeseries?hours=24&bucket=hour|minute
    MSSQL/SQLite uyumlu time bucket.
    """
    time_to = _parse_dt(request.args.get("to")) or _utcnow()
    hours = request.args.get("hours", type=int) or 24
    bucket = (request.args.get("bucket") or "hour").lower()
    bucket = "minute" if bucket == "minute" else "hour"

    time_from = time_to - timedelta(hours=hours)
    dialect = db.engine.dialect.name  # "mssql" | "sqlite" | ...

    # --- MSSQL: datepart parametre olamaz -> raw SQL ile sabit veriyoruz ---
    if dialect == "mssql":
        datepart = "minute" if bucket == "minute" else "hour"

        sql = text(f"""
            SELECT
              DATEADD({datepart}, DATEDIFF({datepart}, 0, ingest_time), 0) AS t,
              COUNT(id) AS c
            FROM log_events
            WHERE ingest_time BETWEEN :t_from AND :t_to
            GROUP BY DATEADD({datepart}, DATEDIFF({datepart}, 0, ingest_time), 0)
            ORDER BY t ASC
        """)

        rows = db.session.execute(sql, {"t_from": time_from, "t_to": time_to}).all()

        data = []
        for r in rows:
            # Row objesinde attribute erişimi her zaman stabil değil -> mapping kullan
            m = r._mapping
            t = m.get("t")
            c = m.get("c", 0)
            data.append({
                "t": t.isoformat() if hasattr(t, "isoformat") else (str(t) if t is not None else None),
                "c": int(c)
            })

        return jsonify({
            "range": {"from": time_from.isoformat(), "to": time_to.isoformat()},
            "bucket": bucket,
            "data": data
        })

    # --- SQLite: strftime ile bucket string üret ---
    if bucket == "minute":
        t_bucket = func.strftime("%Y-%m-%dT%H:%M:00", LogEvent.ingest_time)
    else:
        t_bucket = func.strftime("%Y-%m-%dT%H:00:00", LogEvent.ingest_time)

    rows = (
        db.session.query(t_bucket.label("t"), func.count(LogEvent.id).label("c"))
        .filter(LogEvent.ingest_time.between(time_from, time_to))
        .group_by(t_bucket)
        .order_by(t_bucket.asc())
        .all()
    )

    data = [{"t": str(t), "c": int(c)} for t, c in rows]

    return jsonify({
        "range": {"from": time_from.isoformat(), "to": time_to.isoformat()},
        "bucket": bucket,
        "data": data
    })
