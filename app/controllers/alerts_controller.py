# app/controllers/alerts_controller.py
import json
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import func, or_, desc, text

from ..extensions import db
from ..models.log_event import LogEvent
from ..models.detection_rule import DetectionRule
from ..models.alert_rule import AlertRule
from ..models.alert import Alert
from ..services.alert_engine import AlertEngine
from ..services.alert_actions_runner import run_actions_for_alert

alerts_bp = Blueprint("alerts_api", __name__, url_prefix="/api/alerts")


# ----------------------------
# Helpers
# ----------------------------
def _utcnow():
    return datetime.utcnow()


def _safe_json_loads(s: str, default=None):
    try:
        return json.loads(s) if s else (default if default is not None else {})
    except Exception:
        return default if default is not None else {}


def _safe_json_dumps(obj) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return "{}"


def _append_audit(details: dict | None, action: str, note: str | None):
    details = details or {}
    audit = details.get("audit")
    if not isinstance(audit, list):
        audit = []
    audit.append({
        "ts": _utcnow().isoformat(),
        "action": action,
        "note": note or ""
    })
    details["audit"] = audit
    return details


def _apply_common_filters(q, filters: dict):
    if not filters:
        return q

    if filters.get("service"):
        q = q.filter(LogEvent.service == filters["service"])
    if filters.get("level"):
        q = q.filter(LogEvent.level == filters["level"])
    if filters.get("category"):
        q = q.filter(LogEvent.category == filters["category"])
    if filters.get("event_type") and hasattr(LogEvent, "event_type"):
        q = q.filter(LogEvent.event_type == filters["event_type"])
    if filters.get("src_ip"):
        q = q.filter(LogEvent.src_ip == filters["src_ip"])

    if filters.get("http_status") is not None and hasattr(LogEvent, "http_status"):
        q = q.filter(LogEvent.http_status == int(filters["http_status"]))

    if filters.get("http_status_in") and hasattr(LogEvent, "http_status"):
        vals = []
        for v in filters["http_status_in"]:
            try:
                vals.append(int(v))
            except Exception:
                pass
        if vals:
            q = q.filter(LogEvent.http_status.in_(vals))

    if filters.get("http_status_min") is not None and hasattr(LogEvent, "http_status"):
        q = q.filter(LogEvent.http_status >= int(filters["http_status_min"]))
    if filters.get("http_status_max") is not None and hasattr(LogEvent, "http_status"):
        q = q.filter(LogEvent.http_status <= int(filters["http_status_max"]))

    if filters.get("url_contains") and hasattr(LogEvent, "url"):
        like = f"%{filters['url_contains']}%"
        q = q.filter(LogEvent.url.ilike(like))

    if filters.get("message_contains"):
        like = f"%{filters['message_contains']}%"
        q = q.filter(LogEvent.message.ilike(like))

    # parse_status filtrelemek isteyen rule varsa
    if filters.get("parse_status") is not None and hasattr(LogEvent, "parse_status"):
        try:
            q = q.filter(LogEvent.parse_status == int(filters["parse_status"]))
        except Exception:
            pass

    return q


def _ensure_filters_in_details(details: dict | None, filters: dict | None):
    details = details or {}
    if filters and isinstance(filters, dict):
        details["filters"] = filters
    return details


def _extract_event_count(details: dict | None) -> int | None:
    """
    Rule eval'de 'count' / 'distinct' / 'dc' gibi alanlar oluyor.
    event_count'e en anlamlı olanı basmak için kullanıyoruz.
    """
    if not isinstance(details, dict):
        return None
    for k in ("count", "distinct", "dc", "event_count"):
        v = details.get(k)
        if v is None:
            continue
        try:
            return int(v)
        except Exception:
            continue
    return None


# ----------------------------
# Rule Spec normalize + validation
# ----------------------------
_ALLOWED_TYPES = {"count_threshold", "distinct_threshold", "status_code_spike", "pattern_match"}


def normalize_rule_spec(spec: dict) -> dict:
    """
    Standartlaştırma:
      type: count_threshold | distinct_threshold | status_code_spike | pattern_match
      threshold: int default 1
      group_by: string (LogEvent alanı) veya "none"
      filters: dict
      distinct_field: distinct_threshold için
      field/patterns/mode: pattern_match için
    """
    if not isinstance(spec, dict):
        spec = {}

    out = dict(spec)

    rtype = out.get("type") or out.get("rule_type")
    if not rtype:
        # eski body/query tarafı
        rtype = "count_threshold"
    if rtype not in _ALLOWED_TYPES:
        raise ValueError(f"Invalid rule type: {rtype}")
    out["type"] = rtype

    # threshold
    try:
        out["threshold"] = int(out.get("threshold", 1))
    except Exception:
        out["threshold"] = 1
    if out["threshold"] < 1:
        out["threshold"] = 1

    # group_by
    gb = out.get("group_by")
    if gb is None or gb == "":
        gb = "service"
    out["group_by"] = gb

    # filters
    filters = out.get("filters")
    if filters is None:
        filters = {}
    if not isinstance(filters, dict):
        raise ValueError("filters must be an object/dict")
    out["filters"] = filters

    # distinct_field
    if rtype == "distinct_threshold":
        df = out.get("distinct_field")
        if not df:
            raise ValueError("distinct_threshold requires distinct_field")
        out["distinct_field"] = str(df)

    # status_code_spike params
    if rtype == "status_code_spike":
        # default 500-599
        try:
            out["status_min"] = int(out.get("status_min", 500))
        except Exception:
            out["status_min"] = 500
        try:
            out["status_max"] = int(out.get("status_max", 599))
        except Exception:
            out["status_max"] = 599

    # pattern_match standard: patterns[] + mode(any/all)
    if rtype == "pattern_match":
        field = out.get("field") or "message"
        out["field"] = str(field)

        mode = out.get("mode") or "any"
        mode = str(mode).lower()
        if mode not in ("any", "all", "single", "count"):
            # eski alışkanlıklar için tolerans
            mode = "any"
        out["mode"] = mode

        patterns = out.get("patterns")
        if not patterns:
            single = out.get("pattern") or out.get("contains")
            patterns = [single] if single else []
        if not isinstance(patterns, list):
            raise ValueError("patterns must be a list")
        patterns = [str(p) for p in patterns if p]
        if not patterns:
            raise ValueError("pattern_match requires patterns")
        out["patterns"] = patterns

    # window_minutes opsiyonel
    if "window_minutes" in out and out["window_minutes"] is not None:
        try:
            out["window_minutes"] = int(out["window_minutes"])
        except Exception:
            out.pop("window_minutes", None)

    return out


def _dedup_or_create_alert(
    rule: DetectionRule,
    group_key: str | None,
    title: str,
    window_from: datetime,
    window_to: datetime,
    details: dict | None = None,
    representative_event_id: int | None = None
):
    """
    FIX:
    - alerts.rule_id FK -> dbo.alert_rules.id (DetectionRule.id değil)
    - group_key None ise IS NULL
    - event_count varsa set et
    - commit/rollback güvenliği
    """
    # 1) Önce mirror et, gerçek FK id'sini al
    ar_id = _mirror_rule_to_alert_rules(rule)
    if not ar_id:
        raise ValueError(f"RULE_MIRROR failed for detection_rule_id={getattr(rule,'id',None)}")

    cooldown = timedelta(minutes=int(rule.cooldown_minutes or 15))
    since = window_to - cooldown

    # 2) Dedup query artık Alert.rule_id == ar_id
    q = db.session.query(Alert).filter(Alert.rule_id == ar_id)
    if group_key is None:
        q = q.filter(Alert.group_key.is_(None))
    else:
        q = q.filter(Alert.group_key == group_key)

    existing = (
        q.filter(Alert.status.in_(["open", "ack"]))
         .filter(Alert.last_seen >= since)
         .order_by(Alert.last_seen.desc())
         .first()
    )

    now = _utcnow()
    inferred_event_count = _extract_event_count(details)

    if existing:
        existing.hit_count = (existing.hit_count or 1) + 1
        existing.last_seen = now
        existing.window_from = window_from
        existing.window_to = window_to

        if hasattr(existing, "alert_time"):
            existing.alert_time = now

        if details is not None:
            existing.details_json = _safe_json_dumps(details)

        if representative_event_id:
            existing.event_id = representative_event_id

        if hasattr(existing, "event_count"):
            if inferred_event_count is not None:
                existing.event_count = inferred_event_count
            elif existing.event_count is None:
                existing.event_count = 0

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

        return existing, False

    # 3) Yeni alert: rule_id artık ar_id
    a = Alert(
        rule_id=ar_id,
        status="open",
        severity=rule.severity,
        title=title,
        group_key=group_key,
        details_json=_safe_json_dumps(details) if details else None,
        window_from=window_from,
        window_to=window_to,
        first_seen=now,
        last_seen=now,
        hit_count=1,
        event_id=representative_event_id
    )

    if hasattr(a, "created_at"):
        a.created_at = now
    if hasattr(a, "alert_time"):
        a.alert_time = now

    if hasattr(a, "event_count"):
        if inferred_event_count is not None:
            a.event_count = inferred_event_count
        elif getattr(a, "event_count", None) is None:
            a.event_count = 0

    db.session.add(a)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    try:
        run_actions_for_alert(a, rule, current_app.config)
    except Exception:
        pass

    return a, True


def _sql_has_col(table: str, col: str) -> bool:
    """
    SQL Server COL_LENGTH ile kolon var mı kontrol.
    table: 'alert_rules' veya 'dbo.alert_rules'
    """
    try:
        v = db.session.execute(
            text("SELECT CASE WHEN COL_LENGTH(:t,:c) IS NULL THEN 0 ELSE 1 END"),
            {"t": table, "c": col}
        ).scalar()
        return int(v or 0) == 1
    except Exception:
        return False


def _mirror_rule_to_alert_rules(det_rule: DetectionRule) -> int:
    """
    DetectionRule -> dbo.alert_rules mirror.
    Return: dbo.alert_rules.id  (FK için kullanılacak)
    """
    # DetectionRule'da spec alanın query_json (senin tablonda böyle)
    raw = _safe_json_loads(det_rule.query_json, default={})
    spec = normalize_rule_spec(raw)

    ar = db.session.query(AlertRule).filter(AlertRule.detection_rule_id == det_rule.id).first()
    if not ar:
        ar = AlertRule(detection_rule_id=det_rule.id, created_at=_utcnow(), updated_at=_utcnow())
        db.session.add(ar)

    ar.name = det_rule.name
    ar.enabled = bool(det_rule.enabled)
    ar.severity = det_rule.severity
    ar.cooldown_minutes = int(det_rule.cooldown_minutes or 15)
    ar.updated_at = _utcnow()

    # Standart alanlar
    ar.rule_type = spec.get("type", "count_threshold")
    ar.threshold = int(spec.get("threshold", 1))
    ar.group_by = spec.get("group_by", "service")

    if "window_minutes" in spec and spec["window_minutes"] is not None:
        ar.window_minutes = int(spec["window_minutes"])

    ar.spec_json = json.dumps(spec, ensure_ascii=False)

    # geriye uyumluluk: query_json => filters
    ar.query_json = json.dumps(spec.get("filters", {}), ensure_ascii=False)

    db.session.commit()
    return int(ar.id)


def _delete_rule_from_alert_rules(detection_rule_id: int):
    """
    KRİTİK FIX:
    alert_rules.id != detection_rules.id olabilir.
    Bu yüzden detection_rule_id üzerinden silinir.
    """
    try:
        db.session.execute(
            text("DELETE FROM dbo.alert_rules WHERE detection_rule_id=:id"),
            {"id": int(detection_rule_id)}
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("RULE_MIRROR delete failed detection_rule_id=%s", detection_rule_id)


# ---- AUTH GUARD (KAPALI) ----
def require_admin():
    # Admin yönetimi istemiyorsun: herkese izin ver.
    return True


def _event_to_dict(e: LogEvent):
    if not e:
        return None
    return {
        "id": e.id,
        "ingest_time": e.ingest_time.isoformat() if e.ingest_time else None,
        "service": e.service,
        "level": e.level,
        "message": e.message,
        "raw_text": getattr(e, "raw_text", None),
        "http_status": getattr(e, "http_status", None),
        "url": getattr(e, "url", None),
        "src_ip": getattr(e, "src_ip", None),
        "category": getattr(e, "category", None),
        "parse_status": getattr(e, "parse_status", None),
        "event_type": getattr(e, "event_type", None),
    }


# ----------------------------
# Rule CRUD
# ----------------------------
@alerts_bp.get("/rules")
def list_rules():
    rows = db.session.query(DetectionRule).order_by(DetectionRule.id.desc()).all()
    data = []
    for r in rows:
        spec = _safe_json_loads(r.query_json, {})
        data.append({
            "id": r.id,
            "name": r.name,
            "enabled": r.enabled,
            "severity": r.severity,
            "cooldown_minutes": r.cooldown_minutes,
            "spec": spec,
            "created_at": r.created_at.isoformat() if getattr(r, "created_at", None) else None
        })
    return jsonify({"success": True, "data": data})


@alerts_bp.post("/rules")
def create_rule():
    body = request.get_json(force=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "name required"}), 400

    # Yeni standart: spec
    spec_obj = body.get("spec")
    # Geriye uyum: query
    if spec_obj is None:
        spec_obj = body.get("query", {}) or {}

    try:
        spec_obj = normalize_rule_spec(spec_obj)
    except Exception as e:
        return jsonify({"success": False, "error": f"invalid spec: {str(e)}"}), 400

    rule = DetectionRule(
        name=name,
        enabled=bool(body.get("enabled", True)),
        severity=body.get("severity", "medium"),
        cooldown_minutes=int(body.get("cooldown_minutes", 15)),
        query_json=_safe_json_dumps(spec_obj),  # DetectionRule'da spec burada
    )
    db.session.add(rule)
    db.session.commit()

    _mirror_rule_to_alert_rules(rule)
    return jsonify({"success": True, "id": int(rule.id)})


@alerts_bp.put("/rules/<int:rule_id>")
def update_rule(rule_id: int):
    body = request.get_json(force=True) or {}
    rule = db.session.query(DetectionRule).get(rule_id)
    if not rule:
        return jsonify({"success": False, "error": "rule not found"}), 404

    if "name" in body:
        rule.name = (body["name"] or "").strip()
    if "enabled" in body:
        rule.enabled = bool(body["enabled"])
    if "severity" in body:
        rule.severity = body["severity"]
    if "cooldown_minutes" in body:
        rule.cooldown_minutes = int(body["cooldown_minutes"])

    if "spec" in body or "query" in body:
        spec_obj = body.get("spec")
        if spec_obj is None:
            spec_obj = body.get("query", {}) or {}
        try:
            spec_obj = normalize_rule_spec(spec_obj)
        except Exception as e:
            return jsonify({"success": False, "error": f"invalid spec: {str(e)}"}), 400
        rule.query_json = _safe_json_dumps(spec_obj)

    db.session.commit()
    _mirror_rule_to_alert_rules(rule)
    return jsonify({"success": True})


@alerts_bp.delete("/rules/<int:rule_id>")
def delete_rule(rule_id: int):
    rule = db.session.query(DetectionRule).get(rule_id)
    if not rule:
        return jsonify({"success": False, "error": "rule not found"}), 404

    rid = int(rule.id)
    db.session.delete(rule)
    db.session.commit()

    _delete_rule_from_alert_rules(rid)
    return jsonify({"success": True})


@alerts_bp.patch("/rules/<int:rule_id>")
def patch_rule(rule_id: int):
    body = request.get_json(force=True) or {}
    rule = db.session.query(DetectionRule).get(rule_id)
    if not rule:
        return jsonify({"success": False, "error": "rule not found"}), 404

    if "enabled" in body:
        rule.enabled = bool(body["enabled"])

    db.session.commit()
    _mirror_rule_to_alert_rules(rule)
    return jsonify({"success": True})


# ----------------------------
# Alerts list + actions
# ----------------------------
@alerts_bp.get("/")
def list_alerts():
    status = request.args.get("status")
    stats = request.args.get("stats")

    q = db.session.query(Alert)
    if status:
        q = q.filter(Alert.status == status)

    if stats == "1":
        count = q.count()

        sev_q = db.session.query(Alert.severity, func.count(Alert.id))
        if status:
            sev_q = sev_q.filter(Alert.status == status)
        sev_rows = sev_q.group_by(Alert.severity).all()

        severity_counts = {}
        for sev, c in sev_rows:
            key = sev or "unknown"
            severity_counts[key] = int(c)

        return jsonify({
            "success": True,
            "status": status,
            "count": int(count),
            "severity_counts": severity_counts
        })

    rows = q.order_by(Alert.last_seen.desc()).limit(200).all()
    data = []
    for a in rows:
        data.append({
            "id": a.id,
            "rule_id": a.rule_id,
            "status": a.status,
            "severity": a.severity,
            "title": a.title,
            "group_key": a.group_key,
            "hit_count": a.hit_count,
            "event_count": getattr(a, "event_count", None),
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "window_from": a.window_from.isoformat() if a.window_from else None,
            "window_to": a.window_to.isoformat() if a.window_to else None,
            "event_id": a.event_id,
            "closed_at": a.closed_at.isoformat() if hasattr(a, "closed_at") and a.closed_at else None,
            "alert_time": a.alert_time.isoformat() if hasattr(a, "alert_time") and a.alert_time else None,
            "created_at": a.created_at.isoformat() if hasattr(a, "created_at") and a.created_at else None,
            "details": _safe_json_loads(a.details_json, None)
        })
    return jsonify({"success": True, "data": data})


@alerts_bp.post("/<int:alert_id>/ack")
def ack_alert(alert_id: int):
    a = db.session.query(Alert).get(alert_id)
    if not a:
        return jsonify({"success": False, "error": "alert not found"}), 404

    body = request.get_json(silent=True) or {}
    note = body.get("note")

    details = _safe_json_loads(a.details_json, default={})
    details = _append_audit(details, "ack", note)
    a.details_json = _safe_json_dumps(details)

    a.status = "ack"
    a.last_seen = a.last_seen or _utcnow()

    db.session.commit()
    return jsonify({"success": True, "data": {"id": a.id, "status": a.status}})


@alerts_bp.post("/<int:alert_id>/close")
def close_alert(alert_id: int):
    a = db.session.query(Alert).get(alert_id)
    if not a:
        return jsonify({"success": False, "error": "alert not found"}), 404

    body = request.get_json(silent=True) or {}
    note = body.get("note")

    details = _safe_json_loads(a.details_json, default={})
    details = _append_audit(details, "close", note)
    a.details_json = _safe_json_dumps(details)

    a.status = "closed"
    if hasattr(a, "closed_at"):
        a.closed_at = _utcnow()
    a.last_seen = a.last_seen or _utcnow()

    db.session.commit()

    out = {"id": a.id, "status": a.status}
    if hasattr(a, "closed_at") and a.closed_at:
        out["closed_at"] = a.closed_at.isoformat()
    return jsonify({"success": True, "data": out})


# ----------------------------
# Alert Detail + Drill-down API
# ----------------------------
@alerts_bp.get("/<int:alert_id>")
def get_alert_detail(alert_id: int):
    a = db.session.query(Alert).get(alert_id)
    if not a:
        return jsonify({"success": False, "error": "alert not found"}), 404

    details = _safe_json_loads(a.details_json, default={})

    alert_obj = {
        "id": a.id,
        "rule_id": a.rule_id,
        "title": a.title,
        "status": a.status,
        "severity": a.severity,
        "group_key": a.group_key,
        "created_at": a.created_at.isoformat() if getattr(a, "created_at", None) else None,
        "window_from": a.window_from.isoformat() if a.window_from else None,
        "window_to": a.window_to.isoformat() if a.window_to else None,
        "hit_count": a.hit_count,
        "event_count": getattr(a, "event_count", None),
        "event_id": a.event_id,
        "details": details,
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "closed_at": a.closed_at.isoformat() if hasattr(a, "closed_at") and a.closed_at else None,
    }

    w_from = a.window_from or a.first_seen or getattr(a, "created_at", None) or (_utcnow() - timedelta(minutes=5))
    w_to = a.window_to or a.last_seen or getattr(a, "created_at", None) or _utcnow()

    q = db.session.query(LogEvent).filter(LogEvent.ingest_time.between(w_from, w_to))

    filters = None
    if isinstance(details, dict):
        filters = details.get("filters") if isinstance(details.get("filters"), dict) else None
    if filters:
        q = _apply_common_filters(q, filters)

    q = q.order_by(LogEvent.ingest_time.desc()).limit(50)
    events = q.all()

    pinned = None
    if a.event_id:
        pinned = db.session.query(LogEvent).get(a.event_id)

    out = []
    seen = set()

    if pinned:
        d = _event_to_dict(pinned)
        if d and d["id"] not in seen:
            out.append(d)
            seen.add(d["id"])

    for e in events:
        d = _event_to_dict(e)
        if d and d["id"] not in seen:
            out.append(d)
            seen.add(d["id"])

    return jsonify({"success": True, "alert": alert_obj, "related_events": out})


@alerts_bp.get("/<int:alert_id>/events")
def get_alert_events(alert_id: int):
    a = db.session.query(Alert).get(alert_id)
    if not a:
        return jsonify({"success": False, "error": "alert not found"}), 404

    limit = request.args.get("limit", type=int) or 100
    limit = max(1, min(500, limit))

    details = _safe_json_loads(a.details_json, default={})

    w_from = a.window_from or a.first_seen or getattr(a, "created_at", None) or (_utcnow() - timedelta(minutes=5))
    w_to = a.window_to or a.last_seen or getattr(a, "created_at", None) or _utcnow()

    q = db.session.query(LogEvent).filter(LogEvent.ingest_time.between(w_from, w_to))

    filters = None
    if isinstance(details, dict):
        filters = details.get("filters") if isinstance(details.get("filters"), dict) else None
    if filters:
        q = _apply_common_filters(q, filters)

    rows = q.order_by(desc(LogEvent.ingest_time)).limit(limit).all()

    data = []
    for e in rows:
        data.append({
            "id": e.id,
            "ingest_time": e.ingest_time.isoformat() if e.ingest_time else None,
            "service": e.service,
            "level": e.level,
            "message": e.message,
            "src_ip": getattr(e, "src_ip", None),
            "http_status": getattr(e, "http_status", None),
            "url": getattr(e, "url", None),
            "category": getattr(e, "category", None),
            "parse_status": getattr(e, "parse_status", None),
        })

    return jsonify({
        "success": True,
        "alert_id": a.id,
        "range": {"from": w_from.isoformat() if w_from else None, "to": w_to.isoformat() if w_to else None},
        "count": len(data),
        "data": data
    })


# ----------------------------
# Rule Engine (Runner)
# ----------------------------
@alerts_bp.post("/run")
def run_rules():
    """
    Runner endpoint.
    - minutes default 30
    - debug=1 destekli
    - use_latest=1: window_to'yu DB'deki en yeni ingest_time'a göre ayarla
    """
    body = request.get_json(silent=True) or {}

    minutes = body.get("minutes", None)
    if minutes is None:
        minutes = request.args.get("minutes", None)
    try:
        minutes = int(minutes) if minutes is not None else 30
    except Exception:
        minutes = 30
    minutes = max(1, min(24 * 60, minutes))

    debug = str(request.args.get("debug") or "").strip().lower() in ("1", "true", "yes")
    use_latest = str(request.args.get("use_latest") or "").strip().lower() in ("1", "true", "yes")

    window_to = _utcnow()
    if use_latest:
        latest = (
            db.session.query(LogEvent.ingest_time)
            .order_by(LogEvent.ingest_time.desc())
            .first()
        )
        if latest and latest[0]:
            window_to = latest[0]

    window_from = window_to - timedelta(minutes=minutes)

    total_events = (
        db.session.query(func.count(LogEvent.id))
        .filter(LogEvent.ingest_time.between(window_from, window_to))
        .scalar()
    ) or 0

    rules = db.session.query(DetectionRule).filter(DetectionRule.enabled == True).all()

    fired = []
    debug_rules = []

    for rule in rules:
        raw = _safe_json_loads(rule.query_json, {})
        try:
            spec = normalize_rule_spec(raw)
        except Exception as e:
            if debug:
                debug_rules.append({"rule_id": rule.id, "name": rule.name, "skipped": True, "reason": str(e)})
            continue

        rtype = spec.get("type")
        filters = spec.get("filters", {}) or {}

        try:
            if debug:
                base_q = (
                    db.session.query(LogEvent)
                    .filter(LogEvent.ingest_time.between(window_from, window_to))
                )
                base_q = _apply_common_filters(base_q, filters)
                matched = base_q.count()

                debug_rules.append({
                    "rule_id": rule.id,
                    "name": rule.name,
                    "type": rtype,
                    "minutes": minutes,
                    "threshold": spec.get("threshold"),
                    "group_by": spec.get("group_by"),
                    "filters": filters,
                    "matched_events_in_window": int(matched),
                })

            fired += _eval_rule(rule, spec, window_from, window_to)

        except Exception as e:
            db.session.rollback()
            fired.append({"rule_id": rule.id, "name": rule.name, "error": str(e)})

    resp = {
        "success": True,
        "use_latest": use_latest,
        "window_from": window_from.isoformat(),
        "window_to": window_to.isoformat(),
        "minutes": minutes,
        "total_events_in_window": int(total_events),
        "fired": fired
    }
    if debug:
        resp["debug"] = {"rules": debug_rules}

    return jsonify(resp)


def _eval_rule(rule: DetectionRule, spec: dict, window_from: datetime, window_to: datetime):
    rtype = spec["type"]
    group_by = spec.get("group_by")
    threshold = int(spec.get("threshold", 1))
    filters = spec.get("filters", {}) or {}

    results = []

    # -----------------------------
    # count_threshold
    # -----------------------------
    if rtype == "count_threshold":
        if not group_by:
            raise ValueError("count_threshold requires group_by")
        if not hasattr(LogEvent, group_by):
            raise ValueError(f"Invalid group_by field: {group_by}")

        col = getattr(LogEvent, group_by)
        agg = (
            db.session.query(col.label("k"), func.count(LogEvent.id).label("c"))
            .filter(LogEvent.ingest_time.between(window_from, window_to))
        )
        agg = _apply_common_filters(agg, filters)
        agg = agg.group_by(col).having(func.count(LogEvent.id) >= threshold).order_by(func.count(LogEvent.id).desc())

        for k, c in agg.all():
            # ✅ STANDARD group_key
            gk = f"{rule.id}:{rtype}:{group_by}={k}"
            title = f"{rule.name} ({group_by}={k}) count={int(c)}"

            details = _ensure_filters_in_details({
                "count": int(c),
                "group_by": group_by,
                "group_value": k,
                "window_minutes": int((window_to - window_from).total_seconds() / 60)
            }, filters)

            rep = (
                db.session.query(LogEvent.id)
                .filter(LogEvent.ingest_time.between(window_from, window_to))
                .filter(col == k)
                .order_by(LogEvent.ingest_time.desc())
                .first()
            )

            alert, created = _dedup_or_create_alert(
                rule, gk, title, window_from, window_to,
                details, rep[0] if rep else None
            )
            results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})

        return results

    # -----------------------------
    # distinct_threshold
    # -----------------------------
    if rtype == "distinct_threshold":
        if not group_by or not spec.get("distinct_field"):
            raise ValueError("distinct_threshold requires group_by + distinct_field")

        distinct_field = spec["distinct_field"]
        if not hasattr(LogEvent, group_by):
            raise ValueError(f"Invalid group_by field: {group_by}")
        if not hasattr(LogEvent, distinct_field):
            raise ValueError(f"Invalid distinct_field: {distinct_field}")

        col_g = getattr(LogEvent, group_by)
        col_d = getattr(LogEvent, distinct_field)

        agg = (
            db.session.query(col_g.label("k"), func.count(func.distinct(col_d)).label("dc"))
            .filter(LogEvent.ingest_time.between(window_from, window_to))
        )
        agg = _apply_common_filters(agg, filters)
        agg = agg.group_by(col_g).having(func.count(func.distinct(col_d)) >= threshold).order_by(func.count(func.distinct(col_d)).desc())

        for k, dc in agg.all():
            # ✅ STANDARD group_key (distinct_field dahil)
            gk = f"{rule.id}:{rtype}:{group_by}={k}|distinct={distinct_field}"
            title = f"{rule.name} ({group_by}={k}) distinct({distinct_field})={int(dc)}"

            details = _ensure_filters_in_details({
                "distinct": int(dc),
                "distinct_field": distinct_field,
                "group_by": group_by,
                "group_value": k,
                "window_minutes": int((window_to - window_from).total_seconds() / 60)
            }, filters)

            rep = (
                db.session.query(LogEvent.id)
                .filter(LogEvent.ingest_time.between(window_from, window_to))
                .filter(col_g == k)
                .order_by(LogEvent.ingest_time.desc())
                .first()
            )

            alert, created = _dedup_or_create_alert(
                rule, gk, title, window_from, window_to,
                details, rep[0] if rep else None
            )
            results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})

        return results

    # -----------------------------
    # status_code_spike
    # -----------------------------
    if rtype == "status_code_spike":
        if not group_by:
            raise ValueError("status_code_spike requires group_by")
        if not hasattr(LogEvent, group_by):
            raise ValueError(f"Invalid group_by field: {group_by}")

        min_s = int(spec.get("status_min", 500))
        max_s = int(spec.get("status_max", 599))
        col_g = getattr(LogEvent, group_by)

        agg = (
            db.session.query(col_g.label("k"), func.count(LogEvent.id).label("c"))
            .filter(LogEvent.ingest_time.between(window_from, window_to))
            .filter(LogEvent.http_status >= min_s, LogEvent.http_status <= max_s)
        )
        agg = _apply_common_filters(agg, filters)
        agg = agg.group_by(col_g).having(func.count(LogEvent.id) >= threshold).order_by(func.count(LogEvent.id).desc())

        for k, c in agg.all():
            # ✅ STANDARD group_key (status aralığı dahil)
            gk = f"{rule.id}:{rtype}:{group_by}={k}:{min_s}-{max_s}"
            title = f"{rule.name} ({group_by}={k}) status[{min_s}-{max_s}] count={int(c)}"

            details = _ensure_filters_in_details({
                "count": int(c),
                "status_min": min_s,
                "status_max": max_s,
                "group_by": group_by,
                "group_value": k,
                "window_minutes": int((window_to - window_from).total_seconds() / 60)
            }, filters)

            rep = (
                db.session.query(LogEvent.id)
                .filter(LogEvent.ingest_time.between(window_from, window_to))
                .filter(col_g == k)
                .filter(LogEvent.http_status >= min_s, LogEvent.http_status <= max_s)
                .order_by(LogEvent.ingest_time.desc())
                .first()
            )

            alert, created = _dedup_or_create_alert(
                rule, gk, title, window_from, window_to,
                details, rep[0] if rep else None
            )
            results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})

        return results

    # -----------------------------
    # pattern_match
    # -----------------------------
    if rtype == "pattern_match":
        field = spec.get("field", "url")
        patterns = spec.get("patterns", []) or []
        mode = spec.get("mode", "single")

        if not hasattr(LogEvent, field):
            raise ValueError(f"Invalid pattern field: {field}")

        col = getattr(LogEvent, field)

        like_filters = []
        clean_patterns = []
        for p in patterns:
            if not p:
                continue
            p2 = str(p)
            clean_patterns.append(p2)
            like_filters.append(col.ilike(f"%{p2}%"))

        if not like_filters:
            return results

        patt_key = ",".join(clean_patterns)

        q2 = db.session.query(LogEvent).filter(LogEvent.ingest_time.between(window_from, window_to))
        q2 = _apply_common_filters(q2, filters)
        q2 = q2.filter(or_(*like_filters))

        # --- mode=single: bir tane hit yeter ---
        if mode == "single":
            hit = q2.order_by(LogEvent.ingest_time.desc()).first()
            if not hit:
                return results

            # group_by varsa group key'e kat, yoksa global
            if group_by and hasattr(hit, group_by):
                gv = getattr(hit, group_by)
                gk = f"{rule.id}:{rtype}:{group_by}={gv}|{field}~{patt_key}"
                title = f"{rule.name} ({group_by}={gv}) pattern hit"
            else:
                gk = f"{rule.id}:{rtype}:{field}~{patt_key}"
                title = f"{rule.name} (global) pattern hit"

            # ✅ count=1 ekledik -> event_count artık 0 kalmaz
            details = _ensure_filters_in_details({
                "field": field,
                "patterns": clean_patterns,
                "matched_event_id": hit.id,
                "count": 1
            }, filters)

            alert, created = _dedup_or_create_alert(
                rule, gk, title, window_from, window_to,
                details, hit.id
            )
            results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})
            return results

        # --- mode!=single: count üzerinden threshold ---
        total_c = q2.count()
        if total_c <= 0:
            return results

        # group_by yoksa global count
        if not group_by:
            if total_c >= threshold:
                hit = q2.order_by(LogEvent.ingest_time.desc()).first()
                gk = f"{rule.id}:{rtype}:{field}~{patt_key}"
                title = f"{rule.name} (global) pattern count={int(total_c)}"

                details = _ensure_filters_in_details({
                    "field": field,
                    "patterns": clean_patterns,
                    "count": int(total_c),
                    "window_minutes": int((window_to - window_from).total_seconds() / 60)
                }, filters)

                alert, created = _dedup_or_create_alert(
                    rule, gk, title, window_from, window_to,
                    details, hit.id if hit else None
                )
                results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})
            return results

        # group_by var: grouped count
        if not hasattr(LogEvent, group_by):
            raise ValueError(f"Invalid group_by field: {group_by}")

        col_g = getattr(LogEvent, group_by)
        agg = (
            db.session.query(col_g.label("k"), func.count(LogEvent.id).label("c"))
            .filter(LogEvent.ingest_time.between(window_from, window_to))
        )
        agg = _apply_common_filters(agg, filters)
        agg = agg.filter(or_(*like_filters))
        agg = agg.group_by(col_g).having(func.count(LogEvent.id) >= threshold)

        for k, c in agg.all():
            gk = f"{rule.id}:{rtype}:{group_by}={k}|{field}~{patt_key}"
            title = f"{rule.name} ({group_by}={k}) pattern count={int(c)}"

            hit = (
                db.session.query(LogEvent)
                .filter(LogEvent.ingest_time.between(window_from, window_to))
                .filter(col_g == k)
                .filter(or_(*like_filters))
                .order_by(LogEvent.ingest_time.desc())
                .first()
            )

            details = _ensure_filters_in_details({
                "field": field,
                "patterns": clean_patterns,
                "count": int(c),
                "group_by": group_by,
                "group_value": k,
                "window_minutes": int((window_to - window_from).total_seconds() / 60)
            }, filters)

            alert, created = _dedup_or_create_alert(
                rule, gk, title, window_from, window_to,
                details, hit.id if hit else None
            )
            results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})

        return results

    # -----------------------------
    # Unknown type
    # -----------------------------
    raise ValueError(f"Unknown rule type: {rtype}")


@alerts_bp.post("/test-run")
def test_run():
    try:
        minutes = request.args.get("minutes", type=int)
        minutes = minutes if minutes and minutes > 0 else 5

        engine = AlertEngine(minutes=minutes)
        stats = engine.run_once() or {}
        return jsonify({"ok": True, **stats}), 200

    except Exception as e:
        current_app.logger.exception("ALERT_RUNNER test-run failed")
        return jsonify({"ok": False, "error": "ALERT_RUNNER", "detail": str(e)}), 500


@alerts_bp.get("/diag")
def diag():
    uri = str(current_app.config.get("SQLALCHEMY_DATABASE_URI", ""))

    total_logs = db.session.query(func.count(LogEvent.id)).scalar() or 0

    newest = (
        db.session.query(LogEvent)
        .order_by(LogEvent.ingest_time.desc())
        .first()
    )

    newest_time = newest.ingest_time.isoformat() if newest and newest.ingest_time else None

    samples = (
        db.session.query(LogEvent)
        .order_by(LogEvent.id.desc())
        .limit(3)
        .all()
    )

    return jsonify({
        "ok": True,
        "db_uri": uri,
        "log_total": int(total_logs),
        "newest_ingest_time": newest_time,
        "sample": [
            {
                "id": e.id,
                "ingest_time": e.ingest_time.isoformat() if e.ingest_time else None,
                "service": e.service,
                "category": e.category,
                "event_type": getattr(e, "event_type", None),
                "level": e.level,
                "http_status": getattr(e, "http_status", None),
                "src_ip": getattr(e, "src_ip", None),
                "message": e.message
            }
            for e in samples
        ]
    })


@alerts_bp.get("/diag-rules")
def diag_rules():
    orm_rules = db.session.query(DetectionRule.id, DetectionRule.name).order_by(DetectionRule.id).all()

    try:
        rows = db.session.execute(db.text("SELECT TOP 50 id, name, detection_rule_id FROM dbo.alert_rules ORDER BY id")).fetchall()
        db_rules = [{"id": int(r[0]), "name": r[1], "detection_rule_id": int(r[2]) if r[2] is not None else None} for r in rows]
    except Exception as e:
        db_rules = {"error": str(e)}

    return jsonify({
        "ok": True,
        "orm_detection_rules": [{"id": int(r[0]), "name": r[1]} for r in orm_rules],
        "db_alert_rules": db_rules
    })


@alerts_bp.post("/rules/mirror")
def mirror_all_rules():
    rules = db.session.query(DetectionRule).order_by(DetectionRule.id).all()

    ok = []
    failed = []

    for r in rules:
        try:
            ar_id = _mirror_rule_to_alert_rules(r)
            item = {"detection_rule_id": int(r.id), "name": r.name, "alert_rules_id": ar_id}
            ok.append(item)
        except Exception:
            item = {"detection_rule_id": int(r.id), "name": r.name, "alert_rules_id": None}
            failed.append(item)

    status = 200 if not failed else 500

    return jsonify({
        "success": len(failed) == 0,
        "ok_count": len(ok),
        "fail_count": len(failed),
        "ok": ok,
        "failed": failed
    }), status
