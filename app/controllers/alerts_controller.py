# app/controllers/alerts_controller.py
import json
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import func, or_, desc

from ..extensions import db
from ..models.log_event import LogEvent
from ..models.detection_rule import DetectionRule
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

    if filters.get("http_status") is not None:
        q = q.filter(LogEvent.http_status == int(filters["http_status"]))

    if filters.get("http_status_in"):
        vals = []
        for v in filters["http_status_in"]:
            try:
                vals.append(int(v))
            except Exception:
                pass
        if vals:
            q = q.filter(LogEvent.http_status.in_(vals))

    if filters.get("http_status_min") is not None:
        q = q.filter(LogEvent.http_status >= int(filters["http_status_min"]))
    if filters.get("http_status_max") is not None:
        q = q.filter(LogEvent.http_status <= int(filters["http_status_max"]))

    if filters.get("url_contains") and hasattr(LogEvent, "url"):
        like = f"%{filters['url_contains']}%"
        q = q.filter(LogEvent.url.ilike(like))

    if filters.get("message_contains"):
        like = f"%{filters['message_contains']}%"
        q = q.filter(LogEvent.message.ilike(like))

    return q


def _ensure_filters_in_details(details: dict | None, filters: dict | None):
    details = details or {}
    if filters and isinstance(filters, dict):
        details["filters"] = filters
    return details


def _dedup_or_create_alert(
    rule: DetectionRule,
    group_key: str | None,
    title: str,
    window_from: datetime,
    window_to: datetime,
    details: dict | None = None,
    representative_event_id: int | None = None
):
    cooldown = timedelta(minutes=int(rule.cooldown_minutes or 15))
    since = window_to - cooldown

    existing = (
        db.session.query(Alert)
        .filter(Alert.rule_id == rule.id)
        .filter(Alert.group_key == group_key)
        .filter(Alert.status.in_(["open", "ack"]))
        .filter(Alert.last_seen >= since)
        .order_by(Alert.last_seen.desc())
        .first()
    )

    now = _utcnow()

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

        db.session.commit()
        return existing, False

    a = Alert(
        rule_id=rule.id,
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

    db.session.add(a)
    db.session.commit()

    try:
        run_actions_for_alert(a, rule, current_app.config)
    except Exception:
        pass

    return a, True


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
        data.append({
            "id": r.id,
            "name": r.name,
            "enabled": r.enabled,
            "severity": r.severity,
            "cooldown_minutes": r.cooldown_minutes,
            "query_json": _safe_json_loads(r.query_json, {}),
            "created_at": r.created_at.isoformat() if getattr(r, "created_at", None) else None
        })
    return jsonify({"success": True, "data": data})


@alerts_bp.post("/rules")
def create_rule():
    body = request.get_json(force=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "name required"}), 400

    query_obj = body.get("query", {}) or {}
    rule = DetectionRule(
        name=name,
        enabled=bool(body.get("enabled", True)),
        severity=body.get("severity", "medium"),
        cooldown_minutes=int(body.get("cooldown_minutes", 15)),
        query_json=_safe_json_dumps(query_obj),
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify({"success": True, "id": rule.id})


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
    if "query" in body:
        rule.query_json = _safe_json_dumps(body["query"])

    db.session.commit()
    return jsonify({"success": True})


@alerts_bp.delete("/rules/<int:rule_id>")
def delete_rule(rule_id: int):
    rule = db.session.query(DetectionRule).get(rule_id)
    if not rule:
        return jsonify({"success": False, "error": "rule not found"}), 404
    db.session.delete(rule)
    db.session.commit()
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
    body = request.get_json(silent=True) or {}
    minutes = int(body.get("minutes", 5))
    window_to = _utcnow()
    window_from = window_to - timedelta(minutes=minutes)

    rules = db.session.query(DetectionRule).filter(DetectionRule.enabled == True).all()

    fired = []
    for rule in rules:
        spec = _safe_json_loads(rule.query_json, {})
        rtype = spec.get("type")
        if not rtype:
            continue

        try:
            fired += _eval_rule(rule, spec, window_from, window_to)
        except Exception as e:
            db.session.rollback()
            fired.append({"rule_id": rule.id, "error": str(e)})

    return jsonify({
        "success": True,
        "window_from": window_from.isoformat(),
        "window_to": window_to.isoformat(),
        "fired": fired
    })


def _eval_rule(rule: DetectionRule, spec: dict, window_from: datetime, window_to: datetime):
    rtype = spec["type"]
    group_by = spec.get("group_by")
    threshold = int(spec.get("threshold", 1))
    filters = spec.get("filters", {}) or {}

    results = []

    if rtype == "count_threshold":
        if not group_by:
            raise ValueError("count_threshold requires group_by")

        col = getattr(LogEvent, group_by)
        agg = (
            db.session.query(col.label("k"), func.count(LogEvent.id).label("c"))
            .filter(LogEvent.ingest_time.between(window_from, window_to))
        )
        agg = _apply_common_filters(agg, filters)
        agg = agg.group_by(col).having(func.count(LogEvent.id) >= threshold).order_by(func.count(LogEvent.id).desc())

        rows = agg.all()
        for k, c in rows:
            gk = f"{group_by}={k}"
            title = f"{rule.name} ({gk}) count={c}"

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
            alert, created = _dedup_or_create_alert(rule, gk, title, window_from, window_to, details, rep[0] if rep else None)
            results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})

    elif rtype == "distinct_threshold":
        if not group_by or not spec.get("distinct_field"):
            raise ValueError("distinct_threshold requires group_by + distinct_field")

        distinct_field = spec["distinct_field"]
        col_g = getattr(LogEvent, group_by)
        col_d = getattr(LogEvent, distinct_field)

        agg = (
            db.session.query(col_g.label("k"), func.count(func.distinct(col_d)).label("dc"))
            .filter(LogEvent.ingest_time.between(window_from, window_to))
        )
        agg = _apply_common_filters(agg, filters)
        agg = agg.group_by(col_g).having(func.count(func.distinct(col_d)) >= threshold).order_by(func.count(func.distinct(col_d)).desc())

        rows = agg.all()
        for k, dc in rows:
            gk = f"{group_by}={k}"
            title = f"{rule.name} ({gk}) distinct({distinct_field})={dc}"

            details = _ensure_filters_in_details({
                "distinct": int(dc),
                "distinct_field": distinct_field,
                "group_by": group_by,
                "group_value": k
            }, filters)

            rep = (
                db.session.query(LogEvent.id)
                .filter(LogEvent.ingest_time.between(window_from, window_to))
                .filter(col_g == k)
                .order_by(LogEvent.ingest_time.desc())
                .first()
            )
            alert, created = _dedup_or_create_alert(rule, gk, title, window_from, window_to, details, rep[0] if rep else None)
            results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})

    elif rtype == "status_code_spike":
        if not group_by:
            raise ValueError("status_code_spike requires group_by")

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

        rows = agg.all()
        for k, c in rows:
            gk = f"{group_by}={k}"
            title = f"{rule.name} ({gk}) status[{min_s}-{max_s}] count={c}"

            details = _ensure_filters_in_details({
                "count": int(c),
                "status_min": min_s,
                "status_max": max_s,
                "group_by": group_by,
                "group_value": k
            }, filters)

            rep = (
                db.session.query(LogEvent.id)
                .filter(LogEvent.ingest_time.between(window_from, window_to))
                .filter(col_g == k)
                .filter(LogEvent.http_status >= min_s, LogEvent.http_status <= max_s)
                .order_by(LogEvent.ingest_time.desc())
                .first()
            )
            alert, created = _dedup_or_create_alert(rule, gk, title, window_from, window_to, details, rep[0] if rep else None)
            results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})

    elif rtype == "pattern_match":
        field = spec.get("field", "url")
        patterns = spec.get("patterns", []) or []
        mode = spec.get("mode", "single")

        col = getattr(LogEvent, field)

        like_filters = []
        for p in patterns:
            if not p:
                continue
            like_filters.append(col.ilike(f"%{p}%"))

        if not like_filters:
            return results

        q2 = db.session.query(LogEvent).filter(LogEvent.ingest_time.between(window_from, window_to))
        q2 = _apply_common_filters(q2, filters)
        q2 = q2.filter(or_(*like_filters))

        if mode == "single":
            hit = q2.order_by(LogEvent.ingest_time.desc()).first()
            if hit:
                gk = f"{group_by}={getattr(hit, group_by)}" if group_by else None
                title = f"{rule.name} ({gk or 'global'}) pattern hit"
                details = _ensure_filters_in_details({
                    "field": field,
                    "patterns": patterns,
                    "matched_event_id": hit.id
                }, filters)
                alert, created = _dedup_or_create_alert(rule, gk, title, window_from, window_to, details, hit.id)
                results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})
        else:
            c = q2.count()
            if not group_by:
                if c >= threshold:
                    hit = q2.order_by(LogEvent.ingest_time.desc()).first()
                    details = _ensure_filters_in_details({
                        "field": field,
                        "patterns": patterns,
                        "count": int(c)
                    }, filters)
                    alert, created = _dedup_or_create_alert(
                        rule, None, f"{rule.name} global pattern count={c}",
                        window_from, window_to, details, hit.id if hit else None
                    )
                    results.append({"rule_id": rule.id, "group_key": None, "created": created, "alert_id": alert.id})
            else:
                col_g = getattr(LogEvent, group_by)
                agg = (
                    db.session.query(col_g.label("k"), func.count(LogEvent.id).label("c"))
                    .filter(LogEvent.ingest_time.between(window_from, window_to))
                )
                agg = _apply_common_filters(agg, filters)
                agg = agg.filter(or_(*like_filters))
                agg = agg.group_by(col_g).having(func.count(LogEvent.id) >= threshold)

                rows = agg.all()
                for k, c in rows:
                    gk = f"{group_by}={k}"
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
                        "patterns": patterns,
                        "count": int(c),
                        "group_by": group_by,
                        "group_value": k
                    }, filters)
                    alert, created = _dedup_or_create_alert(
                        rule, gk, f"{rule.name} ({gk}) pattern count={c}",
                        window_from, window_to, details, hit.id if hit else None
                    )
                    results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})
    else:
        raise ValueError(f"Unknown rule type: {rtype}")

    return results


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
