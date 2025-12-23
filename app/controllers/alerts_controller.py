# app/controllers/alerts_controller.py
import json
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import func, or_

from ..extensions import db
from ..models.log_event import LogEvent
from ..models.detection_rule import DetectionRule
from ..models.alert import Alert

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


def _apply_common_filters(q, filters: dict):
    """
    filters keys (optional):
      service, level, category, event_type, src_ip, http_status, http_status_in,
      http_status_min, http_status_max, url_contains, message_contains
    """
    if not filters:
        return q

    if filters.get("service"):
        q = q.filter(LogEvent.service == filters["service"])
    if filters.get("level"):
        q = q.filter(LogEvent.level == filters["level"])
    if filters.get("category"):
        q = q.filter(LogEvent.category == filters["category"])
    if filters.get("event_type"):
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

    if filters.get("url_contains"):
        like = f"%{filters['url_contains']}%"
        q = q.filter(LogEvent.url.ilike(like))

    if filters.get("message_contains"):
        like = f"%{filters['message_contains']}%"
        q = q.filter(LogEvent.message.ilike(like))

    return q


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
    If there's an open/ack alert with same (rule_id, group_key) within cooldown -> increment hit_count & last_seen.
    Else create new alert.
    """
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

        # Eğer modelinde alert_time alanı varsa, dedup olduğunda da güncelleyelim:
        if hasattr(existing, "alert_time"):
            existing.alert_time = now

        if details is not None:
            existing.details_json = json.dumps(details, ensure_ascii=False)
        if representative_event_id:
            existing.event_id = representative_event_id

        db.session.commit()
        return existing, False

    # Yeni alert
    a = Alert(
        rule_id=rule.id,
        status="open",
        severity=rule.severity,
        title=title,
        group_key=group_key,
        details_json=json.dumps(details, ensure_ascii=False) if details else None,
        window_from=window_from,
        window_to=window_to,
        first_seen=now,
        last_seen=now,
        hit_count=1,
        event_id=representative_event_id
    )

    # created_at ve alert_time alanları modelde varsa set et
    if hasattr(a, "created_at"):
        a.created_at = now
    if hasattr(a, "alert_time"):
        a.alert_time = now

    db.session.add(a)
    db.session.commit()

    # ✅ aksiyonları sadece yeni alert oluşturulunca tetikle
    try:
        run_actions_for_alert(a, rule, current_app.config)
    except Exception:
        # aksiyon hatası alert'i bozmasın
        pass

    return a, True


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
        query_json=json.dumps(query_obj, ensure_ascii=False),
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
        rule.query_json = json.dumps(body["query"], ensure_ascii=False)

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


# ----------------------------
# Alerts list + actions
# ----------------------------
@alerts_bp.get("/")
def list_alerts():
    status = request.args.get("status")  # open/ack/closed
    q = db.session.query(Alert)
    if status:
        q = q.filter(Alert.status == status)

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
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "window_from": a.window_from.isoformat() if a.window_from else None,
            "window_to": a.window_to.isoformat() if a.window_to else None,
            "event_id": a.event_id,
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
    a.status = "ack"
    db.session.commit()
    return jsonify({"success": True})


@alerts_bp.post("/<int:alert_id>/close")
def close_alert(alert_id: int):
    a = db.session.query(Alert).get(alert_id)
    if not a:
        return jsonify({"success": False, "error": "alert not found"}), 404
    a.status = "closed"
    db.session.commit()
    return jsonify({"success": True})


# ----------------------------
# Rule Engine (Runner)
# ----------------------------
@alerts_bp.post("/run")
def run_rules():
    """
    Manual runner:
      POST /api/alerts/run
      body: { "minutes": 5 }  -> evaluate last X minutes using ingest_time
    """
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
            # ✅ SQLAlchemy session "failed state" olmasın
            db.session.rollback()
            fired.append({"rule_id": rule.id, "error": str(e)})

    return jsonify({
        "success": True,
        "window_from": window_from.isoformat(),
        "window_to": window_to.isoformat(),
        "fired": fired
    })


def _eval_rule(rule: DetectionRule, spec: dict, window_from: datetime, window_to: datetime):
    """
    Supported types:
      - count_threshold: group_by + threshold
      - distinct_threshold: group_by + distinct_field + threshold
      - status_code_spike: group_by + min/max + threshold
      - pattern_match: group_by + patterns + field(url/message/raw_text/extra_json) + mode(single|threshold)
    """
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
            details = {
                "count": int(c),
                "group_by": group_by,
                "group_value": k,
                "window_minutes": int((window_to - window_from).total_seconds() / 60)
            }

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
            details = {"distinct": int(dc), "distinct_field": distinct_field, "group_by": group_by, "group_value": k}

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
            details = {"count": int(c), "status_min": min_s, "status_max": max_s, "group_by": group_by, "group_value": k}

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

        q2 = (
            db.session.query(LogEvent)
            .filter(LogEvent.ingest_time.between(window_from, window_to))
        )
        q2 = _apply_common_filters(q2, filters)
        q2 = q2.filter(or_(*like_filters))

        if mode == "single":
            hit = q2.order_by(LogEvent.ingest_time.desc()).first()
            if hit:
                gk = f"{group_by}={getattr(hit, group_by)}" if group_by else None
                title = f"{rule.name} ({gk or 'global'}) pattern hit"
                details = {"field": field, "patterns": patterns, "matched_event_id": hit.id}
                alert, created = _dedup_or_create_alert(rule, gk, title, window_from, window_to, details, hit.id)
                results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})
        else:
            c = q2.count()
            if not group_by:
                if c >= threshold:
                    hit = q2.order_by(LogEvent.ingest_time.desc()).first()
                    details = {"field": field, "patterns": patterns, "count": int(c)}
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
                    details = {"field": field, "patterns": patterns, "count": int(c),
                               "group_by": group_by, "group_value": k}
                    alert, created = _dedup_or_create_alert(
                        rule, gk, f"{rule.name} ({gk}) pattern count={c}",
                        window_from, window_to, details, hit.id if hit else None
                    )
                    results.append({"rule_id": rule.id, "group_key": gk, "created": created, "alert_id": alert.id})

    else:
        raise ValueError(f"Unknown rule type: {rtype}")

    return results
