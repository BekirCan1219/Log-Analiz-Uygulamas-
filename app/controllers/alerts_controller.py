import json
from flask import Blueprint, request, jsonify
from ..extensions import db
from ..models.alert_rule import AlertRule
from ..models.alert import Alert
from ..services.alert_engine import AlertEngine

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")
engine = AlertEngine()

@alerts_bp.post("/rules")
def create_rule():
    body = request.get_json(force=True)

    rule = AlertRule(
        name=body.get("name", "Unnamed Rule"),
        enabled=bool(body.get("enabled", True)),
        query_json=json.dumps(body.get("query", {}), ensure_ascii=False),
        window_minutes=int(body.get("window_minutes", 5)),
        threshold=int(body.get("threshold", 50)),
        group_by=body.get("group_by", "service"),
        severity=body.get("severity", "medium"),
        cooldown_minutes=int(body.get("cooldown_minutes", 10)),
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify({"success": True, "id": rule.id})

@alerts_bp.get("/rules")
def list_rules():
    rules = AlertRule.query.order_by(AlertRule.id.desc()).all()
    data = []
    for r in rules:
        data.append({
            "id": r.id,
            "name": r.name,
            "enabled": r.enabled,
            "query": json.loads(r.query_json),
            "window_minutes": r.window_minutes,
            "threshold": r.threshold,
            "group_by": r.group_by,
            "severity": r.severity,
            "cooldown_minutes": r.cooldown_minutes
        })
    return jsonify({"success": True, "data": data})

@alerts_bp.post("/run-once")
def run_once():
    created = engine.run_once()
    return jsonify({"success": True, "created": created})

@alerts_bp.get("")
def list_alerts():
    status = request.args.get("status")  # open/ack/closed
    q = Alert.query
    if status:
        q = q.filter(Alert.status == status)

    alerts = q.order_by(Alert.alert_time.desc()).limit(200).all()
    data = []
    for a in alerts:
        data.append({
            "id": a.id,
            "rule_id": a.rule_id,
            "alert_time": a.alert_time.isoformat(),
            "severity": a.severity,
            "title": a.title,
            "group_key": a.group_key,
            "event_count": a.event_count,
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "status": a.status
        })
    return jsonify({"success": True, "data": data})

@alerts_bp.post("/<int:alert_id>/ack")
def ack_alert(alert_id: int):
    a = Alert.query.get_or_404(alert_id)
    a.status = "ack"
    db.session.commit()
    return jsonify({"success": True})

@alerts_bp.post("/<int:alert_id>/close")
def close_alert(alert_id: int):
    a = Alert.query.get_or_404(alert_id)
    a.status = "closed"
    db.session.commit()
    return jsonify({"success": True})

@alerts_bp.get("/run-once")
def run_once_get():
    created = engine.run_once()
    return jsonify({"success": True, "created": created})
