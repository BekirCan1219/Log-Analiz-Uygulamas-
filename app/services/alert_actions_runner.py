# app/services/alert_actions_runner.py
import json
from typing import Any, Dict, List, Optional

from .actions import send_webhook, send_email_smtp


def _safe_json_loads(s: str) -> Dict[str, Any]:
    try:
        return json.loads(s) if s else {}
    except Exception:
        return {}


def _extract_actions_from_rule(rule_obj) -> List[Dict[str, Any]]:
    """
    Rule objesi AlertRule da olabilir DetectionRule da.
    Biz actions'ı query_json içinden okuyoruz:
      query_json: {"type": "...", ..., "actions":[...]}
    """
    q = getattr(rule_obj, "query_json", None)
    spec = _safe_json_loads(q) if isinstance(q, str) else {}
    actions = spec.get("actions") or []
    if isinstance(actions, list):
        return actions
    return []


def run_actions_for_alert(alert_obj, rule_obj, app_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    alert_obj: Alert modeli instance
    rule_obj : AlertRule veya DetectionRule instance
    app_config: Flask app.config

    actions örnek:
    [
      {"type":"email","to":"x@y.com","subject":"...", "body":"..."},
      {"type":"webhook","url":"https://...", "headers":{"X-Token":"abc"}}
    ]
    """
    actions = _extract_actions_from_rule(rule_obj)
    results: List[Dict[str, Any]] = []

    payload = {
        "alert_id": getattr(alert_obj, "id", None),
        "rule_id": getattr(alert_obj, "rule_id", None),
        "title": getattr(alert_obj, "title", None),
        "severity": getattr(alert_obj, "severity", None),
        "status": getattr(alert_obj, "status", None),
        "group_key": getattr(alert_obj, "group_key", None),
        "hit_count": getattr(alert_obj, "hit_count", None),
        "event_count": getattr(alert_obj, "event_count", None),
        "first_seen": (getattr(alert_obj, "first_seen", None).isoformat()
                       if getattr(alert_obj, "first_seen", None) else None),
        "last_seen": (getattr(alert_obj, "last_seen", None).isoformat()
                      if getattr(alert_obj, "last_seen", None) else None),
        "window_from": (getattr(alert_obj, "window_from", None).isoformat()
                        if getattr(alert_obj, "window_from", None) else None),
        "window_to": (getattr(alert_obj, "window_to", None).isoformat()
                      if getattr(alert_obj, "window_to", None) else None),
        "rule_name": getattr(rule_obj, "name", None),
    }

    for a in actions:
        if not isinstance(a, dict):
            continue

        typ = (a.get("type") or "").strip().lower()
        try:
            if typ == "webhook":
                url = a.get("url")
                if not url:
                    results.append({"type": "webhook", "ok": False, "error": "url required"})
                    continue
                headers = a.get("headers") if isinstance(a.get("headers"), dict) else None
                timeout = int(a.get("timeout", 8))
                res = send_webhook(url, payload, headers=headers, timeout=timeout)
                results.append({"type": "webhook", "ok": True, "result": res})

            elif typ == "email":
                to_email = a.get("to")
                if not to_email:
                    results.append({"type": "email", "ok": False, "error": "to required"})
                    continue

                subject = a.get("subject") or f"[SIEM] {payload.get('title') or 'Alert'}"
                body = a.get("body") or (
                    f"Alert: {payload.get('title')}\n"
                    f"Severity: {payload.get('severity')}\n"
                    f"Rule: {payload.get('rule_name')}\n"
                    f"AlertID: {payload.get('alert_id')}\n"
                    f"Group: {payload.get('group_key')}\n"
                    f"FirstSeen: {payload.get('first_seen')}\n"
                    f"LastSeen: {payload.get('last_seen')}\n"
                )

                smtp_host = app_config.get("SMTP_HOST", "")
                smtp_port = int(app_config.get("SMTP_PORT", 587))
                smtp_user = app_config.get("SMTP_USER", "")
                smtp_pass = app_config.get("SMTP_PASS", "")
                smtp_tls = bool(app_config.get("SMTP_TLS", True))

                if not smtp_host:
                    results.append({"type": "email", "ok": False, "error": "SMTP_HOST not set"})
                    continue

                res = send_email_smtp(
                    host=smtp_host,
                    port=smtp_port,
                    username=smtp_user,
                    password=smtp_pass,
                    to_email=to_email,
                    subject=subject,
                    body=body,
                    use_tls=smtp_tls
                )
                results.append({"type": "email", "ok": True, "result": res})

            else:
                results.append({"type": typ or "unknown", "ok": False, "error": "unknown action type"})

        except Exception as e:
            results.append({"type": typ or "unknown", "ok": False, "error": str(e)})

    return results
