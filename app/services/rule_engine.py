import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, func

from ..extensions import db
from ..models.log_event import LogEvent
from ..models.detection_rule import DetectionRule
from ..models.alert import Alert


def utcnow() -> datetime:
    # naive UTC (MSSQL/SQLAlchemy ile en sorunsuz)
    return datetime.utcnow()


def safe_json_loads(s: Optional[str], default=None):
    try:
        if not s:
            return default if default is not None else {}
        return json.loads(s)
    except Exception:
        return default if default is not None else {}


def _norm_str(x: Any) -> Optional[str]:
    if x is None:
        return None
    x = str(x).strip()
    return x if x else None


@dataclass
class EngineDebug:
    window_from: datetime
    window_to: datetime
    total_events_in_window: int
    rules_checked: int
    fired_count: int
    notes: List[str]
    per_rule: List[Dict[str, Any]]


def _apply_rule_filters(q, filters: Dict[str, Any]):

    # NOT: filtre anahtarları senin UI’de oluşturduğun rule spec ile uyumlu olmalı.
    # Bu fonksiyon bilinmeyen key’leri sessizce ignore eder.

    if not filters:
        return q

    service = _norm_str(filters.get("service"))
    level = _norm_str(filters.get("level"))
    category = _norm_str(filters.get("category"))
    event_type = _norm_str(filters.get("event_type"))
    src_ip = _norm_str(filters.get("src_ip"))

    if service:
        q = q.filter(LogEvent.service == service)
    if level:
        q = q.filter(LogEvent.level == level)
    if category:
        q = q.filter(LogEvent.category == category)
    if event_type:
        q = q.filter(LogEvent.event_type == event_type)
    if src_ip:
        q = q.filter(LogEvent.src_ip == src_ip)

    # http_status filters
    http_status_in = filters.get("http_status_in")
    http_status_min = filters.get("http_status_min")
    http_status_max = filters.get("http_status_max")

    if http_status_in:
        # list of ints
        try:
            vals = [int(x) for x in http_status_in]
            q = q.filter(LogEvent.http_status.in_(vals))
        except Exception:
            pass

    if http_status_min is not None:
        try:
            q = q.filter(LogEvent.http_status >= int(http_status_min))
        except Exception:
            pass

    if http_status_max is not None:
        try:
            q = q.filter(LogEvent.http_status <= int(http_status_max))
        except Exception:
            pass

    # contains filters
    url_contains = _norm_str(filters.get("url_contains"))
    message_contains = _norm_str(filters.get("message_contains"))

    if url_contains:
        q = q.filter(LogEvent.url.ilike(f"%{url_contains}%"))
    if message_contains:
        q = q.filter(LogEvent.message.ilike(f"%{message_contains}%"))

    # parse_status filter (opsiyonel)
    # parse_status: 1=ok, 0=unparsed gibi
    parse_status = filters.get("parse_status")
    if parse_status is not None:
        try:
            q = q.filter(LogEvent.parse_status == int(parse_status))
        except Exception:
            pass

    return q


def _get_group_expr(group_by: str):
    group_by = (group_by or "").strip().lower()
    if group_by in ("src_ip", "srcip", "ip"):
        return LogEvent.src_ip
    if group_by in ("service",):
        return LogEvent.service
    if group_by in ("url", "path"):
        return LogEvent.url
    if group_by in ("category",):
        return LogEvent.category
    # default: single bucket
    return func.cast(func.literal("all"), db.String(50))


def _rule_title(rule: DetectionRule) -> str:
    # bazı projelerde rule.title var, bazılarında name var
    return getattr(rule, "title", None) or getattr(rule, "name", None) or f"Rule #{rule.id}"


def _rule_severity(rule: DetectionRule) -> str:
    return getattr(rule, "severity", None) or "medium"


def _rule_enabled(rule: DetectionRule) -> bool:
    v = getattr(rule, "enabled", None)
    if v is None:
        return True
    return bool(v)


def run_engine(minutes: int = 30, limit_rules: Optional[int] = None, debug: bool = False) -> Tuple[List[Dict[str, Any]], Optional[EngineDebug]]:
    window_to = utcnow()
    window_from = window_to - timedelta(minutes=max(1, int(minutes)))

    fired: List[Dict[str, Any]] = []
    dbg = EngineDebug(
        window_from=window_from,
        window_to=window_to,
        total_events_in_window=0,
        rules_checked=0,
        fired_count=0,
        notes=[],
        per_rule=[]
    ) if debug else None

    base_q = db.session.query(LogEvent).filter(
        and_(LogEvent.ingest_time >= window_from, LogEvent.ingest_time <= window_to)
    )

    total_events = base_q.count()
    if dbg:
        dbg.total_events_in_window = total_events
        if total_events == 0:
            dbg.notes.append(
                "Pencerede hiç event yok. Muhtemel sebepler: ingest_time eski/NULL, timezone karışık veya engine minutes çok küçük."
            )

    rules_q = db.session.query(DetectionRule).order_by(DetectionRule.id.asc())
    if limit_rules:
        rules_q = rules_q.limit(int(limit_rules))
    rules = rules_q.all()

    if dbg:
        dbg.rules_checked = len(rules)
        if len(rules) == 0:
            dbg.notes.append("Hiç rule yok (rules tablosu boş).")

    for rule in rules:
        if not _rule_enabled(rule):
            if dbg:
                dbg.per_rule.append({
                    "rule_id": rule.id,
                    "title": _rule_title(rule),
                    "skipped": True,
                    "reason": "disabled",
                })
            continue

        # ---- rule spec okuma ----
        # Projede genelde filters_json / query_json / spec_json gibi bir alan olur.
        # Burada en esnek şekilde deniyoruz:
        raw_spec = getattr(rule, "spec_json", None) or getattr(rule, "filters_json", None) or getattr(rule, "query_json", None)
        spec = safe_json_loads(raw_spec, default={})

        filters = spec.get("filters") if isinstance(spec, dict) else {}
        if filters is None:
            filters = spec if isinstance(spec, dict) else {}
        if not isinstance(filters, dict):
            filters = {}

        threshold = spec.get("threshold") if isinstance(spec, dict) else None
        try:
            threshold = int(threshold) if threshold is not None else int(getattr(rule, "threshold", 5) or 5)
        except Exception:
            threshold = 5

        group_by = spec.get("group_by") if isinstance(spec, dict) else None
        group_by = group_by or getattr(rule, "group_by", None) or "src_ip"

        # ---- query ----
        q = base_q
        q = _apply_rule_filters(q, filters)

        # group aggregation
        group_expr = _get_group_expr(str(group_by))
        agg = (
            db.session.query(group_expr.label("group_key"), func.count(LogEvent.id).label("cnt"))
            .select_from(LogEvent)
            .filter(and_(LogEvent.ingest_time >= window_from, LogEvent.ingest_time <= window_to))
        )
        agg = _apply_rule_filters(agg, filters)
        agg = agg.group_by(group_expr).having(func.count(LogEvent.id) >= threshold)

        rows = agg.all()

        if dbg:
            sample_cnt = q.limit(5).count()
            dbg.per_rule.append({
                "rule_id": rule.id,
                "title": _rule_title(rule),
                "filters": filters,
                "threshold": threshold,
                "group_by": group_by,
                "matched_events_count": q.count(),
                "matched_events_sample_count_limit5": sample_cnt,
                "groups_over_threshold": [{"group_key": r.group_key, "count": int(r.cnt)} for r in rows],
            })

        for r in rows:
            group_key = r.group_key if r.group_key is not None else "all"
            hit_count = int(r.cnt)

            # dedupe: aynı rule+group için açık alert varsa güncelle, yoksa oluştur
            existing = (
                db.session.query(Alert)
                .filter(
                    Alert.rule_id == rule.id,
                    Alert.group_key == str(group_key),
                    Alert.status.in_(["open", "ack"])  # kapalıyı yeniden açma
                )
                .order_by(Alert.id.desc())
                .first()
            )

            title = _rule_title(rule)
            severity = _rule_severity(rule)

            details = {
                "rule_id": rule.id,
                "group_by": group_by,
                "group_key": str(group_key),
                "threshold": threshold,
                "hit_count": hit_count,
                "filters": filters,
            }

            if existing:
                # update existing alert
                existing.last_seen = window_to
                existing.window_from = window_from
                existing.window_to = window_to
                existing.hit_count = hit_count
                # DB'de NOT NULL olan event_count gibi kolonlar varsa set edelim:
                if hasattr(existing, "event_count"):
                    existing.event_count = hit_count
                existing.details_json = json.dumps(details, ensure_ascii=False)
                db.session.add(existing)

                fired.append({
                    "rule_id": rule.id,
                    "alert_id": existing.id,
                    "status": existing.status,
                    "action": "updated",
                    "title": title,
                    "severity": severity,
                    "group_key": str(group_key),
                    "hit_count": hit_count,
                })
            else:
                new_alert = Alert(
                    rule_id=rule.id,
                    status="open",
                    severity=severity,
                    title=title,
                    group_key=str(group_key),
                    details_json=json.dumps(details, ensure_ascii=False),
                    window_from=window_from,
                    window_to=window_to,
                    first_seen=window_from,
                    last_seen=window_to,
                    hit_count=hit_count,
                )
                # DB NOT NULL kolonları için emniyet:
                if hasattr(new_alert, "event_count"):
                    new_alert.event_count = hit_count

                db.session.add(new_alert)
                db.session.flush()  # id al

                fired.append({
                    "rule_id": rule.id,
                    "alert_id": new_alert.id,
                    "status": new_alert.status,
                    "action": "created",
                    "title": title,
                    "severity": severity,
                    "group_key": str(group_key),
                    "hit_count": hit_count,
                })

    db.session.commit()

    if dbg:
        dbg.fired_count = len(fired)

    return fired, dbg
