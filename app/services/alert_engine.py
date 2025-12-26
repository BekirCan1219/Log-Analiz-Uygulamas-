# app/services/alert_engine.py
import json
from datetime import datetime, timedelta

from sqlalchemy import func

from ..extensions import db
from ..models.log_event import LogEvent
from ..models.detection_rule import DetectionRule
from ..models.alert import Alert


def _utcnow():
    return datetime.utcnow()


def _safe_json_loads(s: str, default=None):
    try:
        return json.loads(s) if s else (default if default is not None else {})
    except Exception:
        return default if default is not None else {}


def _apply_common_filters(q, filters: dict):
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


def _cooldown_minutes_value(v):
    """
    v None ise default 15, 0 ise gerçekten 0.
    (Önceki 'v or 15' bug'ını çözer.)
    """
    return 15 if v is None else int(v)


class AlertEngine:
    """
    Scheduler tarafından çağrılan motor.
    - Cooldown / dedup için Alert.last_seen kullanıyoruz.
    - İsteğe bağlı 'alert_time' alanı yoksa bile patlamamalı (fallback var).
    """

    def __init__(self, minutes: int = 5):
        self.minutes = max(1, int(minutes))

    def run_once(self):
        window_to = _utcnow()
        window_from = window_to - timedelta(minutes=self.minutes)

        stats = {
            "window_from": window_from.isoformat() + "Z",
            "window_to": window_to.isoformat() + "Z",
            "rules_checked": 0,
            "rules_skipped": 0,
            "events_scanned": 0,
            "matches_found": 0,
            "alerts_created": 0,
            "errors": 0,
        }

        rules = db.session.query(DetectionRule).filter(DetectionRule.enabled == True).all()
        for rule in rules:
            stats["rules_checked"] += 1

            spec = _safe_json_loads(rule.query_json, {})
            rtype = spec.get("type")
            if not rtype:
                stats["rules_skipped"] += 1
                continue

            try:
                r = self._eval_rule(rule, spec, window_from, window_to) or {}
                stats["events_scanned"] += int(r.get("events_scanned", 0))
                stats["matches_found"] += int(r.get("matches_found", 0))
                stats["alerts_created"] += int(r.get("alerts_created", 0))
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                stats["errors"] += 1
                try:
                    import traceback
                    print("AlertEngine.run_once rule error:", rule.id, rule.name, str(e))
                    print(traceback.format_exc())
                except Exception:
                    pass

        return stats

    # -----------------------
    # Cooldown helper (FIX)
    # -----------------------
    def _cooldown_hit(self, rule_id: int, group_key: str | None, now, cooldown_minutes: int):
        cooldown = timedelta(minutes=int(cooldown_minutes or 15))
        since = now - cooldown

        q = db.session.query(Alert.id).filter(Alert.rule_id == rule_id)

        if group_key is None:
            q = q.filter(Alert.group_key.is_(None))
        else:
            q = q.filter(Alert.group_key == group_key)

        q = q.filter(Alert.status.in_(["open", "ack"]))

        # alert_time alanı yoksa last_seen'e düş
        time_col = getattr(Alert, "alert_time", None) or getattr(Alert, "last_seen") or getattr(Alert, "created_at")
        q = q.filter(time_col >= since)

        # ✅ MSSQL-safe: EXISTS yerine COUNT
        return q.limit(1).count() > 0

    def _dedup_or_create(
            self,
            rule: DetectionRule,
            group_key: str | None,
            title: str,
            window_from: datetime,
            window_to: datetime,
            details: dict | None = None,
            representative_event_id: int | None = None,
            event_count: int = 1,  # ✅ EKLENDİ
    ):
        now = _utcnow()
        cooldown = timedelta(minutes=int(rule.cooldown_minutes or 15))
        since = now - cooldown

        q = db.session.query(Alert).filter(Alert.rule_id == rule.id)

        if group_key is None:
            q = q.filter(Alert.group_key.is_(None))
        else:
            q = q.filter(Alert.group_key == group_key)

        q = q.filter(Alert.status.in_(["open", "ack"]))
        q = q.filter(Alert.last_seen >= since)

        existing = q.order_by(Alert.last_seen.desc()).first()

        if existing:
            existing.hit_count = (existing.hit_count or 1) + 1
            existing.event_count = int(event_count or 1)  # ✅ MSSQL NULL FIX
            existing.last_seen = now
            existing.window_from = window_from
            existing.window_to = window_to

            if details is not None:
                existing.details_json = json.dumps(details, ensure_ascii=False)

            if representative_event_id:
                existing.event_id = representative_event_id

            return existing, False

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
            event_count=int(event_count or 1),  # ✅ MSSQL NULL FIX
            event_id=representative_event_id,
        )

        db.session.add(a)
        return a, True

    # -----------------------
    # Rule evaluation
    # -----------------------
    def _eval_rule(self, rule: DetectionRule, spec: dict, window_from: datetime, window_to: datetime):
        stats = {"events_scanned": 0, "matches_found": 0, "alerts_created": 0}

        rtype = spec["type"]
        group_by = spec.get("group_by")
        threshold = int(spec.get("threshold", 1))
        filters = spec.get("filters", {}) or {}

        if rtype == "count_threshold":
            if not group_by:
                return stats

            col = getattr(LogEvent, group_by)
            agg = (
                db.session.query(col.label("k"), func.count(LogEvent.id).label("c"))
                .filter(LogEvent.ingest_time.between(window_from, window_to))
            )
            agg = _apply_common_filters(agg, filters)
            agg = agg.group_by(col).having(func.count(LogEvent.id) >= threshold)

            for k, c in agg.all():
                stats["matches_found"] += 1

                # ✅ STANDARD group_key (dedup garanti)
                gk = f"{rule.id}:{rtype}:{group_by}={k}"
                title = f"{rule.name} ({group_by}={k}) count={c}"
                details = {"count": int(c), "group_by": group_by, "group_value": k}

                rep = (
                    db.session.query(LogEvent.id)
                    .filter(LogEvent.ingest_time.between(window_from, window_to))
                    .filter(col == k)
                    .order_by(LogEvent.ingest_time.desc())
                    .first()
                )

                if self._cooldown_hit(rule.id, gk, _utcnow(), rule.cooldown_minutes):
                    continue

                _, created = (self._dedup_or_create
                    (
                                rule,
                                gk,
                                title,
                                window_from,
                                window_to,
                                details,
                                rep[0] if rep else None,
                                event_count=int(c)
                    )
                )
                if created:
                    stats["alerts_created"] += 1

            stats["events_scanned"] += stats["matches_found"]
            return stats

        elif rtype == "status_code_spike":
            if not group_by:
                return stats

            min_s = int(spec.get("status_min", 500))
            max_s = int(spec.get("status_max", 599))

            col_g = getattr(LogEvent, group_by)
            agg = (
                db.session.query(col_g.label("k"), func.count(LogEvent.id).label("c"))
                .filter(LogEvent.ingest_time.between(window_from, window_to))
                .filter(LogEvent.http_status >= min_s, LogEvent.http_status <= max_s)
            )
            agg = _apply_common_filters(agg, filters)
            agg = agg.group_by(col_g).having(func.count(LogEvent.id) >= threshold)

            for k, c in agg.all():
                stats["matches_found"] += 1

                # ✅ STANDARD group_key (dedup garanti)
                gk = f"{rule.id}:{rtype}:{group_by}={k}:{min_s}-{max_s}"
                title = f"{rule.name} ({group_by}={k}) status[{min_s}-{max_s}] count={c}"
                details = {
                    "count": int(c),
                    "status_min": min_s,
                    "status_max": max_s,
                    "group_by": group_by,
                    "group_value": k,
                }

                rep = (
                    db.session.query(LogEvent.id)
                    .filter(LogEvent.ingest_time.between(window_from, window_to))
                    .filter(col_g == k)
                    .filter(LogEvent.http_status >= min_s, LogEvent.http_status <= max_s)
                    .order_by(LogEvent.ingest_time.desc())
                    .first()
                )

                if self._cooldown_hit(rule.id, gk, _utcnow(), rule.cooldown_minutes):
                    continue

                _, created = self._dedup_or_create(
                    rule,
                    gk,
                    title,
                    window_from,
                    window_to,
                    details,
                    rep[0] if rep else None,
                )
                if created:
                    stats["alerts_created"] += 1

            stats["events_scanned"] += stats["matches_found"]
            return stats

        elif rtype == "pattern_match":
            field = spec.get("field", "message")
            pattern = spec.get("pattern") or spec.get("contains")
            if not pattern:
                return stats

            base = db.session.query(LogEvent).filter(LogEvent.ingest_time.between(window_from, window_to))
            base = _apply_common_filters(base, filters)

            col = getattr(LogEvent, field, None)
            if col is None:
                return stats

            like = f"%{pattern}%"
            base = base.filter(col.ilike(like))

            matched_count = base.count()
            stats["events_scanned"] += matched_count
            if matched_count <= 0:
                return stats

            if not group_by:
                stats["matches_found"] += 1

                rep = base.order_by(LogEvent.ingest_time.desc()).with_entities(LogEvent.id).first()

                # ✅ STANDARD group_key (dedup garanti)
                gk = f"{rule.id}:{rtype}:{field}~{pattern}"

                title = f"{rule.name} (match: {pattern}) count={matched_count}"
                details = {
                    "type": "pattern_match",
                    "field": field,
                    "pattern": pattern,
                    "count": matched_count,
                }

                if self._cooldown_hit(rule.id, gk, _utcnow(), rule.cooldown_minutes):
                    return stats

                _, created = self._dedup_or_create(
                    rule,
                    gk,
                    title,
                    window_from,
                    window_to,
                    details,
                    rep[0] if rep else None,
                    event_count=int(c)
                )
                if created:
                    stats["alerts_created"] += 1
                return stats

            col_g = getattr(LogEvent, group_by, None)
            if col_g is None:
                return stats

            agg = (
                base.with_entities(col_g.label("k"), func.count(LogEvent.id).label("c"))
                .group_by(col_g)
                .having(func.count(LogEvent.id) >= threshold)
            )

            for k, c in agg.all():
                stats["matches_found"] += 1

                # ✅ STANDARD group_key (dedup garanti)
                gk = f"{rule.id}:{rtype}:{group_by}={k}|{field}~{pattern}"

                title = f"{rule.name} ({group_by}={k}) match:{pattern} count={int(c)}"
                details = {
                    "type": "pattern_match",
                    "field": field,
                    "pattern": pattern,
                    "group_by": group_by,
                    "group_value": k,
                    "count": int(c),
                }

                rep = (
                    base.filter(col_g == k)
                    .order_by(LogEvent.ingest_time.desc())
                    .with_entities(LogEvent.id)
                    .first()
                )

                if self._cooldown_hit(rule.id, gk, _utcnow(), rule.cooldown_minutes):
                    continue

                _, created = self._dedup_or_create(
                    rule,
                    gk,
                    title,
                    window_from,
                    window_to,
                    details,
                    rep[0] if rep else None,
                    event_count=int(c)
                )
                if created:
                    stats["alerts_created"] += 1

            return stats

        return stats
