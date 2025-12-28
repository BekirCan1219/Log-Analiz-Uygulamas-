# app/services/alert_engine.py
import json
from datetime import datetime, timedelta

from sqlalchemy import func

from ..extensions import db
from ..models.log_event import LogEvent
from ..models.alert_rule import AlertRule
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


def _normalize_spec_from_rule(ar: AlertRule) -> dict:
    """
    1) spec_json varsa onu kullan
    2) yoksa (geriye uyum) query_json + rule_type/type + threshold/group_by/window_minutes'dan spec üret
    """
    spec = _safe_json_loads(getattr(ar, "spec_json", None), default={})

    # spec_json boşsa: query_json filtre olsun
    if not isinstance(spec, dict) or not spec:
        filters = _safe_json_loads(getattr(ar, "query_json", None), default={})
        if not isinstance(filters, dict):
            filters = {}

        # rule_type / type kolonu varsa ordan al
        rtype = getattr(ar, "rule_type", None)
        if rtype is None:
            # bazı modellerde kolon adı "type" olabilir
            rtype = getattr(ar, "type", None)

        spec = {
            "type": rtype or "count_threshold",
            "threshold": int(getattr(ar, "threshold", 1) or 1),
            "group_by": getattr(ar, "group_by", "service") or "service",
            "filters": filters,
        }

    # defaults
    if "threshold" not in spec:
        spec["threshold"] = int(getattr(ar, "threshold", 1) or 1)
    if "group_by" not in spec:
        spec["group_by"] = getattr(ar, "group_by", "service") or "service"
    if "filters" not in spec or spec["filters"] is None:
        spec["filters"] = {}

    # per-rule window override
    if "window_minutes" not in spec:
        wm = getattr(ar, "window_minutes", None)
        if wm is not None:
            spec["window_minutes"] = int(wm)

    return spec


class AlertEngine:
    """
    Scheduler tarafından çağrılan motor.

    Kritik: alerts.rule_id FK -> alert_rules.id
    Bu yüzden engine SADECE AlertRule üzerinden çalışır.
    """

    def __init__(self, minutes: int = 5):
        self.minutes = max(1, int(minutes))

    def run_once(self):
        now = _utcnow()
        window_to_global = now
        window_from_global = window_to_global - timedelta(minutes=self.minutes)

        stats = {
            "window_from": window_from_global.isoformat() + "Z",
            "window_to": window_to_global.isoformat() + "Z",
            "rules_checked": 0,
            "rules_skipped": 0,
            "events_scanned": 0,
            "matches_found": 0,
            "alerts_created": 0,
            "errors": 0,
        }

        # Runner UI için faydalı: global window’daki toplam event
        try:
            stats["total_events_in_window"] = (
                db.session.query(func.count(LogEvent.id))
                .filter(LogEvent.ingest_time.between(window_from_global, window_to_global))
                .scalar()
            ) or 0
        except Exception:
            stats["total_events_in_window"] = 0

        rules = db.session.query(AlertRule).filter(AlertRule.enabled == True).all()

        for rule in rules:
            stats["rules_checked"] += 1

            spec = _normalize_spec_from_rule(rule)
            rtype = spec.get("type")
            if not rtype:
                stats["rules_skipped"] += 1
                continue

            # per-rule window
            wm = spec.get("window_minutes")
            try:
                wm = int(wm) if wm is not None else int(getattr(rule, "window_minutes", self.minutes) or self.minutes)
            except Exception:
                wm = self.minutes

            window_to = now
            window_from = window_to - timedelta(minutes=max(1, wm))

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
    # Cooldown helper
    # -----------------------
    def _cooldown_hit(self, rule_id: int, group_key: str | None, now, cooldown_minutes: int):
        cooldown = timedelta(minutes=_cooldown_minutes_value(cooldown_minutes))
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

        return q.limit(1).count() > 0

    def _dedup_or_create(
        self,
        rule: AlertRule,
        group_key: str | None,
        title: str,
        window_from: datetime,
        window_to: datetime,
        details: dict | None = None,
        representative_event_id: int | None = None,
        event_count: int = 1,
    ):
        now = _utcnow()
        cooldown = timedelta(minutes=_cooldown_minutes_value(getattr(rule, "cooldown_minutes", None)))
        since = now - cooldown

        # ✅ KRİTİK: Alert.rule_id = AlertRule.id olmalı
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
            existing.event_count = int(event_count or 1)
            existing.last_seen = now
            existing.window_from = window_from
            existing.window_to = window_to

            if details is not None:
                existing.details_json = json.dumps(details, ensure_ascii=False)

            if representative_event_id:
                existing.event_id = representative_event_id

            return existing, False

        a = Alert(
            rule_id=rule.id,  # ✅ FK doğru
            status="open",
            severity=getattr(rule, "severity", "medium"),
            title=title,
            group_key=group_key,
            details_json=json.dumps(details, ensure_ascii=False) if details else None,
            window_from=window_from,
            window_to=window_to,
            first_seen=now,
            last_seen=now,
            hit_count=1,
            event_count=int(event_count or 1),
            event_id=representative_event_id,
        )

        db.session.add(a)
        return a, True

    # -----------------------
    # Rule evaluation
    # -----------------------
    def _eval_rule(self, rule: AlertRule, spec: dict, window_from: datetime, window_to: datetime):
        stats = {"events_scanned": 0, "matches_found": 0, "alerts_created": 0}

        rtype = spec["type"]
        group_by = spec.get("group_by")
        threshold = int(spec.get("threshold", 1))
        filters = spec.get("filters", {}) or {}

        if rtype == "count_threshold":
            if not group_by:
                return stats

            col = getattr(LogEvent, group_by, None)
            if col is None:
                return stats

            agg = (
                db.session.query(col.label("k"), func.count(LogEvent.id).label("c"))
                .filter(LogEvent.ingest_time.between(window_from, window_to))
            )
            agg = _apply_common_filters(agg, filters)
            agg = agg.group_by(col).having(func.count(LogEvent.id) >= threshold)

            for k, c in agg.all():
                stats["matches_found"] += 1

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

                if self._cooldown_hit(rule.id, gk, _utcnow(), getattr(rule, "cooldown_minutes", None)):
                    continue

                _, created = self._dedup_or_create(
                    rule,
                    gk,
                    title,
                    window_from,
                    window_to,
                    details,
                    rep[0] if rep else None,
                    event_count=int(c),
                )
                if created:
                    stats["alerts_created"] += 1

            return stats

        elif rtype == "status_code_spike":
            if not group_by:
                return stats

            min_s = int(spec.get("status_min", 500))
            max_s = int(spec.get("status_max", 599))

            col_g = getattr(LogEvent, group_by, None)
            if col_g is None:
                return stats

            agg = (
                db.session.query(col_g.label("k"), func.count(LogEvent.id).label("c"))
                .filter(LogEvent.ingest_time.between(window_from, window_to))
                .filter(LogEvent.http_status >= min_s, LogEvent.http_status <= max_s)
            )
            agg = _apply_common_filters(agg, filters)
            agg = agg.group_by(col_g).having(func.count(LogEvent.id) >= threshold)

            for k, c in agg.all():
                stats["matches_found"] += 1

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

                if self._cooldown_hit(rule.id, gk, _utcnow(), getattr(rule, "cooldown_minutes", None)):
                    continue

                _, created = self._dedup_or_create(
                    rule,
                    gk,
                    title,
                    window_from,
                    window_to,
                    details,
                    rep[0] if rep else None,
                    event_count=int(c),
                )
                if created:
                    stats["alerts_created"] += 1

            return stats

        elif rtype == "pattern_match":
            field = spec.get("field", "message")

            # Yeni standard: patterns[] + mode(any/all)
            patterns = spec.get("patterns")
            mode = spec.get("mode", "any")

            # Geriye uyum: pattern/contains tek string
            if not patterns:
                single = spec.get("pattern") or spec.get("contains")
                if single:
                    patterns = [single]

            if not patterns:
                return stats

            base = db.session.query(LogEvent).filter(LogEvent.ingest_time.between(window_from, window_to))
            base = _apply_common_filters(base, filters)

            col = getattr(LogEvent, field, None)
            if col is None:
                return stats

            # any/all
            if mode == "all":
                for p in patterns:
                    base = base.filter(col.ilike(f"%{p}%"))
            else:
                # any
                ors = []
                for p in patterns:
                    ors.append(col.ilike(f"%{p}%"))
                if ors:
                    from sqlalchemy import or_
                    base = base.filter(or_(*ors))

            matched_count = base.count()
            stats["events_scanned"] += matched_count
            if matched_count <= 0:
                return stats

            # group yoksa tek alert
            if not group_by or group_by == "none":
                stats["matches_found"] += 1

                rep = base.order_by(LogEvent.ingest_time.desc()).with_entities(LogEvent.id).first()

                pat_sig = "|".join(patterns)
                gk = f"{rule.id}:{rtype}:{field}~{pat_sig}"

                title = f"{rule.name} (match: {pat_sig}) count={matched_count}"
                details = {
                    "type": "pattern_match",
                    "field": field,
                    "patterns": patterns,
                    "mode": mode,
                    "count": int(matched_count),
                }

                if self._cooldown_hit(rule.id, gk, _utcnow(), getattr(rule, "cooldown_minutes", None)):
                    return stats

                _, created = self._dedup_or_create(
                    rule,
                    gk,
                    title,
                    window_from,
                    window_to,
                    details,
                    rep[0] if rep else None,
                    event_count=int(matched_count),  # ✅ BUG FIX: c yoktu
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

            pat_sig = "|".join(patterns)

            for k, c in agg.all():
                stats["matches_found"] += 1

                gk = f"{rule.id}:{rtype}:{group_by}={k}|{field}~{pat_sig}"
                title = f"{rule.name} ({group_by}={k}) match:{pat_sig} count={int(c)}"
                details = {
                    "type": "pattern_match",
                    "field": field,
                    "patterns": patterns,
                    "mode": mode,
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

                if self._cooldown_hit(rule.id, gk, _utcnow(), getattr(rule, "cooldown_minutes", None)):
                    continue

                _, created = self._dedup_or_create(
                    rule,
                    gk,
                    title,
                    window_from,
                    window_to,
                    details,
                    rep[0] if rep else None,
                    event_count=int(c),
                )
                if created:
                    stats["alerts_created"] += 1

            return stats

        # distinct_threshold vb. eklemek istersen buraya ekle
        return stats
