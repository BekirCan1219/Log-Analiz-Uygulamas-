# app/services/alert_engine.py
import json
from datetime import datetime, timedelta
from sqlalchemy import func, desc

from ..extensions import db
from ..models.log_event import LogEvent
from ..models.alert_rule import AlertRule
from ..models.alert import Alert


class AlertEngine:
    def run_once(self):
        now = datetime.utcnow()

        rules = AlertRule.query.filter_by(enabled=True).all()
        created = 0

        for rule in rules:
            # Rule query json parse
            try:
                qdef = json.loads(rule.query_json)
            except Exception:
                # query_json bozuksa rule'ü atla
                continue

            window_start = now - timedelta(minutes=rule.window_minutes)

            # ⚠️ KRİTİK: event_time yerine ingest_time kullanıyoruz
            base = db.session.query(LogEvent).filter(LogEvent.ingest_time.between(window_start, now))

            # ---- filtreler (core alanlar) ----
            if qdef.get("service"):
                base = base.filter(LogEvent.service == qdef["service"])
            if qdef.get("level"):
                base = base.filter(LogEvent.level == qdef["level"])
            if qdef.get("category"):
                base = base.filter(LogEvent.category == qdef["category"])
            if qdef.get("event_type"):
                base = base.filter(LogEvent.event_type == qdef["event_type"])
            if qdef.get("http_status") is not None:
                base = base.filter(LogEvent.http_status == int(qdef["http_status"]))
            if qdef.get("src_ip"):
                base = base.filter(LogEvent.src_ip == qdef["src_ip"])

            group_by = (rule.group_by or "none").lower().strip()

            # --- Grouping yoksa toplam say ---
            if group_by == "none":
                count = base.count()
                if count >= rule.threshold:
                    if not self._cooldown_hit(rule.id, "ALL", now, rule.cooldown_minutes):
                        first_seen, last_seen = self._first_last_ingest(base)
                        self._create_alert(rule, "ALL", count, first_seen, last_seen)
                        created += 1
                continue

            # --- group_by kolon seçimi ---
            col = None
            if group_by == "service":
                col = LogEvent.service
            elif group_by == "src_ip":
                col = LogEvent.src_ip
            else:
                # bilinmeyen group_by => none gibi davran
                count = base.count()
                if count >= rule.threshold:
                    if not self._cooldown_hit(rule.id, "ALL", now, rule.cooldown_minutes):
                        first_seen, last_seen = self._first_last_ingest(base)
                        self._create_alert(rule, "ALL", count, first_seen, last_seen)
                        created += 1
                continue

            # ⚠️ KRİTİK: grouped query de ingest_time üzerinden pencereyi hesaplar
            grouped = (
                db.session.query(col.label("k"), func.count(LogEvent.id).label("c"))
                .filter(LogEvent.ingest_time.between(window_start, now))
            )

            # aynı filtreleri grouped query'e de uygula
            if qdef.get("service"):
                grouped = grouped.filter(LogEvent.service == qdef["service"])
            if qdef.get("level"):
                grouped = grouped.filter(LogEvent.level == qdef["level"])
            if qdef.get("category"):
                grouped = grouped.filter(LogEvent.category == qdef["category"])
            if qdef.get("event_type"):
                grouped = grouped.filter(LogEvent.event_type == qdef["event_type"])
            if qdef.get("http_status") is not None:
                grouped = grouped.filter(LogEvent.http_status == int(qdef["http_status"]))
            if qdef.get("src_ip"):
                grouped = grouped.filter(LogEvent.src_ip == qdef["src_ip"])

            grouped = (
                grouped.group_by(col)
                .order_by(desc("c"))
                .limit(50)
                .all()
            )

            for k, c in grouped:
                if not k:
                    continue

                c = int(c)
                if c >= rule.threshold:
                    group_key = str(k)

                    if not self._cooldown_hit(rule.id, group_key, now, rule.cooldown_minutes):
                        # Bu grubun first/last ingest_time'ı
                        subset = base.filter(col == k)
                        first_seen, last_seen = self._first_last_ingest(subset)

                        self._create_alert(rule, group_key, c, first_seen, last_seen)
                        created += 1

        db.session.commit()
        return created

    def _cooldown_hit(self, rule_id: int, group_key: str, now: datetime, cooldown_minutes: int) -> bool:
        since = now - timedelta(minutes=cooldown_minutes)
        recent = (
            Alert.query
            .filter(Alert.rule_id == rule_id)
            .filter(Alert.group_key == group_key)
            .filter(Alert.alert_time >= since)
            .first()
        )
        return recent is not None

    def _first_last_ingest(self, query):
        # ⚠️ KRİTİK: first/last da ingest_time'a göre
        first_seen = query.with_entities(func.min(LogEvent.ingest_time)).scalar()
        last_seen = query.with_entities(func.max(LogEvent.ingest_time)).scalar()
        return first_seen, last_seen

    def _create_alert(self, rule: AlertRule, group_key: str, count: int, first_seen, last_seen):
        title = f"[{rule.severity.upper()}] {rule.name}"
        desc = (
            f"Window={rule.window_minutes}m Threshold={rule.threshold} "
            f"Group={rule.group_by} Key={group_key} Count={count}"
        )

        al = Alert(
            rule_id=rule.id,
            severity=rule.severity,
            title=title,
            description=desc,
            group_key=group_key,
            event_count=count,
            first_seen=first_seen,
            last_seen=last_seen,
            status="open"
        )
        db.session.add(al)
