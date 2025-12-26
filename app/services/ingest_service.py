import json
import re
from datetime import datetime

from app.extensions import db
from app.models.log_event import LogEvent

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


class IngestService:
    def _utcnow(self):
        return datetime.utcnow()

    def _safe_json_loads(self, s: str | None):
        if not s:
            return None
        try:
            return json.loads(s)
        except Exception:
            return None

    def _extract_parsed(self, hint: str | None) -> dict | None:
        """
        hint JSON ise:
          {"__parsed__": {...}}
        döndürür, değilse None
        """
        obj = self._safe_json_loads(hint)
        if isinstance(obj, dict) and isinstance(obj.get("__parsed__"), dict):
            return obj["__parsed__"]
        return None

    def _set_if_exists(self, obj, field: str, value):
        if value is None:
            return
        if hasattr(obj, field):
            try:
                setattr(obj, field, value)
            except Exception:
                pass

    def ingest_raw(self, source_name: str, source_type: str, raw: str, hint: str | None = None):
        raw_line = (raw or "").strip()
        now = self._utcnow()

        parsed = self._extract_parsed(hint)

        # -------- defaults --------
        service = "unknown"
        category = "general"
        level = "info"
        event_type = None
        src_ip = None
        http_status = None
        url = None
        message = raw_line if raw_line else "Empty log"
        raw_text = raw_line

        # parse_status SMALLINT mapping (MSSQL):
        # 0 = unparsed, 1 = ok, 2 = raw_ip
        parse_status = 0

        # -------- apply parsed if exists --------
        if parsed:
            service = parsed.get("service") or service
            category = parsed.get("category") or category
            level = parsed.get("level") or level
            event_type = parsed.get("event_type") or event_type
            src_ip = parsed.get("src_ip") or src_ip
            url = parsed.get("url") or url

            hs = parsed.get("http_status")
            try:
                http_status = int(hs) if hs is not None else None
            except Exception:
                http_status = None

            # parsed bir şey yakaladıysa "ok"
            parse_status = 1 if (src_ip or url or http_status or service != "unknown") else 0

        # -------- fallback: parsed yoksa bile ip yakala --------
        if not src_ip and raw_line:
            m = IPV4_RE.search(raw_line)
            if m:
                src_ip = m.group(0)
                # sadece ip yakalandı
                if parse_status == 0:
                    parse_status = 2

        # -------- create safely (no kwargs) --------
        ev = LogEvent()

        # Core fields (varsa set eder)
        self._set_if_exists(ev, "event_time", now)     # sende var
        self._set_if_exists(ev, "ingest_time", now)
        self._set_if_exists(ev, "service", service)
        self._set_if_exists(ev, "category", category)
        self._set_if_exists(ev, "event_type", event_type)
        self._set_if_exists(ev, "level", level)
        self._set_if_exists(ev, "src_ip", src_ip)
        self._set_if_exists(ev, "url", url)
        self._set_if_exists(ev, "http_status", http_status)
        self._set_if_exists(ev, "message", message)
        self._set_if_exists(ev, "raw_text", raw_text)

        # ✅ MSSQL smallint uyumlu
        self._set_if_exists(ev, "parse_status", parse_status)

        # Optional metadata fields (modelde varsa)
        self._set_if_exists(ev, "source_name", source_name)
        self._set_if_exists(ev, "source_type", source_type)

        # Sende insert SQL'inde extra_json var, onu bas
        self._set_if_exists(ev, "extra_json", hint)

        # Common NOT NULL fallbacks (modelde varsa)
        self._set_if_exists(ev, "created_at", now)
        self._set_if_exists(ev, "event_count", 1)

        db.session.add(ev)
        db.session.commit()
        return ev
