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
        DESTEKLEDİĞİM FORMATLAR:

        1) Eski:
           {"__parsed__": {...}}

        2) Yeni controller patch:
           {"parsed": {...}}  veya {"mode": "...", "parsed": {...}}

        3) Direkt dict (bazı yerlerde yanlışlıkla hint dict gelebilir):
           {"__parsed__": {...}} veya {"parsed": {...}}
        """
        if not hint:
            return None

        obj = hint
        if isinstance(hint, str):
            obj = self._safe_json_loads(hint)

        if isinstance(obj, dict):
            if isinstance(obj.get("__parsed__"), dict):
                return obj["__parsed__"]
            if isinstance(obj.get("parsed"), dict):
                return obj["parsed"]

        return None

    def _try_parse_json_line(self, raw_line: str) -> dict | None:
        """
        raw satır komple JSON ise dict döndürür.
        Örn: {"service":"nginx","http_status":500,...}
        """
        if not raw_line:
            return None
        s = raw_line.strip()
        if not (s.startswith("{") and s.endswith("}")):
            return None
        try:
            obj = json.loads(s)
            return obj if isinstance(obj, dict) else None
        except Exception:
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

        # 1) Önce raw satır JSON mu? (senin upload’larda böyle gelmiş)
        raw_obj = self._try_parse_json_line(raw_line)

        # 2) Hint içinden parsed çıkar (eski/yeni format destekli)
        parsed = self._extract_parsed(hint)

        # -------- defaults --------
        service = "unknown"
        category = "general"
        level = "info"
        event_type = None
        src_ip = None
        http_status = None
        url = None

        # message/raw_text
        message = raw_line if raw_line else "Empty log"
        raw_text = raw_line

        # parse_status SMALLINT mapping (MSSQL):
        # 0 = unparsed, 1 = ok, 2 = raw_ip
        parse_status = 0

        # -------- apply RAW JSON (en güçlü kaynak) --------
        # Eğer raw komple JSON ise, kolonlara buradan bas
        if raw_obj:
            service = raw_obj.get("service") or service
            category = raw_obj.get("category") or category
            level = raw_obj.get("level") or level
            event_type = raw_obj.get("event_type") or event_type
            src_ip = raw_obj.get("src_ip") or src_ip
            url = raw_obj.get("url") or url

            hs = raw_obj.get("http_status")
            try:
                http_status = int(hs) if hs is not None else None
            except Exception:
                http_status = None

            # message alanı JSON içindeki message olsun
            if raw_obj.get("message"):
                message = str(raw_obj.get("message"))
            # raw_text alanı JSON içindeki raw_text olsun
            if raw_obj.get("raw_text"):
                raw_text = str(raw_obj.get("raw_text"))

            parse_status = 1

        # -------- apply parsed if exists (raw JSON yoksa veya eksikse tamamla) --------
        if parsed and not raw_obj:
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

            parse_status = 1 if (src_ip or url or http_status or service != "unknown") else 0

        # -------- fallback: parsed yoksa bile ip yakala --------
        if not src_ip and raw_text:
            m = IPV4_RE.search(raw_text)
            if m:
                src_ip = m.group(0)
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

        # extra_json: hint’i sakla (debug için)
        self._set_if_exists(ev, "extra_json", hint)

        # Common NOT NULL fallbacks (modelde varsa)
        self._set_if_exists(ev, "created_at", now)
        self._set_if_exists(ev, "event_count", 1)

        db.session.add(ev)
        db.session.commit()
        return ev
