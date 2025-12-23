import json
from datetime import datetime

def normalize(parsed: dict | None, raw: str, source_type: str):
    """
    Tek şema:
      service, level, category, event_type, event_time,
      src_ip, dst_ip, src_port, dst_port,
      http_method, url, http_status,
      username, message,
      extra_json, raw_text, parse_status
    parse_status:
      1 = parsed
      2 = parser_failed/unparsed
    """
    now = datetime.utcnow()

    if not parsed:
        return {
            "service": source_type,
            "level": "INFO",
            "category": source_type,
            "event_type": "unparsed",
            "event_time": now,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "http_method": None,
            "url": None,
            "http_status": None,
            "username": None,
            "message": "Unparsed log",
            "extra_json": json.dumps({"note": "parser_failed"}, ensure_ascii=False),
            "raw_text": raw,
            "parse_status": 2
        }

    def _int_or_none(v):
        if v is None:
            return None
        try:
            return int(v)
        except Exception:
            return None

    # event_time normalize
    event_time = parsed.get("event_time") or now
    if not isinstance(event_time, datetime):
        event_time = now

    extra = parsed.get("extra") if isinstance(parsed.get("extra"), dict) else {}
    extra_json = json.dumps(extra, ensure_ascii=False)

    # service: parsed varsa parsed.service öncelikli
    service = parsed.get("service") or source_type

    return {
        "service": service,
        "level": (parsed.get("level") or "INFO"),
        "category": (parsed.get("category") or source_type),
        "event_type": (parsed.get("event_type") or "event"),
        "event_time": event_time,

        "src_ip": parsed.get("src_ip"),
        "dst_ip": parsed.get("dst_ip"),
        "src_port": _int_or_none(parsed.get("src_port")),
        "dst_port": _int_or_none(parsed.get("dst_port")),

        "http_method": parsed.get("http_method"),
        "url": parsed.get("url"),
        "http_status": _int_or_none(parsed.get("http_status")),

        "username": parsed.get("username"),
        "message": parsed.get("message") or "",

        "extra_json": extra_json,
        "raw_text": raw,
        "parse_status": 1
    }
