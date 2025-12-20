import json
from datetime import datetime

def normalize(parsed: dict | None, raw: str, source_type: str):
    """
    parsed: parser çıktısı (core+extra)
    raw: ham log
    source_type: nginx/auth/suricata/app
    """
    if not parsed:
        # parse edilemeyen log - minimum alanlarla sakla
        return {
            "event_time": datetime.utcnow(),
            "category": source_type or "unknown",
            "event_type": "unparsed",
            "level": "INFO",
            "message": "Unparsed log",
            "raw_text": raw,
            "extra_json": json.dumps({"note": "parser_failed"}, ensure_ascii=False),
            "parse_status": 2,
        }

    extra = parsed.get("extra", {})
    return {
        "event_time": parsed.get("event_time", datetime.utcnow()),
        "category": parsed.get("category", source_type or "unknown"),
        "event_type": parsed.get("event_type", "event"),
        "level": parsed.get("level", "INFO"),
        "src_ip": parsed.get("src_ip"),
        "dst_ip": parsed.get("dst_ip"),
        "src_port": parsed.get("src_port"),
        "dst_port": parsed.get("dst_port"),
        "http_method": parsed.get("http_method"),
        "http_status": parsed.get("http_status"),
        "url": parsed.get("url"),
        "username": parsed.get("username"),
        "message": parsed.get("message") or raw[:2000],
        "raw_text": raw,
        "extra_json": json.dumps(extra, ensure_ascii=False),
        "parse_status": 0,
    }
