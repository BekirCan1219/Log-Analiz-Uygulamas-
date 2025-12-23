import json
import re
from datetime import datetime

NGINX_ACCESS_RE = re.compile(
    r'(?P<src_ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)'
)

def _try_parse_iso_datetime(v):
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    if isinstance(v, (int, float)):
        # epoch saniye vs. olabilir (opsiyonel)
        try:
            return datetime.utcfromtimestamp(v)
        except Exception:
            return None
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            return None
    return None


def parse_json_auto(raw: str):
    """
    JSON line gönderen client'lar için fallback parser.
    Senin testinde raw_text içine gömülen JSON'lar burada yakalanacak.
    """
    s = (raw or "").strip()
    if not s.startswith("{"):
        return None
    try:
        obj = json.loads(s)
    except Exception:
        return None

    if not isinstance(obj, dict):
        return None

    # event_time alanı farklı isimlerle gelebilir
    event_time = (
        _try_parse_iso_datetime(obj.get("event_time")) or
        _try_parse_iso_datetime(obj.get("@timestamp")) or
        _try_parse_iso_datetime(obj.get("timestamp")) or
        datetime.utcnow()
    )

    extra = obj.get("extra_json") if isinstance(obj.get("extra_json"), dict) else obj.get("extra")
    if extra is None:
        extra = {}

    # bazı client'lar extra_json'u string yollayabilir
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {"_raw_extra": extra}

    return {
        "event_time": event_time,
        "service": obj.get("service"),
        "category": obj.get("category"),
        "event_type": obj.get("event_type"),
        "level": obj.get("level"),
        "src_ip": obj.get("src_ip"),
        "dst_ip": obj.get("dst_ip"),
        "src_port": obj.get("src_port"),
        "dst_port": obj.get("dst_port"),
        "http_method": obj.get("http_method"),
        "url": obj.get("url"),
        "http_status": obj.get("http_status"),
        "username": obj.get("username") or (extra.get("username") if isinstance(extra, dict) else None),
        "message": obj.get("message"),
        "extra": extra
    }


def parse_nginx_access(raw: str):
    m = NGINX_ACCESS_RE.search(raw)
    if not m:
        return None

    ts_str = m.group("ts")
    try:
        event_time = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except Exception:
        event_time = datetime.utcnow()

    status = int(m.group("status"))

    return {
        "event_time": event_time,
        "category": "web",
        "event_type": "http_request",
        "level": "ERROR" if status >= 500 else "INFO",
        "src_ip": m.group("src_ip"),
        "http_method": m.group("method"),
        "url": m.group("url"),
        "http_status": status,
        "extra": {
            "bytes": int(m.group("size")),
            "parser": "nginx_access_v1"
        }
    }


def parse_suricata_eve(raw: str):
    try:
        obj = json.loads(raw)
    except Exception:
        return None

    event_time = datetime.utcnow()
    if "timestamp" in obj:
        ts = obj["timestamp"]
        t = _try_parse_iso_datetime(ts)
        if t:
            event_time = t

    return {
        "event_time": event_time,
        "category": "ids",
        "event_type": obj.get("event_type", "suricata_event"),
        "level": "WARN",
        "src_ip": (obj.get("src_ip") or obj.get("source", {}).get("ip")),
        "dst_ip": (obj.get("dest_ip") or obj.get("destination", {}).get("ip")),
        "src_port": obj.get("src_port"),
        "dst_port": obj.get("dest_port"),
        "message": obj.get("alert", {}).get("signature") if isinstance(obj.get("alert"), dict) else None,
        "extra": obj
    }


def parse_linux_auth(raw: str):
    m = re.search(r"Failed password.* from (?P<src_ip>\d+\.\d+\.\d+\.\d+)", raw)
    if not m:
        return None

    return {
        "event_time": datetime.utcnow(),
        "category": "auth",
        "event_type": "login_failed",
        "level": "WARN",
        "src_ip": m.group("src_ip"),
        "message": "SSH login failed",
        "extra": {"parser": "linux_auth_v1"}
    }


def parse_by_hint(raw: str, hint: str | None):
    # 1) explicit hint
    if hint == "nginx_access":
        return parse_nginx_access(raw)
    if hint == "suricata_eve":
        return parse_suricata_eve(raw)
    if hint == "linux_auth":
        return parse_linux_auth(raw)

    # 2) AUTO fallback: JSON line ise parse et
    auto = parse_json_auto(raw)
    if auto:
        return auto

    return None
