import json
import re
from datetime import datetime

NGINX_ACCESS_RE = re.compile(
    r'(?P<src_ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)'
)

def parse_nginx_access(raw: str):
    m = NGINX_ACCESS_RE.search(raw)
    if not m:
        return None

    # NGINX time örn: 10/Oct/2000:13:55:36 +0000
    ts_str = m.group("ts")
    try:
        event_time = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except Exception:
        event_time = datetime.utcnow()

    return {
        "event_time": event_time,
        "category": "web",
        "event_type": "http_request",
        "level": "ERROR" if int(m.group("status")) >= 500 else "INFO",
        "src_ip": m.group("src_ip"),
        "http_method": m.group("method"),
        "url": m.group("url"),
        "http_status": int(m.group("status")),
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

    # Suricata eve.json genelde 'timestamp' taşır
    event_time = datetime.utcnow()
    if "timestamp" in obj:
        # çok format olabilir, basit yaklaşım:
        # 2020-01-01T00:00:00.000000+0000 gibi
        ts = obj["timestamp"]
        try:
            # en güvenlisi: kırpıp parse denemesi
            event_time = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            event_time = datetime.utcnow()

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
    # Çok farklı format var. Basit bir “failed password” yakalayıcı.
    # Örn: "Failed password for invalid user root from 1.2.3.4 port 12345 ssh2"
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
    if hint == "nginx_access":
        return parse_nginx_access(raw)
    if hint == "suricata_eve":
        return parse_suricata_eve(raw)
    if hint == "linux_auth":
        return parse_linux_auth(raw)
    return None
