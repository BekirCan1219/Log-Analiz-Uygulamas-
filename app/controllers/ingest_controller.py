from flask import Blueprint, request, jsonify, render_template, current_app
from pydantic import ValidationError
import json
import re
from datetime import datetime

from app.schemas.ingest_schema import IngestEventIn
from app.services.ingest_service import IngestService

# rollback için (MSSQL/SQLAlchemy)
from app.extensions import db

ingest_bp = Blueprint("ingest", __name__, url_prefix="/api/ingest")
svc = IngestService()

# -----------------------------
# Best-effort parser (controller-side)
# -----------------------------
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
NGINX_ACCESS_RE = re.compile(
    r"\"(?P<meth>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<url>/\S*)\s+HTTP/(?P<ver>[0-9.]+)\"\s+(?P<status>\d{3})"
)
SSHD_FROM_RE = re.compile(r"\bfrom\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)


def _utcnow():
    return datetime.utcnow()


def _utcnow_iso():
    return _utcnow().isoformat() + "Z"


def _safe_int(x):
    try:
        return int(x)
    except Exception:
        return None


def _try_parse_json_line(line: str):
    """
    line komple JSON ise dict döndürür, değilse None.
    Senin yeni uploadlarında message içine JSON gömülmüş geliyordu:
    {"service":"nginx","http_status":500,...}
    Bu fonksiyon onu yakalar.
    """
    if not line or not isinstance(line, str):
        return None
    s = line.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return None
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _guess_parsed_fields(line: str, hint: str | None):
    raw = (line or "").strip()
    low = raw.lower()

    service = None
    category = None
    level = None
    event_type = None
    src_ip = None
    http_status = None
    url = None

    # src_ip
    m_from = SSHD_FROM_RE.search(raw)
    if m_from:
        src_ip = m_from.group("ip")
    else:
        m_ip = IPV4_RE.search(raw)
        if m_ip:
            src_ip = m_ip.group(0)

    # nginx access
    m_ng = NGINX_ACCESS_RE.search(raw)
    if m_ng:
        service = "nginx"
        category = "web"
        url = m_ng.group("url")
        http_status = _safe_int(m_ng.group("status"))
        event_type = "access"
        if http_status is not None:
            if http_status >= 500:
                level = "error"
            elif http_status >= 400:
                level = "warning"
            else:
                level = "info"

    # auth/sshd
    if ("sshd" in low) or ("failed password" in low) or ("authentication failure" in low):
        service = service or "auth"
        category = category or "auth"
        level = level or "warning"
        event_type = event_type or "login_fail"
        if not src_ip:
            m_ip = IPV4_RE.search(raw)
            if m_ip:
                src_ip = m_ip.group(0)

    # hint override (opsiyonel)
    if hint:
        h = hint.strip().lower()
        if h in ("nginx", "web"):
            service = service or "nginx"
            category = category or "web"
        elif h in ("auth", "ssh", "sshd"):
            service = service or "auth"
            category = category or "auth"
            level = level or "warning"
            event_type = event_type or "login_fail"

    # fallback
    service = service or "unknown"
    category = category or "general"
    level = level or ("error" if " error " in f" {low} " else "info")

    return {
        "service": service,
        "category": category,
        "level": level,
        "event_type": event_type,
        "src_ip": src_ip,
        "http_status": http_status,
        "url": url,
        "parsed_at": _utcnow_iso()
    }


def _build_hint_json(original_hint: str | None, parsed: dict, mode: str):
    """
    hint alanına 'sadece debug metadata' bas.
    Eskiden hint içine __parsed__ gömüyordun. Service layer bunu kolonlara basmıyorsa
    işe yaramıyor, hatta bazı yerlerde message içine JSON gömülmesine sebep oluyor.
    """
    base = {}
    if original_hint:
        s = original_hint.strip()
        if s:
            # hint kullanıcı metni ise sakla
            base["hint_text"] = s

    base["mode"] = mode  # "line" veya "jsonline" veya "event"
    base["parsed"] = parsed  # debug için kalsın
    return json.dumps(base, ensure_ascii=False)


def _normalize_from_json_obj(obj: dict):
    """
    JSON satırı geldiyse, bunu LogEvent alanlarına map edecek parsed üret.
    Burada controller-side normalize yapıyoruz.
    """
    service = obj.get("service") or "unknown"
    category = obj.get("category") or "general"
    level = obj.get("level") or "info"
    event_type = obj.get("event_type")
    src_ip = obj.get("src_ip")
    url = obj.get("url")
    http_status = obj.get("http_status")

    if http_status is not None:
        http_status = _safe_int(http_status)

    # message alanını temiz tut: obj içindeki message string'i
    message = obj.get("message") or ""
    raw_text = obj.get("raw_text") or ""

    parsed = {
        "service": service,
        "category": category,
        "level": level,
        "event_type": event_type,
        "src_ip": src_ip,
        "http_status": http_status,
        "url": url,
        "parsed_at": _utcnow_iso(),
    }
    return parsed, message, raw_text


@ingest_bp.get("/upload")
def upload_page():
    return render_template("upload.html")


@ingest_bp.post("/upload")
def upload_file():
    f = request.files.get("file")
    source = request.form.get("source", "manual-upload")
    source_type = request.form.get("source_type", "app")
    hint = request.form.get("hint") or None

    if not f:
        return jsonify({"success": False, "error": "file is required"}), 400

    raw_text = f.stream.read().decode("utf-8", errors="ignore")
    lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]

    inserted = 0
    failed = 0
    errors = []
    sample = []

    for idx, line in enumerate(lines, start=1):
        try:
            # 1) Satır komple JSON ise: onu parse edip alanları ordan al
            obj = _try_parse_json_line(line)
            if obj:
                parsed, msg, raw_line = _normalize_from_json_obj(obj)
                hint_json = _build_hint_json(hint, parsed, mode="jsonline")

                # svc.ingest_raw'nin imzasını bozmayalım:
                # raw parametresine gerçek raw log'u (raw_text) bas
                # ve message'in JSON'a dönüşmesini engellemek için raw'ı seçiyoruz
                raw_to_store = raw_line or msg or line

                ev = svc.ingest_raw(
                    source_name=source,
                    source_type=source_type,
                    raw=raw_to_store,
                    hint=hint_json
                )
            else:
                # 2) Normal log satırı: regex parser ile çıkar
                parsed = _guess_parsed_fields(line, hint)
                hint_json = _build_hint_json(hint, parsed, mode="line")

                ev = svc.ingest_raw(
                    source_name=source,
                    source_type=source_type,
                    raw=line,
                    hint=hint_json
                )

            inserted += 1

            if len(sample) < 5:
                sample.append({
                    "id": getattr(ev, "id", None),
                    "service": parsed.get("service"),
                    "level": parsed.get("level"),
                    "category": parsed.get("category"),
                    "src_ip": parsed.get("src_ip"),
                    "http_status": parsed.get("http_status"),
                    "url": parsed.get("url"),
                    "event_type": parsed.get("event_type"),
                })

        except Exception as e:
            failed += 1
            try:
                db.session.rollback()
            except Exception:
                pass

            current_app.logger.exception("INGEST upload failed at line=%s", idx)

            errors.append({
                "line": idx,
                "error": str(e),
                "raw_preview": (line[:180] + "…") if len(line) > 180 else line
            })

    return jsonify({
        "success": True,
        "inserted": inserted,
        "failed": failed,
        "errors": errors,
        "sample": sample
    })


@ingest_bp.post("/event")
def ingest_event():
    try:
        payload = IngestEventIn(**request.get_json(force=True))
    except ValidationError as e:
        return jsonify({"success": False, "error": e.errors()}), 400

    try:
        # payload.raw JSON ise önce onu kullan
        obj = _try_parse_json_line(payload.raw)
        if obj:
            parsed, msg, raw_line = _normalize_from_json_obj(obj)
            hint_json = _build_hint_json(payload.hint, parsed, mode="event-jsonline")
            raw_to_store = raw_line or msg or payload.raw
            ev = svc.ingest_raw(
                source_name=payload.source,
                source_type=payload.source_type,
                raw=raw_to_store,
                hint=hint_json
            )
        else:
            parsed = _guess_parsed_fields(payload.raw, payload.hint)
            hint_json = _build_hint_json(payload.hint, parsed, mode="event")
            ev = svc.ingest_raw(
                source_name=payload.source,
                source_type=payload.source_type,
                raw=payload.raw,
                hint=hint_json
            )

        return jsonify({"success": True, "id": getattr(ev, "id", None), "parsed": parsed})

    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        current_app.logger.exception("INGEST /event failed")
        return jsonify({"success": False, "error": str(e)}), 500
