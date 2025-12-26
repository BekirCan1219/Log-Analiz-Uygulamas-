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

def _utcnow_iso():
    return datetime.utcnow().isoformat() + "Z"

def _safe_int(x):
    try:
        return int(x)
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

def _merge_hint(existing_hint: str | None, parsed: dict):
    base = {}
    if existing_hint:
        s = existing_hint.strip()
        if s:
            try:
                base = json.loads(s)
                if not isinstance(base, dict):
                    base = {"__hint_text__": existing_hint}
            except Exception:
                base = {"__hint_text__": existing_hint}
    base["__parsed__"] = parsed
    return json.dumps(base, ensure_ascii=False)


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
            parsed = _guess_parsed_fields(line, hint)
            merged_hint = _merge_hint(hint, parsed)

            ev = svc.ingest_raw(source_name=source, source_type=source_type, raw=line, hint=merged_hint)
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
                })

        except Exception as e:
            failed += 1
            # MSSQL + SQLAlchemy: hata sonrası session temizle
            try:
                db.session.rollback()
            except Exception:
                pass

            # Konsola tam traceback bas
            current_app.logger.exception("INGEST upload failed at line=%s", idx)

            # Kullanıcıya kısa hata döndür
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
        parsed = _guess_parsed_fields(payload.raw, payload.hint)
        merged_hint = _merge_hint(payload.hint, parsed)

        ev = svc.ingest_raw(
            source_name=payload.source,
            source_type=payload.source_type,
            raw=payload.raw,
            hint=merged_hint
        )
        return jsonify({"success": True, "id": getattr(ev, "id", None), "parsed": parsed})

    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        current_app.logger.exception("INGEST /event failed")
        return jsonify({"success": False, "error": str(e)}), 500
