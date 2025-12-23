from flask import Blueprint, request, jsonify, render_template
from pydantic import ValidationError
from app.schemas.ingest_schema import IngestEventIn
from app.services.ingest_service import IngestService

ingest_bp = Blueprint("ingest", __name__, url_prefix="/api/ingest")
svc = IngestService()

@ingest_bp.get("/upload")
def upload_page():
    return render_template("upload.html")

@ingest_bp.post("/upload")
def upload_file():
    f = request.files.get("file")
    source = request.form.get("source", "manual-upload")
    source_type = request.form.get("source_type", "app")
    hint = request.form.get("hint") or None  # boş string gelirse None

    if not f:
        return jsonify({"success": False, "error": "file is required"}), 400

    inserted = 0
    failed = 0
    for line in f.stream.read().decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            svc.ingest_raw(source_name=source, source_type=source_type, raw=line, hint=hint)
            inserted += 1
        except Exception:
            failed += 1

    return jsonify({"success": True, "inserted": inserted, "failed": failed})

@ingest_bp.post("/event")
def ingest_event():
    try:
        payload = IngestEventIn(**request.get_json(force=True))
    except ValidationError as e:
        return jsonify({"success": False, "error": e.errors()}), 400

    ev = svc.ingest_raw(
        source_name=payload.source,
        source_type=payload.source_type,
        raw=payload.raw,
        hint=payload.hint
    )
    return jsonify({"success": True, "id": ev.id})
