from app.repositories.log_repository import LogRepository
from .parse_service import parse_by_hint
from .normalize_service import normalize

class IngestService:
    def __init__(self):
        self.repo = LogRepository()

    def ingest_raw(self, *, source_name: str, source_type: str, raw: str, hint: str | None):
        source = self.repo.get_or_create_source(source_name, source_type)
        parsed = parse_by_hint(raw, hint)
        normalized = normalize(parsed, raw, source_type)

        event = self.repo.insert_event(source_id=source.id, source_type=source_type, normalized=normalized)
        return event
