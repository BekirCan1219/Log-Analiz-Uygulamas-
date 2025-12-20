from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class IngestEventIn(BaseModel):
    source: str = Field(..., description="log source name e.g. nginx-web1")
    source_type: str = Field(..., description="nginx/auth/suricata/app")
    raw: str = Field(..., description="raw log line or raw json string")
    hint: Optional[str] = Field(None, description="optional hint: nginx_access, linux_auth, suricata_eve")
    metadata: Optional[Dict[str, Any]] = None
