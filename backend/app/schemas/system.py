from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class ServiceHealth(BaseModel):
    status: str = Field(description="HEALTHY | DEGRADED | UNAVAILABLE")
    message: str
    details: Optional[Dict[str, Any]] = None


class SystemHealthResponse(BaseModel):
    status: str = Field(description="HEALTHY | DEGRADED | UNAVAILABLE")
    timestamp: str
    version: str
    environment: str
    services: Dict[str, ServiceHealth]
