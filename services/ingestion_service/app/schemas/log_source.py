"""LogSource Pydantic V2 schemas for CRUD operations."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class LogSourceCreate(BaseModel):
    """Schema for registering a new telemetry log source."""

    name: str = Field(..., min_length=1, max_length=100)
    source_type: str = Field(..., min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=255)
    is_active: bool = Field(default=True)
    config: dict[str, Any] = Field(default_factory=dict)


class LogSourceUpdate(BaseModel):
    """Schema for updating an existing log source."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    source_type: str | None = Field(default=None, min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=255)
    is_active: bool | None = None
    config: dict[str, Any] | None = None


class LogSourceResponse(BaseModel):
    """Schema representing a persistent log source."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    source_type: str
    description: str | None
    is_active: bool
    config: dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
