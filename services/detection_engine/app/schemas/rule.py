"""Pydantic schemas for Detection Rules CRUD and dry-run testing."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RuleBase(BaseModel):
    """Base schema for detection rule properties."""

    title: str = Field(..., min_length=3, max_length=255, description="Rule title")
    description: str = Field("", max_length=1000, description="Rule description")
    rule_type: Literal["sigma", "threshold"] = Field("sigma", description="Type of detection rule")
    severity: Literal["low", "medium", "high", "critical"] = Field("medium", description="Alert severity")
    is_active: bool = Field(True, description="Whether rule is currently active")
    yaml_definition: str | None = Field(None, description="Sigma YAML definition")
    threshold_config: dict[str, Any] = Field(default_factory=dict, description="Threshold configuration")
    mitre_attack_tactics: list[str] = Field(default_factory=list, description="MITRE ATT&CK tactic tags")

    @model_validator(mode="after")
    def validate_rule_config(self) -> RuleBase:
        """Ensure appropriate config is provided for the rule type."""
        if self.rule_type == "sigma" and not self.yaml_definition:
            raise ValueError("yaml_definition is required for Sigma rules")
        if self.rule_type == "threshold" and not self.threshold_config:
            raise ValueError("threshold_config is required for Threshold rules")
        return self


class RuleCreate(RuleBase):
    """Schema for creating a detection rule."""

    pass


class RuleUpdate(BaseModel):
    """Schema for updating an existing detection rule."""

    title: str | None = Field(None, min_length=3, max_length=255)
    description: str | None = Field(None, max_length=1000)
    rule_type: Literal["sigma", "threshold"] | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    is_active: bool | None = None
    yaml_definition: str | None = None
    threshold_config: dict[str, Any] | None = None
    mitre_attack_tactics: list[str] | None = None


class RuleResponse(BaseModel):
    """Schema for returning detection rule details."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    description: str
    rule_type: str
    severity: str
    is_active: bool
    yaml_definition: str | None
    threshold_config: dict[str, Any]
    mitre_attack_tactics: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RuleTestRequest(BaseModel):
    """Schema for testing / dry-running a rule against a sample event."""

    sample_event: dict[str, Any] = Field(
        ...,
        description="Sample security event dictionary to test against the rule",
    )


class RuleTestResponse(BaseModel):
    """Schema for dry-run test result."""

    matched: bool
    rule_id: str
    rule_type: str
    title: str
    severity: str
    details: dict[str, Any]
    evaluated_fields: list[str] = Field(default_factory=list)
