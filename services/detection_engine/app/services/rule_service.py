"""Service layer for Detection Rules CRUD and dry-run testing."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.detection.sigma_engine import SigmaRule
from sentinel_common.detection.threshold_engine import ThresholdRule
from services.detection_engine.app.models.rule import DetectionRule
from services.detection_engine.app.schemas.rule import (
    RuleCreate,
    RuleTestResponse,
    RuleUpdate,
)


class RuleService:
    """Manages DetectionRule persistence and dry-run execution."""

    @staticmethod
    async def create_rule(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        rule_in: RuleCreate,
    ) -> DetectionRule:
        """Create and store a detection rule after validating its syntax."""
        # Validate Sigma YAML if applicable
        if rule_in.rule_type == "sigma" and rule_in.yaml_definition:
            SigmaRule.from_yaml(rule_in.yaml_definition)

        # Validate Threshold configuration if applicable
        if rule_in.rule_type == "threshold" and rule_in.threshold_config:
            ThresholdRule.from_dict(
                {
                    "rule_id": "temp-validate",
                    "title": rule_in.title,
                    **rule_in.threshold_config,
                }
            )

        db_rule = DetectionRule(
            tenant_id=tenant_id,
            title=rule_in.title,
            description=rule_in.description,
            rule_type=rule_in.rule_type,
            severity=rule_in.severity,
            is_active=rule_in.is_active,
            yaml_definition=rule_in.yaml_definition,
            threshold_config=rule_in.threshold_config,
            mitre_attack_tactics=rule_in.mitre_attack_tactics,
        )
        db.add(db_rule)
        await db.commit()
        await db.refresh(db_rule)
        return db_rule

    @staticmethod
    async def get_rule(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        rule_id: uuid.UUID,
    ) -> DetectionRule | None:
        """Retrieve a specific detection rule by ID scoped to tenant."""
        stmt = select(DetectionRule).where(
            DetectionRule.id == rule_id,
            DetectionRule.tenant_id == tenant_id,
        )
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @staticmethod
    async def list_rules(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        rule_type: str | None = None,
        severity: str | None = None,
        is_active: bool | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> list[DetectionRule]:
        """Query list of detection rules with optional filters."""
        stmt = select(DetectionRule).where(DetectionRule.tenant_id == tenant_id)
        if rule_type:
            stmt = stmt.where(DetectionRule.rule_type == rule_type)
        if severity:
            stmt = stmt.where(DetectionRule.severity == severity)
        if is_active is not None:
            stmt = stmt.where(DetectionRule.is_active == is_active)

        stmt = stmt.offset(skip).limit(limit)
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @staticmethod
    async def update_rule(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        rule_id: uuid.UUID,
        rule_in: RuleUpdate,
    ) -> DetectionRule | None:
        """Update detection rule fields."""
        rule = await RuleService.get_rule(db, tenant_id, rule_id)
        if not rule:
            return None

        update_data = rule_in.model_dump(exclude_unset=True)

        if "yaml_definition" in update_data and update_data["yaml_definition"]:
            SigmaRule.from_yaml(update_data["yaml_definition"])

        for k, v in update_data.items():
            setattr(rule, k, v)

        await db.commit()
        await db.refresh(rule)
        return rule

    @staticmethod
    async def delete_rule(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        rule_id: uuid.UUID,
    ) -> bool:
        """Delete detection rule by ID."""
        stmt = delete(DetectionRule).where(
            DetectionRule.id == rule_id,
            DetectionRule.tenant_id == tenant_id,
        )
        res = await db.execute(stmt)
        await db.commit()
        return res.rowcount > 0

    @staticmethod
    def test_dry_run(
        rule: DetectionRule,
        sample_event: dict[str, Any],
    ) -> RuleTestResponse:
        """Dry-run test a rule against a sample log event."""
        if rule.rule_type == "sigma":
            if not rule.yaml_definition:
                return RuleTestResponse(
                    matched=False,
                    rule_id=str(rule.id),
                    rule_type=rule.rule_type,
                    title=rule.title,
                    severity=rule.severity,
                    details={"error": "Rule is missing YAML definition"},
                    evaluated_fields=list(sample_event.keys()),
                )

            sigma_rule = SigmaRule.from_yaml(rule.yaml_definition)
            matched = sigma_rule.matches(sample_event)
            details = {
                "matched": matched,
                "selection": sigma_rule.selection,
                "detection": sigma_rule.detection,
                "level": sigma_rule.level,
            }
            return RuleTestResponse(
                matched=matched,
                rule_id=str(rule.id),
                rule_type=rule.rule_type,
                title=rule.title,
                severity=rule.severity,
                details=details,
                evaluated_fields=list(sample_event.keys()),
            )

        elif rule.rule_type == "threshold":
            th_dict = {
                "rule_id": str(rule.id),
                "title": rule.title,
                "severity": rule.severity,
                **rule.threshold_config,
            }
            th_rule = ThresholdRule.from_dict(th_dict)
            matches_filter = th_rule.matches_filter(sample_event)
            group_val = th_rule.extract_group_value(sample_event)
            details = {
                "matches_filter": matches_filter,
                "group_by_field": th_rule.group_by,
                "extracted_group_value": group_val,
                "threshold": th_rule.threshold,
                "window_seconds": th_rule.window_seconds,
            }
            return RuleTestResponse(
                matched=matches_filter,
                rule_id=str(rule.id),
                rule_type=rule.rule_type,
                title=rule.title,
                severity=rule.severity,
                details=details,
                evaluated_fields=list(sample_event.keys()),
            )

        return RuleTestResponse(
            matched=False,
            rule_id=str(rule.id),
            rule_type=rule.rule_type,
            title=rule.title,
            severity=rule.severity,
            details={"error": f"Unsupported rule type: {rule.rule_type}"},
            evaluated_fields=[],
        )
