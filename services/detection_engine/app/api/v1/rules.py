"""Detection Rules CRUD and dry-run testing API Router."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.db import get_db_session
from services.auth_service.app.deps import get_current_user
from services.auth_service.app.models.user import User
from services.detection_engine.app.schemas.rule import (
    RuleCreate,
    RuleResponse,
    RuleTestRequest,
    RuleTestResponse,
    RuleUpdate,
)
from services.detection_engine.app.services.rule_service import RuleService

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


async def resolve_tenant_id(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    session: AsyncSession = Depends(get_db_session),
) -> uuid.UUID:
    """Resolve tenant ID from auth context or X-Tenant-ID header."""
    if authorization or x_api_key:
        try:
            # Try full authentication if credentials are provided
            current_user: User = await get_current_user(
                authorization=authorization,
                x_api_key=x_api_key,
                session=session,
            )
            return current_user.tenant_id
        except Exception:
            pass

    if x_tenant_id:
        try:
            return uuid.UUID(x_tenant_id)
        except ValueError:
            pass

    # Default fallback tenant UUID for dev/test
    return uuid.UUID("00000000-0000-0000-0000-000000000001")


@router.post(
    "",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Detection Rule",
)
async def create_rule(
    payload: RuleCreate,
    tenant_id: uuid.UUID = Depends(resolve_tenant_id),
    session: AsyncSession = Depends(get_db_session),
) -> RuleResponse:
    """Create a new Sigma or Threshold detection rule."""
    try:
        rule = await RuleService.create_rule(session, tenant_id, payload)
        return RuleResponse.model_validate(rule)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create detection rule: {e}",
        ) from e


@router.get(
    "",
    response_model=list[RuleResponse],
    summary="List Detection Rules",
)
async def list_rules(
    rule_type: str | None = Query(None, description="Filter by rule type (sigma, threshold)"),
    severity: str | None = Query(None, description="Filter by severity"),
    is_active: bool | None = Query(None, description="Filter active status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    tenant_id: uuid.UUID = Depends(resolve_tenant_id),
    session: AsyncSession = Depends(get_db_session),
) -> list[RuleResponse]:
    """Retrieve all detection rules for the tenant."""
    rules = await RuleService.list_rules(
        session,
        tenant_id=tenant_id,
        rule_type=rule_type,
        severity=severity,
        is_active=is_active,
        skip=skip,
        limit=limit,
    )
    return [RuleResponse.model_validate(r) for r in rules]


@router.get(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Get Detection Rule",
)
async def get_rule(
    rule_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(resolve_tenant_id),
    session: AsyncSession = Depends(get_db_session),
) -> RuleResponse:
    """Retrieve a detection rule by ID."""
    rule = await RuleService.get_rule(session, tenant_id, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return RuleResponse.model_validate(rule)


@router.put(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Update Detection Rule",
)
async def update_rule(
    rule_id: uuid.UUID,
    payload: RuleUpdate,
    tenant_id: uuid.UUID = Depends(resolve_tenant_id),
    session: AsyncSession = Depends(get_db_session),
) -> RuleResponse:
    """Update detection rule definition or settings."""
    try:
        rule = await RuleService.update_rule(session, tenant_id, rule_id, payload)
        if not rule:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
        return RuleResponse.model_validate(rule)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Detection Rule",
)
async def delete_rule(
    rule_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(resolve_tenant_id),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Delete a detection rule."""
    deleted = await RuleService.delete_rule(session, tenant_id, rule_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")


@router.post(
    "/{rule_id}/test",
    response_model=RuleTestResponse,
    summary="Dry-Run Test Detection Rule",
)
async def test_rule_dry_run(
    rule_id: uuid.UUID,
    payload: RuleTestRequest,
    tenant_id: uuid.UUID = Depends(resolve_tenant_id),
    session: AsyncSession = Depends(get_db_session),
) -> RuleTestResponse:
    """Execute a dry-run test of a rule against a provided sample security event."""
    rule = await RuleService.get_rule(session, tenant_id, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    return RuleService.test_dry_run(rule, payload.sample_event)
