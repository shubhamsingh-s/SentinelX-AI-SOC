"""Tests for error handlers and unified JSON error structure."""

import pytest
from fastapi import APIRouter
from httpx import ASGITransport, AsyncClient

from sentinel_common.exceptions import NotFoundException, UnauthorizedException
from services.auth_service.app.main import create_app

# Dummy app with routes raising exceptions
dummy_app = create_app()
dummy_router = APIRouter()


@dummy_router.get("/test-not-found")
async def trigger_not_found() -> None:
    raise NotFoundException("Custom resource missing")


@dummy_router.get("/test-unauthorized")
async def trigger_unauthorized() -> None:
    raise UnauthorizedException("Token expired")


dummy_app.include_router(dummy_router)


@pytest.mark.asyncio
async def test_custom_exception_json_shape() -> None:
    """Verify custom SentinelXException returns standard JSON shape."""
    transport = ASGITransport(app=dummy_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/test-not-found")
        assert res.status_code == 404
        data = res.json()
        assert "error" in data
        err = data["error"]
        assert err["code"] == "RESOURCE_NOT_FOUND"
        assert err["message"] == "Custom resource missing"
        assert "request_id" in err


@pytest.mark.asyncio
async def test_unauthorized_exception_json_shape() -> None:
    """Verify UnauthorizedException returns HTTP 401 and code UNAUTHORIZED."""
    transport = ASGITransport(app=dummy_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/test-unauthorized")
        assert res.status_code == 401
        data = res.json()
        assert data["error"]["code"] == "UNAUTHORIZED"
        assert data["error"]["message"] == "Token expired"


@pytest.mark.asyncio
async def test_404_routing_error_json_shape(client: AsyncClient) -> None:
    """Verify undefined route returns standard JSON shape."""
    res = await client.get("/non-existent-route")
    assert res.status_code == 404
    data = res.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
