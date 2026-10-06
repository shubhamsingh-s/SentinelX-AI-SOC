"""Tests for Log Ingestion API routes and threat processing pipeline."""

import uuid
from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient


@pytest.fixture
def mock_redis_xadd() -> Generator[AsyncMock, None, None]:
    """Fixture mocking Redis Stream xadd call."""
    with patch(
        "services.ingestion_service.app.services.ingest_service.Redis.xadd", new_callable=AsyncMock
    ) as mock_xadd:
        yield mock_xadd


@pytest.mark.asyncio
async def test_syslog_ingestion_api(client: AsyncClient, mock_redis_xadd: AsyncMock) -> None:
    """Test Syslog ingestion endpoint producing events and alert threat score."""
    tenant_id = str(uuid.uuid4())
    payload = {
        "message": (
            "<134>1 2026-10-07T00:00:00Z web01 sshd 1234 - - Failed password for invalid user"
            " admin from 192.168.1.100 port 54321 ssh2"
        ),
        "tenant_id": tenant_id,
    }

    response = await client.post("/api/v1/ingest/syslog", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["events_processed"] == 1
    assert data["alerts_generated"] >= 1
    assert data["max_risk_score"] >= 30.0


@pytest.mark.asyncio
async def test_cloudtrail_ingestion_api(client: AsyncClient, mock_redis_xadd: AsyncMock) -> None:
    """Test CloudTrail ingestion endpoint."""
    tenant_id = str(uuid.uuid4())
    payload = {
        "Records": [
            {
                "eventName": "ConsoleLogin",
                "sourceIPAddress": "192.168.1.100",
                "userIdentity": {"userName": "admin"},
                "eventSource": "signin.amazonaws.com",
            }
        ]
    }
    headers = {"X-Tenant-ID": tenant_id}

    response = await client.post("/api/v1/ingest/cloudtrail", json=payload, headers=headers)
    assert response.status_code == 202
    data = response.json()
    assert data["events_processed"] == 1


@pytest.mark.asyncio
async def test_vpc_flow_ingestion_api(client: AsyncClient, mock_redis_xadd: AsyncMock) -> None:
    """Test AWS VPC Flow log ingestion endpoint."""
    tenant_id = str(uuid.uuid4())
    payload = "2 123456789012 eni-01235678 192.168.1.100 10.0.0.1 443 49152 6 10 8400 1600000000 1600000060 REJECT OK"
    headers = {"X-Tenant-ID": tenant_id}

    response = await client.post("/api/v1/ingest/vpc-flow", content=payload, headers=headers)
    assert response.status_code == 202
    data = response.json()
    assert data["events_processed"] == 1
