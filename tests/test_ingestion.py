"""Tests for Log Ingestion API routes, batch ingestion, normaliser, Redis Stream, and Log Sources CRUD."""

import uuid
from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from services.ingestion_service.app.schemas.ingest import RawEventItem
from services.ingestion_service.app.services.normalizer import EventNormalizer


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


@pytest.mark.asyncio
async def test_batch_events_ingestion_api_key_auth(client: AsyncClient, mock_redis_xadd: AsyncMock) -> None:
    """Test POST /api/v1/ingest/events batch ingestion with API-Key authentication and Redis Stream push."""
    # 1. Register user and create API Key
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "ingest.analyst@sentinelx.io",
            "password": "Password123!",
            "full_name": "Ingest Analyst",
            "role": "analyst",
            "tenant_name": "Ingest Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "ingest.analyst@sentinelx.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    key_res = await client.post(
        "/api/v1/auth/api-keys",
        json={"name": "Collector Key", "scopes": ["alerts:read", "logs:read"]},
        headers=auth_headers,
    )
    raw_api_key = key_res.json()["raw_key"]

    # 2. Ingest batch of events using API Key header
    batch_payload = {
        "events": [
            {
                "source_type": "firewall",
                "event_name": "network_traffic",
                "source_ip": "192.168.1.50",
                "destination_ip": "10.0.0.1",
                "source_port": 51234,
                "destination_port": 443,
                "protocol": "TCP",
                "action": "reject",
                "severity": "medium",
                "raw_payload": "traffic reject from 192.168.1.50 to 10.0.0.1:443",
            },
            {
                "source_type": "auth",
                "event_name": "ssh_login",
                "source_ip": "10.0.0.99",
                "username": "root",
                "action": "failed",
                "severity": "high",
                "raw_payload": "Failed SSH login for root from 10.0.0.99",
            },
        ]
    }
    ingest_headers = {"X-API-Key": raw_api_key}

    res = await client.post("/api/v1/ingest/events", json=batch_payload, headers=ingest_headers)
    assert res.status_code == 202
    data = res.json()
    assert data["status"] == "accepted"
    assert data["events_ingested"] == 2
    assert data["stream"] == "events:raw"


@pytest.mark.asyncio
async def test_batch_events_ingestion_unauthorized(client: AsyncClient) -> None:
    """Test POST /api/v1/ingest/events rejecting missing or invalid API Key."""
    payload = {
        "events": [
            {
                "source_type": "syslog",
                "event_name": "system_event",
                "raw_payload": "system booted",
            }
        ]
    }

    # Missing API Key
    res_no_auth = await client.post("/api/v1/ingest/events", json=payload)
    assert res_no_auth.status_code == 401

    # Invalid API Key
    res_bad_key = await client.post(
        "/api/v1/ingest/events",
        json=payload,
        headers={"X-API-Key": "sx_live_invalid_key_1234567890"},
    )
    assert res_bad_key.status_code == 401


@pytest.mark.asyncio
async def test_batch_events_validation_limit(client: AsyncClient) -> None:
    """Test validation rejecting empty batches and batches exceeding 1,000 events."""
    # Register & get token
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "batch.tester@sentinelx.io",
            "password": "Password123!",
            "full_name": "Batch Tester",
            "role": "analyst",
            "tenant_name": "Batch Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "batch.tester@sentinelx.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Empty events array -> 422 Unprocessable Entity
    empty_res = await client.post("/api/v1/ingest/events", json={"events": []}, headers=headers)
    assert empty_res.status_code == 422

    # 2. Batch exceeding 1,000 events -> 422 Unprocessable Entity
    oversized_events = [{"source_type": "test", "raw_payload": "event"} for _ in range(1001)]
    over_res = await client.post("/api/v1/ingest/events", json={"events": oversized_events}, headers=headers)
    assert over_res.status_code == 422


def test_event_normalizer_common_schema() -> None:
    """Unit test EventNormalizer converting raw events into Common Event Schema."""
    tenant_id = uuid.uuid4()
    item = RawEventItem(
        source_type="FIREWALL ",
        event_name="Deny Traffic",
        source_ip=" 192.168.1.100 ",
        destination_ip="invalid_ip_format",
        source_port=8080,
        destination_port=999999,  # Invalid port
        protocol="tcp",
        username=" JDOE ",
        hostname=" WEB-01 ",
        action="reject",
        severity="CRITICAL",
        extra_fields={"rule_id": "fw-101"},
    )

    normalized = EventNormalizer.normalize_event(item, tenant_id=tenant_id)

    assert normalized["tenant_id"] == tenant_id
    assert normalized["source_type"] == "firewall"
    assert normalized["source_ip"] == "192.168.1.100"
    assert normalized["destination_ip"] is None  # Invalid IP discarded
    assert normalized["source_port"] == 8080
    assert normalized["destination_port"] is None  # Invalid port discarded
    assert normalized["protocol"] == "TCP"
    assert normalized["username"] == "jdoe"
    assert normalized["hostname"] == "web-01"
    assert normalized["action"] == "deny"  # 'reject' mapped to 'deny'
    assert normalized["severity"] == "critical"
    assert normalized["extra_fields"] == {"rule_id": "fw-101"}

    # Test stream payload generation
    stream_payload = EventNormalizer.to_stream_payload(normalized)
    assert stream_payload["source_type"] == "firewall"
    assert stream_payload["action"] == "deny"
    assert stream_payload["severity"] == "critical"


@pytest.mark.asyncio
async def test_log_sources_crud(client: AsyncClient) -> None:
    """Test full CRUD lifecycle for log sources."""
    # 1. Register & Login
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "source.admin@sentinelx.io",
            "password": "Password123!",
            "full_name": "Source Admin",
            "role": "org_admin",
            "tenant_name": "Source Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "source.admin@sentinelx.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. CREATE Log Source
    create_payload = {
        "name": "Edge Palo Alto Firewall",
        "source_type": "firewall",
        "description": "Primary perimeter firewall feed",
        "is_active": True,
        "config": {"port": 514, "format": "pan_os"},
    }
    create_res = await client.post("/api/v1/log-sources", json=create_payload, headers=headers)
    assert create_res.status_code == 201
    source_data = create_res.json()
    source_id = source_data["id"]
    assert source_data["name"] == "Edge Palo Alto Firewall"
    assert source_data["source_type"] == "firewall"

    # 3. LIST Log Sources
    list_res = await client.get("/api/v1/log-sources", headers=headers)
    assert list_res.status_code == 200
    sources = list_res.json()
    assert len(sources) >= 1
    assert any(s["id"] == source_id for s in sources)

    # 4. GET Single Log Source
    get_res = await client.get(f"/api/v1/log-sources/{source_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "Edge Palo Alto Firewall"

    # 5. UPDATE Log Source
    update_res = await client.put(
        f"/api/v1/log-sources/{source_id}",
        json={"name": "Updated Firewall Name", "is_active": False},
        headers=headers,
    )
    assert update_res.status_code == 200
    assert update_res.json()["name"] == "Updated Firewall Name"
    assert update_res.json()["is_active"] is False

    # 6. DELETE Log Source
    del_res = await client.delete(f"/api/v1/log-sources/{source_id}", headers=headers)
    assert del_res.status_code == 200
    assert del_res.json()["message"] == "Log source successfully deleted"

    # 7. GET Deleted Log Source -> 404 Not Found
    get_after_del = await client.get(f"/api/v1/log-sources/{source_id}", headers=headers)
    assert get_after_del.status_code == 404
