"""Tests for Authentication, Argon2, RS256 JWT, Refresh Token Rotation, and RBAC."""

import uuid

import pytest
from httpx import AsyncClient

from sentinel_common.security import (
    Role,
    create_access_token,
    decode_access_token,
    generate_opaque_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)


def test_argon2_password_hashing() -> None:
    """Verify Argon2 password hashing and verification."""
    password = "SuperSecretPassword123!"
    hashed = hash_password(password)
    assert hashed.startswith("$argon2")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_rs256_jwt_token_generation_and_decoding() -> None:
    """Verify RS256 JWT access token signing and claim verification."""
    user_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())
    role = Role.ANALYST.value

    token = create_access_token(user_id=user_id, tenant_id=tenant_id, role=role)
    payload = decode_access_token(token)

    assert payload["sub"] == user_id
    assert payload["tenant_id"] == tenant_id
    assert payload["role"] == role
    assert payload["type"] == "access"


def test_opaque_refresh_token_hashing() -> None:
    """Verify opaque refresh token generation and SHA-256 hashing."""
    raw_token, hashed_token = generate_opaque_refresh_token()
    assert len(raw_token) == 64
    assert hash_refresh_token(raw_token) == hashed_token


@pytest.mark.asyncio
async def test_auth_service_registration_and_login(client: AsyncClient) -> None:
    """Integration test for registration and login API flow."""
    # 1. Register User
    reg_payload = {
        "email": "test.analyst@sentinelx.io",
        "password": "Password123!",
        "full_name": "Test Security Analyst",
        "role": "analyst",
        "tenant_name": "Acme Security Org",
    }
    reg_res = await client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201
    user_data = reg_res.json()
    assert user_data["email"] == "test.analyst@sentinelx.io"
    assert user_data["role"] == "analyst"
    assert "id" in user_data

    # 2. Login User
    login_payload = {
        "email": "test.analyst@sentinelx.io",
        "password": "Password123!",
    }
    login_res = await client.post("/api/v1/auth/login", json=login_payload)
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    assert token_data["mfa_required"] is False
    assert "sentinel_refresh_token" in login_res.cookies


@pytest.mark.asyncio
async def test_rbac_protected_routes(client: AsyncClient) -> None:
    """Test RBAC permission enforcement on protected user endpoints."""
    # 1. Accessing /users/me without token returns 401
    res = await client.get("/api/v1/users/me")
    assert res.status_code == 401

    # 2. Register analyst user and access /users/me
    reg_payload = {
        "email": "rbac.analyst@sentinelx.io",
        "password": "Password123!",
        "full_name": "RBAC Analyst",
        "role": "analyst",
        "tenant_name": "RBAC Org",
    }
    await client.post("/api/v1/auth/register", json=reg_payload)

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "rbac.analyst@sentinelx.io", "password": "Password123!"},
    )
    access_token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    me_res = await client.get("/api/v1/users/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "rbac.analyst@sentinelx.io"

    # 3. Accessing admin-only route with analyst role returns 403 Forbidden
    admin_res = await client.get("/api/v1/users/admin-only", headers=headers)
    assert admin_res.status_code == 403
    assert admin_res.json()["error"]["code"] == "FORBIDDEN"
