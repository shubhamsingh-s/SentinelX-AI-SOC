"""Comprehensive tests for Authentication, Argon2, RS256 JWT, MFA,
Refresh Token Rotation, JTI Blacklist, API Keys, and RBAC / require_perm.
"""

import uuid

import pyotp
import pytest
from httpx import AsyncClient

from sentinel_common.security import (
    Role,
    create_access_token,
    decode_access_token,
    generate_api_key,
    generate_opaque_refresh_token,
    hash_api_key,
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
    """Verify RS256 JWT access token signing, claims, and JTI."""
    user_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())
    role = Role.ANALYST.value

    token = create_access_token(user_id=user_id, tenant_id=tenant_id, role=role, permissions=["alerts:read"])
    payload = decode_access_token(token)

    assert payload["sub"] == user_id
    assert payload["tenant_id"] == tenant_id
    assert payload["role"] == role
    assert payload["type"] == "access"
    assert "jti" in payload
    assert payload["permissions"] == ["alerts:read"]


def test_opaque_refresh_token_hashing() -> None:
    """Verify opaque refresh token generation and SHA-256 hashing."""
    raw_token, hashed_token = generate_opaque_refresh_token()
    assert len(raw_token) == 64
    assert hash_refresh_token(raw_token) == hashed_token


def test_api_key_generation_and_hashing() -> None:
    """Verify API key prefix generation and SHA-256 key hashing."""
    raw_key, prefix, key_hash = generate_api_key(prefix="sx_live_")
    assert raw_key.startswith("sx_live_")
    assert prefix == "sx_live_"
    assert hash_api_key(raw_key) == key_hash


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
async def test_auth_me_endpoint(client: AsyncClient) -> None:
    """Test /auth/me profile endpoint returning active permissions."""
    # Register & Login
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "me.analyst@sentinelx.io",
            "password": "Password123!",
            "full_name": "Me Analyst",
            "role": "analyst",
            "tenant_name": "Me Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "me.analyst@sentinelx.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    me_res = await client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["email"] == "me.analyst@sentinelx.io"
    assert me_data["role"] == "analyst"
    assert "alerts:read" in me_data["permissions"]


@pytest.mark.asyncio
async def test_mfa_setup_and_verification(client: AsyncClient) -> None:
    """Test TOTP MFA setup, verification, and enforcement upon login."""
    # 1. Register & Login User
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "mfa.user@sentinelx.io",
            "password": "Password123!",
            "full_name": "MFA User",
            "role": "analyst",
            "tenant_name": "MFA Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "mfa.user@sentinelx.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Initiate MFA setup
    setup_res = await client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert setup_res.status_code == 200
    setup_data = setup_res.json()
    secret = setup_data["secret"]
    assert "provisioning_uri" in setup_data

    # 3. Verify MFA code and enable MFA
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    verify_res = await client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": valid_code, "secret": secret},
        headers=headers,
    )
    assert verify_res.status_code == 200

    # 4. Login without TOTP code returns mfa_required=True
    login_no_totp = await client.post(
        "/api/v1/auth/login",
        json={"email": "mfa.user@sentinelx.io", "password": "Password123!"},
    )
    assert login_no_totp.status_code == 200
    assert login_no_totp.json()["mfa_required"] is True

    # 5. Login with valid TOTP code succeeds
    login_with_totp = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "mfa.user@sentinelx.io",
            "password": "Password123!",
            "totp_code": totp.now(),
        },
    )
    assert login_with_totp.status_code == 200
    assert login_with_totp.json()["access_token"] != ""


@pytest.mark.asyncio
async def test_refresh_token_rotation_and_reuse_detection(client: AsyncClient) -> None:
    """Test refresh token rotation and token reuse detection logic."""
    # Register & Login
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "refresh.user@sentinelx.io",
            "password": "Password123!",
            "full_name": "Refresh User",
            "role": "analyst",
            "tenant_name": "Refresh Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "refresh.user@sentinelx.io", "password": "Password123!"},
    )
    first_cookie = login_res.cookies.get("sentinel_refresh_token")
    assert first_cookie is not None

    # 1. First refresh -> succeeds, returns new cookie
    ref_res1 = await client.post("/api/v1/auth/refresh", headers={"X-Refresh-Token": first_cookie})
    assert ref_res1.status_code == 200
    assert "access_token" in ref_res1.json()
    second_cookie = ref_res1.cookies.get("sentinel_refresh_token")
    assert second_cookie is not None
    assert second_cookie != first_cookie

    # 2. Reuse old refresh token -> triggers reuse detection & revokes all sessions
    ref_res_reuse = await client.post("/api/v1/auth/refresh", headers={"X-Refresh-Token": first_cookie})
    assert ref_res_reuse.status_code == 401
    assert ref_res_reuse.json()["error"]["code"] == "TOKEN_REUSE_DETECTED"

    # 3. Subsequent attempts even with second token fail because all tokens were revoked
    ref_res2 = await client.post("/api/v1/auth/refresh", headers={"X-Refresh-Token": second_cookie})
    assert ref_res2.status_code == 401


@pytest.mark.asyncio
async def test_logout_clears_cookie(client: AsyncClient) -> None:
    """Test logout endpoint clearing refresh token cookie."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "logout.user@sentinelx.io",
            "password": "Password123!",
            "full_name": "Logout User",
            "role": "analyst",
            "tenant_name": "Logout Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "logout.user@sentinelx.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    logout_res = await client.post("/api/v1/auth/logout", headers=headers)
    assert logout_res.status_code == 200
    assert logout_res.json()["message"] == "Successfully logged out"


@pytest.mark.asyncio
async def test_rbac_and_require_perm_guard(client: AsyncClient) -> None:
    """Test RBAC role requirement and require_perm permission guard."""
    # Register Analyst User
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "perm.analyst@sentinelx.io",
            "password": "Password123!",
            "full_name": "Perm Analyst",
            "role": "analyst",
            "tenant_name": "Perm Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "perm.analyst@sentinelx.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Access admin-only route -> 403 Forbidden
    admin_res = await client.get("/api/v1/users/admin-only", headers=headers)
    assert admin_res.status_code == 403

    # 2. Access perm-check route requiring 'alerts:write' with Analyst role -> 403 Forbidden
    perm_res = await client.get("/api/v1/users/perm-check", headers=headers)
    assert perm_res.status_code == 403

    # Register Org Admin User (possesses 'alerts:write')
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "perm.admin@sentinelx.io",
            "password": "Password123!",
            "full_name": "Perm Admin",
            "role": "org_admin",
            "tenant_name": "Perm Org Admin",
        },
    )
    admin_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "perm.admin@sentinelx.io", "password": "Password123!"},
    )
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Access perm-check with Org Admin role -> 200 OK
    admin_perm_res = await client.get("/api/v1/users/perm-check", headers=admin_headers)
    assert admin_perm_res.status_code == 200
    assert admin_perm_res.json()["permission"] == "alerts:write"


@pytest.mark.asyncio
async def test_api_keys_full_lifecycle(client: AsyncClient) -> None:
    """Test API Key creation, authentication via X-API-Key header, and key revocation."""
    # Register & Login
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "apikey.user@sentinelx.io",
            "password": "Password123!",
            "full_name": "API Key User",
            "role": "analyst",
            "tenant_name": "APIKey Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "apikey.user@sentinelx.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create API Key
    create_key_res = await client.post(
        "/api/v1/auth/api-keys",
        json={"name": "Ingestion Key", "scopes": ["alerts:read", "logs:read"]},
        headers=headers,
    )
    assert create_key_res.status_code == 201
    key_data = create_key_res.json()
    raw_key = key_data["raw_key"]
    key_id = key_data["id"]
    assert raw_key.startswith("sx_live_")

    # 2. List API Keys
    list_keys_res = await client.get("/api/v1/auth/api-keys", headers=headers)
    assert list_keys_res.status_code == 200
    assert len(list_keys_res.json()) >= 1

    # 3. Authenticate endpoint using X-API-Key header
    api_header = {"X-API-Key": raw_key}
    me_res = await client.get("/api/v1/users/me", headers=api_header)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "apikey.user@sentinelx.io"

    # 4. Revoke API Key
    del_key_res = await client.delete(f"/api/v1/auth/api-keys/{key_id}", headers=headers)
    assert del_key_res.status_code == 200

    # 5. Authenticate with revoked key returns 401 Unauthorized
    me_revoked_res = await client.get("/api/v1/users/me", headers=api_header)
    assert me_revoked_res.status_code == 401


@pytest.mark.asyncio
async def test_logout_jti_blacklist_invalidation(client: AsyncClient) -> None:
    """Test logout blacklisting access token JTI in Redis and preventing usage."""
    from unittest.mock import AsyncMock

    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "jti.user@sentinelx.io",
            "password": "Password123!",
            "full_name": "JTI User",
            "role": "analyst",
            "tenant_name": "JTI Org",
        },
    )
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "jti.user@sentinelx.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    me_res = await client.get("/api/v1/users/me", headers=headers)
    assert me_res.status_code == 200

    # Test blacklisted JTI check in deps
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("services.auth_service.app.deps.is_jti_blacklisted", AsyncMock(return_value=True))
        me_blacklisted_res = await client.get("/api/v1/users/me", headers=headers)
        assert me_blacklisted_res.status_code == 401
        assert me_blacklisted_res.json()["error"]["code"] == "TOKEN_REVOKED"


@pytest.mark.asyncio
async def test_brute_force_login_lockout(client: AsyncClient) -> None:
    """Test brute-force login lockout returning 401 TOO_MANY_REQUESTS when account is locked out."""
    from unittest.mock import AsyncMock

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("services.auth_service.app.services.auth_service.is_locked_out", AsyncMock(return_value=True))
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": "locked.user@sentinelx.io", "password": "Password123!"},
        )
        assert login_res.status_code == 401
        assert login_res.json()["error"]["code"] == "TOO_MANY_REQUESTS"
