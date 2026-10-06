"""Security module handling Argon2 password hashing, RS256 JWT tokens, TOTP MFA, and RBAC."""

import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sentinel_common.exceptions import UnauthorizedException
from sentinel_common.logger import logger

# Initialize Argon2 Password Hasher
ph = PasswordHasher()

# Generate RS256 Keypair dynamically if not supplied via env
_private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_private_pem = _private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("utf-8")
_public_pem = (
    _private_key_obj.public_key()
    .public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    .decode("utf-8")
)

JWT_PRIVATE_KEY: str = os.getenv("JWT_PRIVATE_KEY", _private_pem)
JWT_PUBLIC_KEY: str = os.getenv("JWT_PUBLIC_KEY", _public_pem)
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7


class Role(str, Enum):
    """SentinelX Role-Based Access Control (RBAC) roles."""

    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    RESPONDER = "responder"
    ANALYST = "analyst"
    HUNTER = "hunter"
    VIEWER = "viewer"


ROLE_HIERARCHY: dict[Role, int] = {
    Role.SUPER_ADMIN: 100,
    Role.ORG_ADMIN: 80,
    Role.RESPONDER: 60,
    Role.ANALYST: 40,
    Role.HUNTER: 30,
    Role.VIEWER: 10,
}


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    return ph.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password against Argon2id hash."""
    try:
        return ph.verify(hashed_password, password)
    except VerifyMismatchError:
        return False
    except Exception as e:
        logger.error(f"Error during password verification: {e}")
        return False


def create_access_token(user_id: str, tenant_id: str, role: str, expires_delta: timedelta | None = None) -> str:
    """Generate RS256 signed access token (15 min lifespan)."""
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    payload: dict[str, Any] = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "iat": now.timestamp(),
        "exp": expire.timestamp(),
        "type": "access",
    }

    token = jwt.encode(payload, JWT_PRIVATE_KEY, algorithm="RS256")
    return token


def decode_access_token(token: str) -> dict[str, Any]:
    """Verify and decode RS256 access token."""
    try:
        payload = jwt.decode(token, JWT_PUBLIC_KEY, algorithms=["RS256"])
        if payload.get("type") != "access":
            raise UnauthorizedException("Invalid token type")
        return payload
    except jwt.ExpiredSignatureError as e:
        raise UnauthorizedException("Access token has expired", code="TOKEN_EXPIRED") from e
    except jwt.PyJWTError as e:
        raise UnauthorizedException(f"Invalid access token: {e}", code="INVALID_TOKEN") from e


def generate_opaque_refresh_token() -> tuple[str, str]:
    """Generate opaque 64-char refresh token and its SHA-256 hash for DB storage."""
    raw_token = secrets.token_hex(32)  # 64 hex characters
    hashed_token = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, hashed_token


def hash_refresh_token(raw_token: str) -> str:
    """Hash refresh token string using SHA-256."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_totp_secret() -> str:
    """Generate secret for TOTP MFA."""
    return pyotp.random_base32()


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify 6-digit TOTP MFA code."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)


def check_role_permission(user_role: str, allowed_roles: list[Role]) -> bool:
    """Check if user role satisfies any of allowed roles."""
    try:
        user_r = Role(user_role)
    except ValueError:
        return False

    allowed_values = [r.value for r in allowed_roles]
    return user_r.value in allowed_values or user_r == Role.SUPER_ADMIN
