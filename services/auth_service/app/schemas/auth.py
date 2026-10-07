"""Auth, User, APIKey, and RBAC Pydantic V2 schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from sentinel_common.security import Role


class LoginRequest(BaseModel):
    """User login request payload."""

    email: EmailStr = Field(..., json_schema_extra={"example": "analyst@sentinelx.io"})
    password: str = Field(..., min_length=8, json_schema_extra={"example": "SecurePass123!"})
    totp_code: str | None = Field(default=None, json_schema_extra={"example": "123456"})


class TokenResponse(BaseModel):
    """JWT Token authentication response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutes
    mfa_required: bool = False
    mfa_session_token: str | None = None


class UserCreate(BaseModel):
    """User registration / creation schema."""

    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str
    role: Role = Role.ANALYST
    tenant_name: str | None = Field(default=None, description="Provide to create a new tenant organization")
    tenant_id: uuid.UUID | None = Field(default=None, description="Target existing tenant ID")


class UserResponse(BaseModel):
    """User response object."""

    id: uuid.UUID
    email: EmailStr
    full_name: str
    role: str
    tenant_id: uuid.UUID
    is_active: bool
    mfa_enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserProfileResponse(UserResponse):
    """Extended user profile including permissions list."""

    permissions: list[str] = Field(default_factory=list)


class TenantResponse(BaseModel):
    """Tenant organization response object."""

    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TOTPSetupResponse(BaseModel):
    """TOTP MFA setup initiation response."""

    secret: str
    provisioning_uri: str


class TOTPVerifyRequest(BaseModel):
    """TOTP MFA verification payload."""

    code: str = Field(..., min_length=6, max_length=6)
    secret: str | None = Field(default=None, description="TOTP secret if enabling MFA")


class APIKeyCreate(BaseModel):
    """Schema for creating a new API Key."""

    name: str = Field(..., min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=list, description="Requested permission scopes e.g. ['alerts:read']")
    expires_in_days: int | None = Field(default=None, ge=1, le=365)


class APIKeyResponse(BaseModel):
    """Schema for API Key response."""

    id: uuid.UUID
    name: str
    prefix: str
    raw_key: str | None = Field(default=None, description="Only populated on initial creation")
    scopes: list[str]
    expires_at: datetime | None
    is_active: bool
    last_used_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
