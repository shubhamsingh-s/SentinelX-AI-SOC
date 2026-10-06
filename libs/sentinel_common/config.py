"""Configuration management using pydantic-settings."""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global application settings loaded exclusively from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # General Environment
    ENV: Literal["development", "testing", "staging", "production"] = Field(
        default="development", description="Execution environment mode"
    )
    DEBUG: bool = Field(default=False, description="Enable debug mode")
    SERVICE_NAME: str = Field(default="sentinelx-service", description="Service identifier")
    API_V1_PREFIX: str = Field(default="/api/v1", description="API V1 path prefix")

    # Security & JWT Secrets
    SECRET_KEY: str = Field(
        default="09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7",
        description="Application secret key",
    )

    # PostgreSQL / TimescaleDB Configuration
    POSTGRES_HOST: str = Field(default="localhost", description="PostgreSQL host")
    POSTGRES_PORT: int = Field(default=5432, description="PostgreSQL port")
    POSTGRES_USER: str = Field(default="sentinelx", description="PostgreSQL user")
    POSTGRES_PASSWORD: str = Field(default="sentinelx_secure_pass", description="PostgreSQL password")
    POSTGRES_DB: str = Field(default="sentinelx_db", description="PostgreSQL database name")
    DATABASE_URL: str | None = Field(default=None, description="Direct Database URL string")

    # Redis Configuration
    REDIS_HOST: str = Field(default="localhost", description="Redis host")
    REDIS_PORT: int = Field(default=6379, description="Redis port")
    REDIS_PASSWORD: str | None = Field(default=None, description="Redis password")
    REDIS_DB: int = Field(default=0, description="Redis database index")
    REDIS_URL: str | None = Field(default=None, description="Direct Redis URL string")

    @property
    def get_database_url(self) -> str:
        """Construct database connection URL if not provided directly."""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def get_redis_url(self) -> str:
        """Construct redis connection URL if not provided directly."""
        if self.REDIS_URL:
            return self.REDIS_URL
        auth = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"


settings = Settings()
