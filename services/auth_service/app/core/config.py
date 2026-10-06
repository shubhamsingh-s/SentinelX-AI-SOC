"""Auth service specific configuration extending global settings."""

from sentinel_common.config import Settings


class AuthServiceSettings(Settings):
    """Auth Service Config."""

    SERVICE_NAME: str = "auth-service"


auth_settings = AuthServiceSettings()
