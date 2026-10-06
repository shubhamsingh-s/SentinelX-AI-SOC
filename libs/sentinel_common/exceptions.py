"""Custom Exception hierarchy for SentinelX platform."""

from typing import Any


class SentinelXException(Exception):
    """Base exception class for all SentinelX application errors."""

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = 500,
        details: dict[str, Any] | list[Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class NotFoundException(SentinelXException):
    """Resource not found exception (HTTP 404)."""

    def __init__(
        self,
        message: str = "Requested resource not found",
        code: str = "RESOURCE_NOT_FOUND",
        details: dict[str, Any] | list[Any] | None = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=404, details=details)


class UnauthorizedException(SentinelXException):
    """Authentication required or failed exception (HTTP 401)."""

    def __init__(
        self,
        message: str = "Authentication credentials were not provided or are invalid",
        code: str = "UNAUTHORIZED",
        details: dict[str, Any] | list[Any] | None = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=401, details=details)


class ForbiddenException(SentinelXException):
    """Permission denied exception (HTTP 403)."""

    def __init__(
        self,
        message: str = "You do not have permission to perform this action",
        code: str = "FORBIDDEN",
        details: dict[str, Any] | list[Any] | None = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=403, details=details)


class BadRequestException(SentinelXException):
    """Invalid request payload exception (HTTP 400)."""

    def __init__(
        self,
        message: str = "Bad request format or invalid parameter",
        code: str = "BAD_REQUEST",
        details: dict[str, Any] | list[Any] | None = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=400, details=details)


class ConflictException(SentinelXException):
    """Resource conflict exception (HTTP 409)."""

    def __init__(
        self,
        message: str = "Resource conflict detected",
        code: str = "CONFLICT",
        details: dict[str, Any] | list[Any] | None = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=409, details=details)


class ServiceUnavailableException(SentinelXException):
    """Downstream service unavailable exception (HTTP 503)."""

    def __init__(
        self,
        message: str = "Service is temporarily unavailable",
        code: str = "SERVICE_UNAVAILABLE",
        details: dict[str, Any] | list[Any] | None = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=503, details=details)
