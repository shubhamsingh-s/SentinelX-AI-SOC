"""Global error handlers producing standardized JSON error responses."""

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from sentinel_common.exceptions import SentinelXException
from sentinel_common.logger import logger, request_id_ctx


def build_error_response(
    status_code: int,
    code: str,
    message: str,
    details: Any = None,
    request_id: str | None = None,
) -> JSONResponse:
    """Build unified error JSON shape {error: {code, message, details, request_id}}."""
    req_id = request_id or request_id_ctx.get() or "unknown"
    content = {
        "error": {
            "code": code,
            "message": message,
            "details": details if details is not None else {},
            "request_id": req_id,
        }
    }
    return JSONResponse(status_code=status_code, content=content)


async def sentinelx_exception_handler(request: Request, exc: SentinelXException) -> JSONResponse:
    """Handle application-specific SentinelX exceptions."""
    logger.warning(
        f"Handled SentinelXException: {exc.code} - {exc.message}",
        extra={"path": request.url.path, "status_code": exc.status_code},
    )
    return build_error_response(
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        details=exc.details,
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle request payload validation errors from Pydantic / FastAPI."""
    errors = exc.errors()
    logger.warning(
        f"Validation error on {request.url.path}",
        extra={"validation_errors": errors},
    )
    return build_error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        code="VALIDATION_ERROR",
        message="Request validation failed",
        details=errors,
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handle standard Starlette / FastAPI HTTP exceptions."""
    code_map = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        429: "TOO_MANY_REQUESTS",
    }
    code = code_map.get(exc.status_code, "HTTP_ERROR")
    return build_error_response(
        status_code=exc.status_code,
        code=code,
        message=str(exc.detail),
        details={},
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for uncaught server errors."""
    logger.error(
        f"Unhandled server error: {exc}",
        exc_info=exc,
        extra={"path": request.url.path},
    )
    return build_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected internal server error occurred",
        details={},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all custom exception handlers to a FastAPI application instance."""
    app.add_exception_handler(SentinelXException, sentinelx_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)
