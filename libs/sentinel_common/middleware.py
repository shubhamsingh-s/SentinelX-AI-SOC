"""Request ID and Tenant ID middleware for tracing and multi-tenant isolation."""

import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel_common.logger import request_id_ctx, tenant_id_ctx


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware ensuring every request has an X-Request-ID header and context variable."""

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:16]}"
        tenant_id = request.headers.get("X-Tenant-ID")

        # Set context variables for structured logging
        req_token = request_id_ctx.set(request_id)
        tenant_token = tenant_id_ctx.set(tenant_id)

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            if tenant_id:
                response.headers["X-Tenant-ID"] = tenant_id
            return response
        finally:
            request_id_ctx.reset(req_token)
            tenant_id_ctx.reset(tenant_token)
