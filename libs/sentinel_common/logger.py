"""Structured JSON logging with request_id and tenant_id contextvars."""

import json
import logging
import sys
from contextvars import ContextVar
from typing import Any

# Context variables for request and tenant tracing across async calls
request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
tenant_id_ctx: ContextVar[str | None] = ContextVar("tenant_id", default=None)


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter adding request_id, tenant_id, and metadata to log outputs."""

    def format(self, record: logging.LogRecord) -> str:
        log_object: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "service": record.__dict__.get("service", "sentinelx"),
            "request_id": request_id_ctx.get(),
            "tenant_id": tenant_id_ctx.get(),
        }

        if record.exc_info:
            log_object["exception"] = self.formatException(record.exc_info)

        # Include additional extra context passed to log calls
        extra = {
            k: v
            for k, v in record.__dict__.items()
            if k
            not in (
                "args",
                "asctime",
                "created",
                "exc_info",
                "exc_text",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "msg",
                "name",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
                "service",
            )
        }
        if extra:
            log_object["extra"] = extra

        return json.dumps(log_object)


def setup_logging(service_name: str = "sentinelx", log_level: str = "INFO") -> logging.Logger:
    """Configure system-wide structured JSON logger."""
    log_inst = logging.getLogger(service_name)
    log_inst.setLevel(log_level.upper())
    log_inst.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    log_inst.addHandler(handler)
    log_inst.propagate = False

    return log_inst


logger = setup_logging()
