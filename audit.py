"""
audit.py — structured JSON audit logging.

One-line JSON to stdout for every security-relevant event:
  * login_attempt (outcome=success/failure, ip, redmine_url, login)
  * token_issued / token_refreshed / token_revoked
  * rate_limit_exceeded
  * redmine_call (method, path, login, status, latency_ms)
  * auth_rejected (reason, ip, client_id)

Every record carries a `request_id` (8-char hex) sourced from a contextvar
that `RequestIDMiddleware` sets per HTTP request, so multiple log lines
emitted while handling a single user action can be correlated.

Secrets and PII never appear: API keys are already `RedactedStr`; request
bodies, query params, and payloads are *never* logged — just method, path,
and outcome.
"""
from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


_request_id: ContextVar[str] = ContextVar("request_id", default="-")


def current_request_id() -> str:
    return _request_id.get()


def new_request_id() -> str:
    """Short, URL-safe ID for correlating log lines within one request."""
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
}


class JsonAuditFormatter(logging.Formatter):
    """Serialize each record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "ts": round(record.created, 3),
            "level": record.levelname,
            "logger": record.name,
            "request_id": _request_id.get(),
            "msg": record.getMessage(),
        }
        # Merge any structured fields passed via `extra=...`.
        for k, v in record.__dict__.items():
            if k in _RESERVED or k.startswith("_") or k in data:
                continue
            try:
                json.dumps(v)
                data[k] = v
            except (TypeError, ValueError):
                data[k] = repr(v)
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False, default=str)


def configure_audit_logging(level: int = logging.INFO) -> None:
    """Wire stdlib logging to emit JSON to stdout.

    Idempotent: calling more than once won't stack handlers (helpful for
    test reloads).
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonAuditFormatter())
    root = logging.getLogger()
    # Drop any prior handler we installed; keep third-party ones we didn't.
    for h in list(root.handlers):
        if isinstance(getattr(h, "formatter", None), JsonAuditFormatter):
            root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(level)


# ---------------------------------------------------------------------------
# Request-ID middleware
# ---------------------------------------------------------------------------

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Set the request_id contextvar for every HTTP request.

    Honors an inbound X-Request-Id header (so an upstream proxy or load
    balancer can supply the value); otherwise generates a new short ID.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("x-request-id") or new_request_id()
        # Trim to a reasonable length so malicious upstream can't bloat logs.
        rid = rid[:64]
        token = _request_id.set(rid)
        try:
            response = await call_next(request)
            response.headers["X-Request-Id"] = rid
            return response
        finally:
            _request_id.reset(token)


# ---------------------------------------------------------------------------
# Helper for emitting structured events
# ---------------------------------------------------------------------------

_audit_log = logging.getLogger("redmine_mcp.audit")


def audit(event: str, /, level: int = logging.INFO, **fields: Any) -> None:
    """Emit a structured audit event.

    Usage:
        audit("login_attempt", outcome="success", ip="1.2.3.4", login="alice")
    """
    _audit_log.log(level, event, extra={"event": event, **fields})
