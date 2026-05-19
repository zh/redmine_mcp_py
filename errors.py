"""
errors.py — typed exceptions surfaced to MCP tool callers.

`_redmine` translates raw `httpx.HTTPStatusError` (which carries the full
Redmine response body, sometimes containing version banners, plugin names,
or backtraces) into a `RedmineAPIError` with a safe, short message. The
upstream body is preserved on the exception for server-side logs but is
never returned to the client.

Destructive tools (`delete_*`) raise `ConfirmationRequired` when called
without `confirm=True`, replacing the earlier ad-hoc `{"error": "..."}`
dict return so that all failures look the same to an MCP client.
"""
from __future__ import annotations

from typing import Optional


class RedmineAPIError(Exception):
    """A sanitized error from the upstream Redmine API.

    Attributes:
        status_code: the HTTP status returned by Redmine.
        upstream_body: the raw response body (may be None). For server logs only.
        validation_errors: parsed list when Redmine returns 422 with an
            ``errors`` array — safe to surface to the caller.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        upstream_body: Optional[str] = None,
        validation_errors: Optional[list[str]] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.upstream_body = upstream_body
        self.validation_errors = validation_errors or []


class ConfirmationRequired(Exception):
    """Raised by destructive tools when `confirm=True` was not passed.

    The message is human-readable and tells the caller what to do.
    """
