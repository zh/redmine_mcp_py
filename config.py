"""
config.py — central, env-var-driven configuration.

All knobs live here so the rest of the codebase can stay portable across
deployment targets (Hugging Face Spaces, self-hosted, PaaS).
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None or val.strip() == "":
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _env_csv(name: str) -> list[str]:
    val = os.getenv(name, "")
    return [s.strip() for s in val.split(",") if s.strip()]


@dataclass(frozen=True)
class Settings:
    # Server-side secret used to sign CSRF cookies. Generated per process if
    # unset, which means CSRF cookies do not survive restart — fine for now,
    # explicit env var recommended for production.
    secret_key: str = field(
        default_factory=lambda: os.getenv("REDMINE_MCP_SECRET") or secrets.token_urlsafe(32)
    )

    # SSRF allowlist. If empty, only the private-IP block applies.
    allowed_hosts: list[str] = field(
        default_factory=lambda: _env_csv("REDMINE_MCP_ALLOWED_HOSTS")
    )

    # OAuth redirect_uri allowlist for clients that did NOT register via
    # /oauth/register. Exact-match.
    allowed_redirects: list[str] = field(
        default_factory=lambda: _env_csv("REDMINE_MCP_ALLOWED_REDIRECTS")
    )

    # Permit plaintext http:// for the redmine_url (dev only).
    allow_http: bool = field(default_factory=lambda: _env_bool("REDMINE_MCP_ALLOW_HTTP"))

    # Trust X-Forwarded-For / X-Real-IP (only enable when behind a known proxy).
    trust_proxy: bool = field(default_factory=lambda: _env_bool("REDMINE_MCP_TRUST_PROXY"))

    # Access-token lifetime, seconds. Default: 24h.
    token_ttl_seconds: int = field(
        default_factory=lambda: _env_int("REDMINE_MCP_TOKEN_TTL_SECONDS", 86400)
    )

    # Authorization-code lifetime, seconds. Default: 5min (RFC 6749 recommends ≤10min).
    code_ttl_seconds: int = field(
        default_factory=lambda: _env_int("REDMINE_MCP_CODE_TTL_SECONDS", 300)
    )

    # Per-request timeout for outbound Redmine HTTP calls.
    redmine_timeout_seconds: int = field(
        default_factory=lambda: _env_int("REDMINE_MCP_TIMEOUT_SECONDS", 30)
    )


settings = Settings()
