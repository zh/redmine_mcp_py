"""
auth/store.py — in-memory token store + Redmine API key validator.

Sessions and authorization codes are stored in-process. Swap with a Redis or
DB-backed implementation behind the same module-level functions for production.

Security notes:
  * UserSession.redmine_api_key is wrapped in RedactedStr so it never appears
    in logs or tracebacks.
  * Tokens and codes have explicit TTLs; expired entries are pruned lazily on
    lookup and eagerly via purge_expired().
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from auth.security import RedactedStr, InvalidRedmineURL, validate_redmine_url
from config import settings


@dataclass
class UserSession:
    redmine_url: str
    redmine_api_key: RedactedStr
    redmine_user_id: int
    redmine_login: str
    expires_at: float = 0.0  # absolute unix timestamp; 0 means "set on issue"

    def is_expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) >= self.expires_at

    def __repr__(self) -> str:
        return (
            f"UserSession(redmine_url={self.redmine_url!r}, "
            f"redmine_api_key='***', "
            f"redmine_user_id={self.redmine_user_id}, "
            f"redmine_login={self.redmine_login!r}, "
            f"expires_at={self.expires_at})"
        )


# token -> UserSession
_sessions: dict[str, UserSession] = {}


async def validate_redmine_credentials(
    redmine_url: str, api_key: str
) -> Optional[UserSession]:
    """Hit /users/current.json to verify the API key. Returns None on failure.

    Applies SSRF validation to redmine_url before any outbound request.
    """
    try:
        safe_base = validate_redmine_url(redmine_url)
    except InvalidRedmineURL:
        return None

    url = f"{safe_base}/users/current.json"
    try:
        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=False,  # SSRF defense: no sneaky 302 to a private IP
        ) as client:
            resp = await client.get(url, headers={"X-Redmine-API-Key": api_key})
        if resp.status_code != 200:
            return None
        data = resp.json().get("user", {})
        return UserSession(
            redmine_url=safe_base,
            redmine_api_key=RedactedStr(api_key),
            redmine_user_id=data["id"],
            redmine_login=data.get("login", ""),
        )
    except Exception:
        return None


def issue_token(session: UserSession) -> tuple[str, int]:
    """Mint a bearer token. Returns (token, expires_in_seconds)."""
    ttl = settings.token_ttl_seconds
    session.expires_at = time.time() + ttl
    token = secrets.token_urlsafe(32)
    _sessions[token] = session
    return token, ttl


def lookup_token(token: str) -> Optional[UserSession]:
    sess = _sessions.get(token)
    if sess is None:
        return None
    if sess.is_expired():
        _sessions.pop(token, None)
        return None
    return sess


def revoke_token(token: str) -> None:
    _sessions.pop(token, None)


def purge_expired() -> int:
    """Drop expired sessions. Returns count purged."""
    now = time.time()
    expired = [t for t, s in _sessions.items() if s.is_expired(now)]
    for t in expired:
        _sessions.pop(t, None)
    return len(expired)
