"""
auth/store.py — UserSession model + Redmine credential validation.

Storage of tokens, OAuth codes, and DCR clients lives in `auth/token_store.py`
(pluggable backend, in-memory or Redis). This module is intentionally small
to avoid a circular import: TokenStore depends on UserSession, not the
other way around.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import httpx

from auth.security import RedactedStr, InvalidRedmineURL, validate_redmine_url


@dataclass
class UserSession:
    redmine_url: str
    redmine_api_key: RedactedStr
    redmine_user_id: int
    redmine_login: str
    expires_at: float = 0.0  # absolute unix timestamp; 0 = "set on issue"

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


async def validate_redmine_credentials(
    redmine_url: str, api_key: str
) -> Optional[UserSession]:
    """Hit /users/current.json to verify the API key. Returns None on failure.

    Applies SSRF validation to redmine_url before any outbound request.
    `expires_at` is left at 0 — the caller (token issuer) sets it.
    """
    try:
        safe_base = validate_redmine_url(redmine_url)
    except InvalidRedmineURL:
        return None

    url = f"{safe_base}/users/current.json"
    try:
        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=False,
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
