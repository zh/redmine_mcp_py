"""
auth/store.py — in-memory token store + Redmine API key validator.
Replace the dict with a DB-backed store for production.
"""
import secrets
import httpx
from dataclasses import dataclass
from typing import Optional


@dataclass
class UserSession:
    redmine_url: str
    redmine_api_key: str
    redmine_user_id: int
    redmine_login: str


# token -> UserSession
_sessions: dict[str, UserSession] = {}


async def validate_redmine_credentials(redmine_url: str, api_key: str) -> Optional[UserSession]:
    """Hit /users/current.json to verify the API key is valid."""
    url = redmine_url.rstrip("/") + "/users/current.json"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers={"X-Redmine-API-Key": api_key})
        if resp.status_code != 200:
            return None
        data = resp.json().get("user", {})
        return UserSession(
            redmine_url=redmine_url.rstrip("/"),
            redmine_api_key=api_key,
            redmine_user_id=data["id"],
            redmine_login=data.get("login", ""),
        )
    except Exception:
        return None


def issue_token(session: UserSession) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = session
    return token


def lookup_token(token: str) -> Optional[UserSession]:
    return _sessions.get(token)


def revoke_token(token: str) -> None:
    _sessions.pop(token, None)
