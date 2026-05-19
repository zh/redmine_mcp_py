"""
auth/token_store.py — pluggable persistence for OAuth state.

Three kinds of objects live in the store:

  * **Sessions** — `UserSession` per access token, holding the user's Redmine
    URL + API key. TTL = `REDMINE_MCP_TOKEN_TTL_SECONDS`.
  * **Authorization codes** — short-lived dicts holding a session +
    redirect_uri + PKCE challenge. TTL = `REDMINE_MCP_CODE_TTL_SECONDS`.
  * **DCR clients** — RFC 7591 dynamic-client-registration records (the
    minted client_id and its `redirect_uris`). TTL =
    `REDMINE_MCP_CLIENT_TTL_SECONDS`.

The `TokenStore` Protocol lets the rest of the codebase stay agnostic to the
backend. `build_store()` reads `config.settings` and picks:

  * `InMemoryTokenStore` when `REDMINE_MCP_REDIS_URL` is empty (default).
    Single-process, dies on restart, zero deps.
  * `RedisTokenStore` when `REDMINE_MCP_REDIS_URL` is set. Requires
    `REDMINE_MCP_FERNET_KEY` so API keys are encrypted at rest.
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional, Protocol

from auth.store import UserSession
from config import settings


class TokenStore(Protocol):
    """Backend interface for OAuth state. All operations are async so the
    same call sites work for both in-memory and Redis backends.
    """

    async def put_session(self, token: str, session: UserSession) -> None: ...
    async def get_session(self, token: str) -> Optional[UserSession]: ...
    async def delete_session(self, token: str) -> None: ...
    async def purge_expired_sessions(self) -> int: ...

    async def put_code(self, code: str, entry: dict) -> None: ...
    async def pop_code(self, code: str) -> Optional[dict]: ...
    async def purge_expired_codes(self) -> int: ...

    async def put_client(self, client_id: str, data: dict) -> None: ...
    async def get_client(self, client_id: str) -> Optional[dict]: ...

    # Refresh tokens. `pop_refresh` is atomic (used in rotation) — once popped,
    # the same token cannot be redeemed again.
    async def put_refresh(self, refresh_token: str, session: UserSession) -> None: ...
    async def pop_refresh(self, refresh_token: str) -> Optional[UserSession]: ...

    # Fixed-window rate counter. Returns the count *after* this increment so
    # the caller can compare against a threshold.
    async def incr_rate(self, key: str, window_seconds: int) -> int: ...

    async def ping(self) -> bool: ...
    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# In-memory implementation (default; identical behavior to the original code).
# ---------------------------------------------------------------------------


class InMemoryTokenStore:
    """Single-process store. Encryption-at-rest is N/A — data only exists in
    the running process; the dataclass-level `RedactedStr` already prevents
    accidental log leakage.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, UserSession] = {}
        self._codes: dict[str, dict] = {}
        self._clients: dict[str, dict] = {}
        self._refresh: dict[str, UserSession] = {}
        self._rate: dict[str, tuple[int, float]] = {}  # key -> (count, window_end)
        self._lock = asyncio.Lock()

    # -- sessions -----------------------------------------------------------

    async def put_session(self, token: str, session: UserSession) -> None:
        async with self._lock:
            self._sessions[token] = session

    async def get_session(self, token: str) -> Optional[UserSession]:
        async with self._lock:
            s = self._sessions.get(token)
            if s is None:
                return None
            if s.is_expired():
                self._sessions.pop(token, None)
                return None
            return s

    async def delete_session(self, token: str) -> None:
        async with self._lock:
            self._sessions.pop(token, None)

    async def purge_expired_sessions(self) -> int:
        now = time.time()
        async with self._lock:
            expired = [t for t, s in self._sessions.items() if s.is_expired(now)]
            for t in expired:
                self._sessions.pop(t, None)
            return len(expired)

    # -- codes --------------------------------------------------------------

    async def put_code(self, code: str, entry: dict) -> None:
        async with self._lock:
            self._codes[code] = entry

    async def pop_code(self, code: str) -> Optional[dict]:
        async with self._lock:
            return self._codes.pop(code, None)

    async def purge_expired_codes(self) -> int:
        now = time.time()
        async with self._lock:
            expired = [c for c, e in self._codes.items() if now > e["expires_at"]]
            for c in expired:
                self._codes.pop(c, None)
            return len(expired)

    # -- DCR clients --------------------------------------------------------

    async def put_client(self, client_id: str, data: dict) -> None:
        async with self._lock:
            self._clients[client_id] = data

    async def get_client(self, client_id: str) -> Optional[dict]:
        async with self._lock:
            return self._clients.get(client_id)

    # -- refresh tokens -----------------------------------------------------

    async def put_refresh(self, refresh_token: str, session: UserSession) -> None:
        async with self._lock:
            self._refresh[refresh_token] = session

    async def pop_refresh(self, refresh_token: str) -> Optional[UserSession]:
        async with self._lock:
            sess = self._refresh.pop(refresh_token, None)
            if sess is None:
                return None
            if sess.is_expired():
                return None
            return sess

    # -- rate counters ------------------------------------------------------

    async def incr_rate(self, key: str, window_seconds: int) -> int:
        async with self._lock:
            now = time.time()
            count, window_end = self._rate.get(key, (0, 0.0))
            if now >= window_end:
                count, window_end = 0, now + window_seconds
            count += 1
            self._rate[key] = (count, window_end)
            return count

    # -- lifecycle ----------------------------------------------------------

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        async with self._lock:
            self._sessions.clear()
            self._codes.clear()
            self._clients.clear()
            self._refresh.clear()
            self._rate.clear()


# ---------------------------------------------------------------------------
# Factory + module-level singleton
# ---------------------------------------------------------------------------

_store: Optional[TokenStore] = None


async def build_store() -> TokenStore:
    """Construct the configured backend. Called once at app startup."""
    if not settings.redis_url:
        return InMemoryTokenStore()

    if not settings.fernet_key:
        raise RuntimeError(
            "REDMINE_MCP_REDIS_URL is set but REDMINE_MCP_FERNET_KEY is missing. "
            "Generate one with: "
            "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' "
            "and set it as an env var (do NOT commit it)."
        )

    # Validate key format before reaching out to Redis — Fernet's own error
    # ("Fernet key must be 32 url-safe base64-encoded bytes.") is technically
    # correct but cryptic to an operator who just pasted a placeholder.
    from cryptography.fernet import Fernet
    try:
        Fernet(settings.fernet_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as e:
        raise RuntimeError(
            "REDMINE_MCP_FERNET_KEY is not a valid Fernet key. "
            "It must be 32 url-safe base64-encoded bytes — generate one with: "
            "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        ) from e

    # Lazy import so the cryptography + redis deps are only required when used.
    from auth.token_store_redis import RedisTokenStore

    store = RedisTokenStore(settings.redis_url, settings.fernet_key)
    if not await store.ping():
        await store.close()
        raise RuntimeError(
            f"Cannot connect to Redis at {settings.redis_url}. "
            "If you're using docker compose, start the redis sibling with "
            "`docker compose --profile redis up` — without the profile the "
            "redis service is not created."
        )
    return store


def get_store() -> TokenStore:
    """Return the active store. Raises if startup hasn't initialized one."""
    if _store is None:
        raise RuntimeError("TokenStore not initialized — app lifespan never ran")
    return _store


def set_store(store: TokenStore) -> None:
    """Install the store as the module-level singleton. Called from lifespan."""
    global _store
    _store = store


def reset_store_for_tests() -> None:
    """Clear the module-level singleton. Tests only."""
    global _store
    _store = None
