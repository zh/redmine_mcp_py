"""
auth/token_store_redis.py — Redis-backed TokenStore with at-rest encryption.

Used when `REDMINE_MCP_REDIS_URL` is set. Redis stores JSON values; the only
sensitive field (the user's Redmine API key) is Fernet-encrypted before
serialization. The DB itself can therefore be snapshotted, replicated, or
inspected by an operator without exposing user credentials.

TTLs use native Redis `EX`, so expiry is server-enforced — no Python sweeper
needed for sessions or auth codes. DCR client records get a long TTL
(`REDMINE_MCP_CLIENT_TTL_SECONDS`, default 30 days).
"""
from __future__ import annotations

import json
import time
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from redis.asyncio import Redis
from redis.exceptions import RedisError

from auth.security import RedactedStr
from auth.store import UserSession
from config import settings


_SESSION_PREFIX = "mcp:session:"
_CODE_PREFIX = "mcp:code:"
_CLIENT_PREFIX = "mcp:client:"
_REFRESH_PREFIX = "mcp:refresh:"
_RATE_PREFIX = "mcp:rate:"


class RedisTokenStore:
    def __init__(self, url: str, fernet_key: str) -> None:
        self._redis: Redis = Redis.from_url(url, decode_responses=True)
        self._fernet = Fernet(fernet_key.encode("ascii"))

    # -- helpers ------------------------------------------------------------

    def _encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def _decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")

    def _session_to_dict(self, s: UserSession) -> dict:
        return {
            "redmine_url": s.redmine_url,
            "redmine_api_key": self._encrypt(s.redmine_api_key.reveal()),
            "redmine_user_id": s.redmine_user_id,
            "redmine_login": s.redmine_login,
            "expires_at": s.expires_at,
        }

    def _session_from_dict(self, d: dict) -> UserSession:
        return UserSession(
            redmine_url=d["redmine_url"],
            redmine_api_key=RedactedStr(self._decrypt(d["redmine_api_key"])),
            redmine_user_id=d["redmine_user_id"],
            redmine_login=d["redmine_login"],
            expires_at=float(d["expires_at"]),
        )

    @staticmethod
    def _ttl_for(expires_at: float) -> int:
        return max(1, int(expires_at - time.time()))

    # -- sessions -----------------------------------------------------------

    async def put_session(self, token: str, session: UserSession) -> None:
        await self._redis.set(
            _SESSION_PREFIX + token,
            json.dumps(self._session_to_dict(session)),
            ex=self._ttl_for(session.expires_at),
        )

    async def get_session(self, token: str) -> Optional[UserSession]:
        raw = await self._redis.get(_SESSION_PREFIX + token)
        if raw is None:
            return None
        try:
            sess = self._session_from_dict(json.loads(raw))
        except (json.JSONDecodeError, InvalidToken, KeyError, ValueError):
            # Corrupted entry — drop it.
            await self._redis.delete(_SESSION_PREFIX + token)
            return None
        if sess.is_expired():
            await self._redis.delete(_SESSION_PREFIX + token)
            return None
        return sess

    async def delete_session(self, token: str) -> None:
        await self._redis.delete(_SESSION_PREFIX + token)

    async def purge_expired_sessions(self) -> int:
        # Native Redis TTL handles expiry.
        return 0

    # -- codes --------------------------------------------------------------

    async def put_code(self, code: str, entry: dict) -> None:
        s: UserSession = entry["session"]
        payload = {
            "session": self._session_to_dict(s),
            "redirect_uri": entry["redirect_uri"],
            "client_id": entry.get("client_id", ""),
            "expires_at": entry["expires_at"],
            "code_challenge": entry["code_challenge"],
            "code_challenge_method": entry["code_challenge_method"],
        }
        await self._redis.set(
            _CODE_PREFIX + code,
            json.dumps(payload),
            ex=self._ttl_for(entry["expires_at"]),
        )

    async def pop_code(self, code: str) -> Optional[dict]:
        # GETDEL is atomic — exactly the "single-use" semantics we need.
        raw = await self._redis.getdel(_CODE_PREFIX + code)
        if raw is None:
            return None
        try:
            d = json.loads(raw)
            d["session"] = self._session_from_dict(d["session"])
            return d
        except (json.JSONDecodeError, InvalidToken, KeyError, ValueError):
            return None

    async def purge_expired_codes(self) -> int:
        return 0

    # -- DCR clients --------------------------------------------------------

    async def put_client(self, client_id: str, data: dict) -> None:
        await self._redis.set(
            _CLIENT_PREFIX + client_id,
            json.dumps(data),
            ex=settings.client_ttl_seconds,
        )

    async def get_client(self, client_id: str) -> Optional[dict]:
        raw = await self._redis.get(_CLIENT_PREFIX + client_id)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    # -- refresh tokens -----------------------------------------------------

    async def put_refresh(self, refresh_token: str, session: UserSession) -> None:
        await self._redis.set(
            _REFRESH_PREFIX + refresh_token,
            json.dumps(self._session_to_dict(session)),
            ex=self._ttl_for(session.expires_at),
        )

    async def pop_refresh(self, refresh_token: str) -> Optional[UserSession]:
        # GETDEL is atomic — rotation requires that two concurrent refreshes
        # cannot both succeed.
        raw = await self._redis.getdel(_REFRESH_PREFIX + refresh_token)
        if raw is None:
            return None
        try:
            sess = self._session_from_dict(json.loads(raw))
        except (json.JSONDecodeError, InvalidToken, KeyError, ValueError):
            return None
        if sess.is_expired():
            return None
        return sess

    # -- rate counters ------------------------------------------------------

    async def incr_rate(self, key: str, window_seconds: int) -> int:
        full = _RATE_PREFIX + key
        # Pipeline: INCR + EXPIRE-only-if-no-TTL. The EXPIRE NX option makes
        # the TTL stick to the *first* increment of the window, so subsequent
        # bumps don't reset the window.
        pipe = self._redis.pipeline()
        pipe.incr(full)
        pipe.expire(full, window_seconds, nx=True)
        results = await pipe.execute()
        return int(results[0])

    # -- lifecycle ----------------------------------------------------------

    async def ping(self) -> bool:
        try:
            return bool(await self._redis.ping())
        except RedisError:
            return False

    async def close(self) -> None:
        await self._redis.aclose()
