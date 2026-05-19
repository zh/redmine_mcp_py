"""TokenStore contract tests.

Both backends must satisfy the same Protocol. We run the same scenario
against InMemoryTokenStore and (when REDIS_URL is set) RedisTokenStore.
The Redis case is opt-in — set REDMINE_MCP_TEST_REDIS_URL to enable, e.g.
`REDMINE_MCP_TEST_REDIS_URL=redis://localhost:6379/15 pytest`.

The Fernet-encryption check is implemented as a tighter assertion specific
to the Redis backend: we read the raw bytes back and confirm the API key
isn't visible in cleartext.
"""
from __future__ import annotations

import json
import os
import time

import pytest

from auth.security import RedactedStr
from auth.store import UserSession
from auth.token_store import InMemoryTokenStore


def _fresh_session(api_key: str = "secret-key-12345", ttl: float = 3600.0) -> UserSession:
    return UserSession(
        redmine_url="https://redmine.example.com",
        redmine_api_key=RedactedStr(api_key),
        redmine_user_id=42,
        redmine_login="alice",
        expires_at=time.time() + ttl,
    )


# ---------------------------------------------------------------------------
# In-memory contract
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_inmem_session_roundtrip():
    store = InMemoryTokenStore()
    sess = _fresh_session()
    await store.put_session("tok", sess)
    got = await store.get_session("tok")
    assert got is not None
    assert got.redmine_login == "alice"
    assert got.redmine_api_key.reveal() == "secret-key-12345"


@pytest.mark.asyncio
async def test_inmem_session_delete():
    store = InMemoryTokenStore()
    await store.put_session("tok", _fresh_session())
    await store.delete_session("tok")
    assert await store.get_session("tok") is None


@pytest.mark.asyncio
async def test_inmem_pop_code_is_one_shot():
    store = InMemoryTokenStore()
    entry = {
        "session": _fresh_session(),
        "redirect_uri": "http://localhost:1234/cb",
        "client_id": "c",
        "expires_at": time.time() + 60,
        "code_challenge": "abc",
        "code_challenge_method": "S256",
    }
    await store.put_code("code-1", entry)
    out = await store.pop_code("code-1")
    assert out is not None
    assert out["redirect_uri"] == "http://localhost:1234/cb"
    # Second pop returns None — codes are single-use.
    assert await store.pop_code("code-1") is None


@pytest.mark.asyncio
async def test_inmem_client_roundtrip():
    store = InMemoryTokenStore()
    data = {"redirect_uris": ["http://localhost:1234/cb"], "created_at": 1}
    await store.put_client("client-x", data)
    got = await store.get_client("client-x")
    assert got == data


@pytest.mark.asyncio
async def test_inmem_purge_expired_sessions():
    store = InMemoryTokenStore()
    fresh = _fresh_session(ttl=3600)
    stale = _fresh_session(ttl=-10)  # already expired
    await store.put_session("ok", fresh)
    await store.put_session("dead", stale)
    purged = await store.purge_expired_sessions()
    assert purged == 1
    assert await store.get_session("ok") is not None
    assert await store.get_session("dead") is None


@pytest.mark.asyncio
async def test_inmem_ping():
    store = InMemoryTokenStore()
    assert await store.ping() is True


# ---------------------------------------------------------------------------
# Redis backend (opt-in — needs a real Redis)
# ---------------------------------------------------------------------------

_REDIS_URL = os.getenv("REDMINE_MCP_TEST_REDIS_URL")


@pytest.mark.asyncio
@pytest.mark.skipif(not _REDIS_URL, reason="set REDMINE_MCP_TEST_REDIS_URL to enable")
async def test_redis_session_roundtrip_and_encryption():
    from cryptography.fernet import Fernet
    from auth.token_store_redis import RedisTokenStore, _SESSION_PREFIX

    key = Fernet.generate_key().decode()
    store = RedisTokenStore(_REDIS_URL, key)
    try:
        assert await store.ping() is True

        sess = _fresh_session(api_key="super-secret-redmine-key")
        await store.put_session("tok-1", sess)

        # Round-trip via the public API.
        got = await store.get_session("tok-1")
        assert got is not None
        assert got.redmine_api_key.reveal() == "super-secret-redmine-key"

        # And the raw value in Redis must NOT contain the cleartext key.
        raw = await store._redis.get(_SESSION_PREFIX + "tok-1")
        assert raw is not None
        assert "super-secret-redmine-key" not in raw
        # It IS a JSON document with an encrypted api_key field.
        d = json.loads(raw)
        assert d["redmine_login"] == "alice"
        assert "super-secret-redmine-key" not in d["redmine_api_key"]

        await store.delete_session("tok-1")
        assert await store.get_session("tok-1") is None
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.skipif(not _REDIS_URL, reason="set REDMINE_MCP_TEST_REDIS_URL to enable")
async def test_redis_pop_code_is_atomic_single_use():
    from cryptography.fernet import Fernet
    from auth.token_store_redis import RedisTokenStore

    store = RedisTokenStore(_REDIS_URL, Fernet.generate_key().decode())
    try:
        entry = {
            "session": _fresh_session(),
            "redirect_uri": "http://localhost:5555/cb",
            "client_id": "c",
            "expires_at": time.time() + 60,
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        }
        await store.put_code("rcode-1", entry)
        first = await store.pop_code("rcode-1")
        second = await store.pop_code("rcode-1")
        assert first is not None
        assert second is None
    finally:
        await store.close()
