"""Tests for Phase 1.2 (refresh tokens) and Phase 1.3 (rate limiting)."""
from __future__ import annotations

import base64
import hashlib
import re
import secrets

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from auth import security, store as store_mod
from auth.security import RedactedStr
from auth.token_store import get_store
from config import settings
from server import app


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _complete_oauth_flow(client: TestClient, monkeypatch) -> dict:
    """Run through register → authorize → login → token, return the JSON."""
    monkeypatch.setattr(security, "validate_redmine_url", lambda u: u.rstrip("/"))
    monkeypatch.setattr(store_mod, "validate_redmine_url", lambda u: u.rstrip("/"))

    reg = client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://app.example.com/cb"]},
    )
    cid = reg.json()["client_id"]

    verifier, challenge = _pkce()
    authz = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": "https://app.example.com/cb",
            "state": "xyz",
            "response_type": "code",
            "client_id": cid,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    csrf = authz.cookies.get("redmine_mcp_csrf")

    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://redmine.example.com/users/current.json").mock(
            return_value=httpx.Response(200, json={"user": {"id": 1, "login": "alice"}})
        )
        login = client.post(
            "/auth/login",
            data={
                "redmine_url": "https://redmine.example.com",
                "api_key": "k",
                "redirect_uri": "https://app.example.com/cb",
                "state": "xyz",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "client_id": cid,
                "csrf_token": csrf,
            },
            cookies={"redmine_mcp_csrf": csrf},
            follow_redirects=False,
        )
    code = re.search(r"[?&]code=([^&]+)", login.headers["location"]).group(1)

    tok = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://app.example.com/cb",
            "client_id": cid,
            "code_verifier": verifier,
        },
    )
    assert tok.status_code == 200, tok.text
    return tok.json()


# ---------------------------------------------------------------------------
# 1.2 Refresh tokens
# ---------------------------------------------------------------------------

def test_authorization_code_response_includes_refresh_token(monkeypatch):
    client = TestClient(app)
    body = _complete_oauth_flow(client, monkeypatch)
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["expires_in"] > 0
    # Refresh tokens are longer than access tokens (48 vs 32 bytes urlsafe).
    assert len(body["refresh_token"]) > len(body["access_token"])


def test_refresh_token_exchange_returns_new_pair(monkeypatch):
    client = TestClient(app)
    first = _complete_oauth_flow(client, monkeypatch)
    refresh = first["refresh_token"]

    resp = client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh},
    )
    assert resp.status_code == 200, resp.text
    second = resp.json()
    assert second["access_token"] != first["access_token"]
    assert second["refresh_token"] != first["refresh_token"]
    assert second["token_type"] == "bearer"
    assert second["expires_in"] > 0


def test_refresh_token_is_single_use(monkeypatch):
    """RFC 6749 §6 rotation: the old refresh token must not redeem again."""
    client = TestClient(app)
    first = _complete_oauth_flow(client, monkeypatch)
    refresh = first["refresh_token"]

    ok = client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh},
    )
    assert ok.status_code == 200

    replay = client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh},
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"


def test_refresh_unknown_token_rejected():
    client = TestClient(app)
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": "no-such-token"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_refresh_missing_token_rejected():
    client = TestClient(app)
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_metadata_advertises_refresh_grant():
    client = TestClient(app)
    md = client.get("/.well-known/oauth-authorization-server").json()
    assert "refresh_token" in md["grant_types_supported"]


# ---------------------------------------------------------------------------
# 1.3 Rate limiting
# ---------------------------------------------------------------------------

def test_register_endpoint_is_rate_limited(monkeypatch):
    """5/min default — the 6th call from one IP must 429."""
    client = TestClient(app)
    body = {"redirect_uris": ["https://app.example.com/cb"]}

    # Burn through the allowance.
    for _ in range(settings.rate_register_per_minute):
        ok = client.post("/oauth/register", json=body)
        assert ok.status_code == 201

    blocked = client.post("/oauth/register", json=body)
    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After") == "60"
    assert blocked.json()["error"] == "too_many_requests"


def test_token_endpoint_is_rate_limited():
    client = TestClient(app)

    # All 10 invalid_grant responses count toward the limit.
    for _ in range(settings.rate_token_per_minute):
        resp = client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": "bogus"},
        )
        assert resp.status_code == 400

    blocked = client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": "bogus"},
    )
    assert blocked.status_code == 429


def test_login_endpoint_is_rate_limited():
    client = TestClient(app)

    # 5/min default. CSRF-rejected responses still count.
    for _ in range(settings.rate_login_per_minute):
        resp = client.post(
            "/auth/login",
            data={
                "redmine_url": "https://redmine.example.com",
                "api_key": "k",
                "redirect_uri": "http://localhost:1234/cb",  # loopback allowed
                "state": "xyz",
                "code_challenge": "abc",
                "code_challenge_method": "S256",
                "client_id": "anything",
                # No csrf_token → 400, but still counts toward rate limit.
            },
        )
        assert resp.status_code == 400

    blocked = client.post(
        "/auth/login",
        data={
            "redmine_url": "https://redmine.example.com",
            "api_key": "k",
            "redirect_uri": "http://localhost:1234/cb",
            "state": "xyz",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
            "client_id": "anything",
        },
    )
    assert blocked.status_code == 429


# ---------------------------------------------------------------------------
# 1.3 TokenStore.incr_rate contract
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_incr_rate_resets_after_window():
    """First increment establishes the window; expiry resets the counter."""
    store = get_store()
    # 1-second window — easy to reset by tweaking the store internals.
    n1 = await store.incr_rate("test:reset", 1)
    n2 = await store.incr_rate("test:reset", 1)
    assert n1 == 1
    assert n2 == 2

    # Force the window past its expiry without sleeping.
    store._rate["test:reset"] = (2, 0.0)
    n3 = await store.incr_rate("test:reset", 1)
    assert n3 == 1
