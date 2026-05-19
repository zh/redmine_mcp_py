"""End-to-end OAuth flow: register → authorize → login → token → tool call."""
from __future__ import annotations

import base64
import hashlib
import re
import secrets

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from server import app


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.fixture(autouse=True)
def _reset_state():
    """Clear in-process auth state between tests so they don't leak."""
    from auth import routes as routes_mod
    from auth import store as store_mod
    routes_mod._pending_codes.clear()
    routes_mod._clients.clear()
    store_mod._sessions.clear()
    yield
    routes_mod._pending_codes.clear()
    routes_mod._clients.clear()
    store_mod._sessions.clear()


def test_full_oauth_flow(monkeypatch):
    client = TestClient(app)

    # Bypass DNS-based SSRF check for this synthetic redmine host.
    from auth import security, store as store_mod
    monkeypatch.setattr(security, "validate_redmine_url", lambda u: u.rstrip("/"))
    monkeypatch.setattr(store_mod, "validate_redmine_url", lambda u: u.rstrip("/"))

    # 1. register client
    reg = client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://app.example.com/cb"]},
    )
    assert reg.status_code == 201
    client_id = reg.json()["client_id"]

    # 2. authorize → CSRF cookie + form
    verifier, challenge = _pkce_pair()
    authz = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": "https://app.example.com/cb",
            "state": "xyz",
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert authz.status_code == 200
    csrf = authz.cookies.get("redmine_mcp_csrf")
    assert csrf

    # 3. login (mock the upstream Redmine /users/current.json)
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://redmine.example.com/users/current.json").mock(
            return_value=httpx.Response(200, json={"user": {"id": 42, "login": "alice"}})
        )
        login = client.post(
            "/auth/login",
            data={
                "redmine_url": "https://redmine.example.com",
                "api_key": "deadbeef",
                "redirect_uri": "https://app.example.com/cb",
                "state": "xyz",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "client_id": client_id,
                "csrf_token": csrf,
            },
            cookies={"redmine_mcp_csrf": csrf},
            follow_redirects=False,
        )
    assert login.status_code == 302, login.text
    loc = login.headers["location"]
    m = re.search(r"[?&]code=([^&]+)", loc)
    assert m, f"no code in redirect: {loc}"
    code = m.group(1)
    assert "state=xyz" in loc

    # 4. token exchange — must include verifier
    tok = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://app.example.com/cb",
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert tok.status_code == 200, tok.text
    payload = tok.json()
    assert payload["token_type"] == "bearer"
    assert payload["access_token"]
    assert payload["expires_in"] > 0

    # 5. token without verifier is rejected (replay safety)
    bad = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "anything",
            "redirect_uri": "https://app.example.com/cb",
        },
    )
    assert bad.status_code == 400


def test_token_redirect_uri_mismatch(monkeypatch):
    client = TestClient(app)

    from auth import security, store as store_mod
    monkeypatch.setattr(security, "validate_redmine_url", lambda u: u.rstrip("/"))
    monkeypatch.setattr(store_mod, "validate_redmine_url", lambda u: u.rstrip("/"))

    reg = client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://app.example.com/cb"]},
    )
    client_id = reg.json()["client_id"]

    verifier, challenge = _pkce_pair()
    authz = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": "https://app.example.com/cb",
            "state": "xyz",
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    csrf = authz.cookies.get("redmine_mcp_csrf")

    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://redmine.example.com/users/current.json").mock(
            return_value=httpx.Response(200, json={"user": {"id": 1, "login": "u"}})
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
                "client_id": client_id,
                "csrf_token": csrf,
            },
            cookies={"redmine_mcp_csrf": csrf},
            follow_redirects=False,
        )
    code = re.search(r"[?&]code=([^&]+)", login.headers["location"]).group(1)

    # Mismatched redirect_uri at token exchange — must fail.
    tok = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://app.example.com/different",
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert tok.status_code == 400
    assert tok.json()["error"] == "invalid_grant"
