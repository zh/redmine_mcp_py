"""
Security regression tests.

Each test pins a specific defect that was fixed during the Phase 0 hardening
pass. If any of these regress, an attacker capability returns. Treat failures
as launch-blockers.
"""
from __future__ import annotations

import re

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from auth.security import (
    InvalidRedmineURL,
    RedactedStr,
    validate_redmine_url,
)
from auth import store as store_mod
from auth.token_store import get_store
from server import app


client = TestClient(app)


# ---------------------------------------------------------------------------
# 0.1 SSRF on redmine_url
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/",   # AWS / GCP metadata
        "http://127.0.0.1:8080/",     # loopback
        "http://10.0.0.5/",            # RFC1918 private
        "http://192.168.1.1/",         # RFC1918 private
        "http://localhost/",           # loopback by name
        "http://[::1]/",               # IPv6 loopback
        "ftp://redmine.example.com/", # bad scheme
        "javascript:alert(1)",         # bad scheme
        "",                            # empty
        "http://no-https.example.com/", # http blocked when ALLOW_HTTP not set
    ],
)
def test_validate_redmine_url_blocks_dangerous_inputs(url):
    with pytest.raises(InvalidRedmineURL):
        validate_redmine_url(url)


def test_validate_redmine_url_accepts_https_public():
    # We can't make a real DNS call deterministically; pick a host that we
    # know resolves to a public IP. Skip the test gracefully if offline.
    try:
        out = validate_redmine_url("https://example.com/")
    except InvalidRedmineURL as e:
        pytest.skip(f"DNS unavailable in test env: {e}")
    assert out == "https://example.com"


# ---------------------------------------------------------------------------
# 0.3 PKCE mandatory + S256-only
# ---------------------------------------------------------------------------

def test_authorize_rejects_missing_pkce():
    resp = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": "https://app.example.com/cb",
            "state": "xyz",
            "response_type": "code",
            "client_id": "anything",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_authorize_rejects_plain_pkce():
    resp = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": "https://app.example.com/cb",
            "state": "xyz",
            "response_type": "code",
            "client_id": "anything",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
        },
    )
    assert resp.status_code == 400


def test_authorize_rejects_unsupported_response_type():
    resp = client.get(
        "/auth/authorize",
        params={
            "response_type": "token",  # implicit flow, banned
            "redirect_uri": "https://app.example.com/cb",
            "state": "xyz",
            "client_id": "anything",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 0.2 Open redirect — redirect_uri must be registered
# ---------------------------------------------------------------------------

def test_authorize_rejects_unregistered_redirect_uri():
    # No client registered → fallback to env allowlist (empty in tests) → reject.
    resp = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": "https://evil.example.com/steal",
            "state": "xyz",
            "response_type": "code",
            "client_id": "nonexistent",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 400
    assert "redirect_uri" in resp.json()["error_description"]


@pytest.mark.parametrize(
    "loopback",
    [
        "http://127.0.0.1:62439/callback",
        "http://localhost:8080/callback",
        "http://[::1]:9000/callback",
    ],
)
def test_authorize_allows_rfc8252_loopback_without_registration(loopback):
    """Desktop MCP clients use random loopback ports; allow without DCR."""
    resp = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": loopback,
            "state": "xyz",
            "response_type": "code",
            "client_id": "no-such-client",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 200
    assert "Connect to Redmine" in resp.text


def test_authorize_accepts_registered_redirect_uri():
    reg = client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://app.example.com/cb"]},
    )
    assert reg.status_code == 201
    client_id = reg.json()["client_id"]

    resp = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": "https://app.example.com/cb",
            "state": "xyz",
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 200
    assert "Connect to Redmine" in resp.text


# ---------------------------------------------------------------------------
# 0.4 XSS in login template — autoescape on
# ---------------------------------------------------------------------------

def test_login_form_escapes_state():
    reg = client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://app.example.com/cb"]},
    )
    client_id = reg.json()["client_id"]

    xss = '"><script>alert(1)</script>'
    resp = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": "https://app.example.com/cb",
            "state": xss,
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 200
    # The raw payload must NOT appear; the escaped form should.
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


# ---------------------------------------------------------------------------
# 0.5 CSRF — /auth/login must reject when token is absent / wrong
# ---------------------------------------------------------------------------

def test_login_rejects_missing_csrf():
    resp = client.post(
        "/auth/login",
        data={
            "redmine_url": "https://redmine.example.com",
            "api_key": "deadbeef",
            "redirect_uri": "http://localhost:1234/cb",  # loopback allowed
            "state": "xyz",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
            "client_id": "anything",
            # csrf_token deliberately omitted
        },
    )
    assert resp.status_code == 400
    # Validation failures now re-render the login form with the error visible.
    assert "Session expired" in resp.text or "reload" in resp.text.lower()


def test_login_rejects_mismatched_csrf():
    # Get a real CSRF cookie from /auth/authorize
    reg = client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://app.example.com/cb"]},
    )
    cid = reg.json()["client_id"]
    fresh = client.get(
        "/auth/authorize",
        params={
            "redirect_uri": "https://app.example.com/cb",
            "state": "xyz",
            "response_type": "code",
            "client_id": cid,
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        },
    )
    assert fresh.status_code == 200
    cookie_csrf = fresh.cookies.get("redmine_mcp_csrf")
    assert cookie_csrf

    # Submit a *different* csrf_token — must fail.
    resp = client.post(
        "/auth/login",
        data={
            "redmine_url": "https://redmine.example.com",
            "api_key": "deadbeef",
            "redirect_uri": "https://app.example.com/cb",
            "state": "xyz",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
            "client_id": cid,
            "csrf_token": "this-is-not-the-token",
        },
        cookies={"redmine_mcp_csrf": cookie_csrf},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 0.6 Token expiry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_store_drops_expired_sessions():
    """Expired sessions vanish from the store on the next get_session."""
    sess = store_mod.UserSession(
        redmine_url="https://redmine.example.com",
        redmine_api_key=RedactedStr("k"),
        redmine_user_id=1,
        redmine_login="u",
        expires_at=1.0,  # already in the past
    )
    store = get_store()
    await store.put_session("tok-abc", sess)
    assert await store.get_session("tok-abc") is None
    # And asking again still returns None (entry was pruned).
    assert await store.get_session("tok-abc") is None


# ---------------------------------------------------------------------------
# 0.7 Credential redaction
# ---------------------------------------------------------------------------

def test_redacted_str_hides_value_in_repr_and_str():
    r = RedactedStr("super-secret-api-key")
    assert "super-secret" not in repr(r)
    assert "super-secret" not in str(r)
    # But the underlying value is intact for code that explicitly reveals.
    assert r.reveal() == "super-secret-api-key"


def test_user_session_repr_does_not_leak_api_key():
    sess = store_mod.UserSession(
        redmine_url="https://redmine.example.com",
        redmine_api_key=RedactedStr("super-secret-api-key"),
        redmine_user_id=7,
        redmine_login="alice",
    )
    text = repr(sess)
    assert "super-secret" not in text
    assert "***" in text


# ---------------------------------------------------------------------------
# 0.8 Confirm gate on destructive deletes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delete_issue_requires_confirm():
    from server import delete_issue
    from errors import ConfirmationRequired

    with pytest.raises(ConfirmationRequired) as exc:
        await delete_issue(issue_id=42)
    assert "confirm" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

def test_security_headers_present_on_metadata_endpoint():
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    h = resp.headers
    assert "strict-transport-security" in {k.lower() for k in h.keys()}
    assert "x-frame-options" in {k.lower() for k in h.keys()}
    assert "content-security-policy" in {k.lower() for k in h.keys()}
    assert h["x-frame-options"] == "DENY"
