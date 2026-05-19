"""Phase 1.7 — audit log shape:
* events emit one-line JSON to the `redmine_mcp.audit` logger
* request_id propagates from middleware to every audit() call in the same request
* X-Request-Id round-trips on the response
* No secrets or payloads ever appear (API keys are RedactedStr; payloads
  aren't passed to audit())
"""
from __future__ import annotations

import json
import logging

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from audit import audit, current_request_id
from server import app


def test_request_id_round_trips_on_response_headers():
    client = TestClient(app)
    resp = client.get(
        "/.well-known/oauth-authorization-server",
        headers={"X-Request-Id": "test-rid-deadbeef"},
    )
    assert resp.headers.get("X-Request-Id") == "test-rid-deadbeef"


def test_request_id_is_generated_when_absent():
    client = TestClient(app)
    resp = client.get("/.well-known/oauth-authorization-server")
    rid = resp.headers.get("X-Request-Id")
    assert rid and rid != "-"
    assert len(rid) >= 8


def test_audit_event_emits_structured_fields(caplog):
    """audit() puts the event name plus structured extras on the LogRecord."""
    with caplog.at_level(logging.INFO, logger="redmine_mcp.audit"):
        audit("login_ok", login="alice", ip="1.2.3.4")
    record = caplog.records[-1]
    assert record.getMessage() == "login_ok"
    assert getattr(record, "event") == "login_ok"
    assert getattr(record, "login") == "alice"
    assert getattr(record, "ip") == "1.2.3.4"


def test_audit_login_ok_event_fires_on_successful_login(caplog, monkeypatch):
    """End-to-end: a real /auth/login that succeeds emits 'login_ok'."""
    from auth import security, store as store_mod
    monkeypatch.setattr(security, "validate_redmine_url", lambda u: u.rstrip("/"))
    monkeypatch.setattr(store_mod, "validate_redmine_url", lambda u: u.rstrip("/"))

    client = TestClient(app)
    reg = client.post(
        "/oauth/register", json={"redirect_uris": ["https://app.example.com/cb"]},
    )
    cid = reg.json()["client_id"]
    authz = client.get(
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
    csrf = authz.cookies.get("redmine_mcp_csrf")

    with caplog.at_level(logging.INFO, logger="redmine_mcp.audit"):
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://redmine.example.com/users/current.json").mock(
                return_value=httpx.Response(
                    200, json={"user": {"id": 1, "login": "alice"}}
                )
            )
            client.post(
                "/auth/login",
                data={
                    "redmine_url": "https://redmine.example.com",
                    "api_key": "k",
                    "redirect_uri": "https://app.example.com/cb",
                    "state": "xyz",
                    "code_challenge": "abc",
                    "code_challenge_method": "S256",
                    "client_id": cid,
                    "csrf_token": csrf,
                },
                cookies={"redmine_mcp_csrf": csrf},
                follow_redirects=False,
            )

    login_records = [r for r in caplog.records if r.getMessage() == "login_ok"]
    assert login_records, "expected at least one login_ok event"
    rec = login_records[-1]
    assert getattr(rec, "login") == "alice"
    # The API key is NOT in the audit record (it never gets passed to audit()).
    serialized = json.dumps(rec.__dict__, default=str)
    assert "redmine_api_key" not in serialized


def test_audit_rate_limit_exceeded_fires_at_warning_level(caplog):
    """The 6th /oauth/register call in a window emits rate_limit_exceeded."""
    client = TestClient(app)
    body = {"redirect_uris": ["https://app.example.com/cb"]}
    with caplog.at_level(logging.WARNING, logger="redmine_mcp.audit"):
        for _ in range(6):
            client.post("/oauth/register", json=body)

    rate_records = [r for r in caplog.records if r.getMessage() == "rate_limit_exceeded"]
    assert rate_records, "expected a rate_limit_exceeded event"
    assert rate_records[-1].levelno == logging.WARNING
    assert getattr(rate_records[-1], "endpoint") == "register"
