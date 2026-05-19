"""Phase 1.6 — input validation:
* `limit` clamps to 1..100 inside every list_* tool.
* `if v is not None` (not truthiness) on list_issues / list_time_entries so
  legitimate zero / empty-string filters aren't silently dropped.
* Literal types on enum-ish fields are advisory at runtime (FastMCP relays
  whatever the LLM sends), so we exercise the call shape, not the type
  checker.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from auth import security, store as store_mod
from auth.security import RedactedStr
from auth.store import UserSession
from auth.token_store import get_store


@pytest.fixture(autouse=True)
def _bypass_url_validator(monkeypatch):
    monkeypatch.setattr(security, "validate_redmine_url", lambda u: u.rstrip("/"))
    monkeypatch.setattr(store_mod, "validate_redmine_url", lambda u: u.rstrip("/"))
    import server
    monkeypatch.setattr(server, "validate_redmine_url", lambda u: u.rstrip("/"))


async def _install_session() -> str:
    sess = UserSession(
        redmine_url="https://redmine.example.com",
        redmine_api_key=RedactedStr("k"),
        redmine_user_id=1,
        redmine_login="alice",
        expires_at=9_999_999_999.0,
    )
    await get_store().put_session("tok", sess)
    return "tok"


def _force_session(monkeypatch, sess: UserSession) -> None:
    """FastMCP's `get_access_token` reads from contextvars wired to a real
    request. For unit-testing tools directly we just stub _session()."""
    import server

    async def _fake_session():
        return sess

    monkeypatch.setattr(server, "_session", _fake_session)


def _sess() -> UserSession:
    return UserSession(
        redmine_url="https://redmine.example.com",
        redmine_api_key=RedactedStr("k"),
        redmine_user_id=1,
        redmine_login="alice",
        expires_at=9_999_999_999.0,
    )


@pytest.mark.asyncio
async def test_list_issues_clamps_limit_above_100(monkeypatch):
    _force_session(monkeypatch, _sess())
    from server import list_issues

    with respx.mock(assert_all_called=False) as mock:
        route = mock.get("https://redmine.example.com/issues.json").mock(
            return_value=httpx.Response(200, json={"issues": []})
        )
        await list_issues(limit=10_000)

    assert route.calls.last is not None
    params = dict(route.calls.last.request.url.params)
    assert params["limit"] == "100"


@pytest.mark.asyncio
async def test_list_issues_clamps_limit_below_1(monkeypatch):
    _force_session(monkeypatch, _sess())
    from server import list_issues

    with respx.mock(assert_all_called=False) as mock:
        route = mock.get("https://redmine.example.com/issues.json").mock(
            return_value=httpx.Response(200, json={"issues": []})
        )
        await list_issues(limit=0)

    assert dict(route.calls.last.request.url.params)["limit"] == "1"


@pytest.mark.asyncio
async def test_list_issues_does_not_drop_explicit_empty_string_status(monkeypatch):
    """`if v:` was dropping `status_id=""`; `is not None` keeps it."""
    _force_session(monkeypatch, _sess())
    from server import list_issues

    with respx.mock(assert_all_called=False) as mock:
        route = mock.get("https://redmine.example.com/issues.json").mock(
            return_value=httpx.Response(200, json={"issues": []})
        )
        await list_issues(status_id="")

    # An explicit empty string IS now forwarded — the caller signaled "any".
    assert "status_id" in dict(route.calls.last.request.url.params)


@pytest.mark.asyncio
async def test_list_time_entries_keeps_user_id_zero(monkeypatch):
    """user_id=0 used to be silently dropped by truthiness."""
    _force_session(monkeypatch, _sess())
    from server import list_time_entries

    with respx.mock(assert_all_called=False) as mock:
        route = mock.get("https://redmine.example.com/time_entries.json").mock(
            return_value=httpx.Response(200, json={"time_entries": []})
        )
        await list_time_entries(user_id=0)

    assert dict(route.calls.last.request.url.params)["user_id"] == "0"


@pytest.mark.asyncio
async def test_list_projects_clamps_limit(monkeypatch):
    _force_session(monkeypatch, _sess())
    from server import list_projects

    with respx.mock(assert_all_called=False) as mock:
        route = mock.get("https://redmine.example.com/projects.json").mock(
            return_value=httpx.Response(200, json={"projects": []})
        )
        await list_projects(limit=500)

    assert dict(route.calls.last.request.url.params)["limit"] == "100"
