"""Phase 1.5 — _redmine maps upstream HTTP errors to typed exceptions
with sanitized messages. Raw upstream bodies must never reach the caller."""
from __future__ import annotations

import httpx
import pytest
import respx

from auth import security, store as store_mod
from auth.security import RedactedStr
from auth.store import UserSession
from errors import RedmineAPIError
from server import _redmine


@pytest.fixture
def _bypass_url_validator(monkeypatch):
    """Skip DNS-based SSRF check for the synthetic redmine host."""
    monkeypatch.setattr(security, "validate_redmine_url", lambda u: u.rstrip("/"))
    monkeypatch.setattr(store_mod, "validate_redmine_url", lambda u: u.rstrip("/"))
    # server.py imports the symbol directly, so patch that too.
    import server
    monkeypatch.setattr(server, "validate_redmine_url", lambda u: u.rstrip("/"))


def _session() -> UserSession:
    return UserSession(
        redmine_url="https://redmine.example.com",
        redmine_api_key=RedactedStr("k"),
        redmine_user_id=1,
        redmine_login="alice",
        expires_at=9_999_999_999.0,
    )


@pytest.mark.asyncio
async def test_redmine_401_becomes_permission_denied(_bypass_url_validator):
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://redmine.example.com/issues/1.json").mock(
            return_value=httpx.Response(
                401,
                text='<html>Redmine 5.1.2 — Internal stack trace: ...</html>',
            )
        )
        with pytest.raises(RedmineAPIError) as exc:
            await _redmine("GET", _session(), "/issues/1.json")
    assert exc.value.status_code == 401
    assert str(exc.value) == "Permission denied."
    # The upstream body is preserved for server logs but isn't in the message.
    assert "stack trace" not in str(exc.value)
    assert "Redmine 5.1.2" not in str(exc.value)


@pytest.mark.asyncio
async def test_redmine_404_becomes_not_found(_bypass_url_validator):
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://redmine.example.com/issues/999.json").mock(
            return_value=httpx.Response(404, text='{"error": "not found"}')
        )
        with pytest.raises(RedmineAPIError) as exc:
            await _redmine("GET", _session(), "/issues/999.json")
    assert exc.value.status_code == 404
    assert str(exc.value) == "Not found."


@pytest.mark.asyncio
async def test_redmine_422_includes_validation_errors(_bypass_url_validator):
    """422 errors are useful and not sensitive — surface them to the caller."""
    with respx.mock(assert_all_called=False) as mock:
        mock.post("https://redmine.example.com/issues.json").mock(
            return_value=httpx.Response(
                422,
                json={"errors": ["Subject cannot be blank", "Project is invalid"]},
            )
        )
        with pytest.raises(RedmineAPIError) as exc:
            await _redmine("POST", _session(), "/issues.json", json={"issue": {}})
    assert exc.value.status_code == 422
    assert "Subject cannot be blank" in str(exc.value)
    assert "Project is invalid" in str(exc.value)
    assert exc.value.validation_errors == [
        "Subject cannot be blank",
        "Project is invalid",
    ]


@pytest.mark.asyncio
async def test_redmine_5xx_redacts_upstream_body(_bypass_url_validator, caplog):
    """5xx body goes to server logs only, never to the MCP client."""
    sensitive = "INTERNAL ERROR: postgres password=hunter2 — /opt/redmine/app/..."
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://redmine.example.com/issues.json").mock(
            return_value=httpx.Response(500, text=sensitive)
        )
        with caplog.at_level("ERROR", logger="redmine_mcp.redmine"):
            with pytest.raises(RedmineAPIError) as exc:
                await _redmine("GET", _session(), "/issues.json")
    assert exc.value.status_code == 500
    assert str(exc.value) == "Upstream Redmine error."
    assert "hunter2" not in str(exc.value)
    assert "postgres" not in str(exc.value)
    # The sensitive body IS in the server log (operator can debug there).
    assert any("hunter2" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_redmine_200_returns_json(_bypass_url_validator):
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://redmine.example.com/issues/1.json").mock(
            return_value=httpx.Response(200, json={"issue": {"id": 1}})
        )
        result = await _redmine("GET", _session(), "/issues/1.json")
    assert result == {"issue": {"id": 1}}
