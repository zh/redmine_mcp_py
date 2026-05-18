"""
auth/routes.py — minimal OAuth 2.1 Authorization Code flow.

Endpoints:
  GET  /auth/authorize  — show login form (or redirect with code)
  POST /auth/login      — validate Redmine creds, redirect with code
  POST /oauth/token     — exchange code for bearer token

No PKCE enforcement here to keep it simple, but you can add it.
Codes are single-use, stored in memory, expire after 5 minutes.
"""
import secrets
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Template

from auth.store import validate_redmine_credentials, issue_token, lookup_token

router = APIRouter()

# code -> {session, expires_at, redirect_uri}
_pending_codes: dict[str, dict] = {}

_TEMPLATE = Template((Path(__file__).parent / "login.html").read_text())


def _clean_url(url: str) -> str:
    """Strip trailing slash."""
    return url.rstrip("/")


@router.get("/auth/authorize", response_class=HTMLResponse)
async def authorize(
    request: Request,
    redirect_uri: str = "",
    state: str = "",
    response_type: str = "code",
    client_id: str = "",
):
    return HTMLResponse(_TEMPLATE.render(
        redirect_uri=redirect_uri,
        state=state,
        redmine_url="",
        error=None,
    ))


@router.post("/auth/login")
async def login(
    request: Request,
    redmine_url: str = Form(...),
    api_key: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
):
    session = await validate_redmine_credentials(redmine_url, api_key)
    if session is None:
        html = _TEMPLATE.render(
            redirect_uri=redirect_uri,
            state=state,
            redmine_url=redmine_url,
            error="Could not authenticate with Redmine. Check the URL and API key.",
        )
        return HTMLResponse(html, status_code=400)

    code = secrets.token_urlsafe(24)
    _pending_codes[code] = {
        "session": session,
        "redirect_uri": redirect_uri,
        "expires_at": time.time() + 300,  # 5 min
    }

    params = {"code": code}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)


@router.post("/oauth/token")
async def token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    # refresh_token not implemented — add if needed
):
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    if not code or code not in _pending_codes:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    entry = _pending_codes.pop(code)
    if time.time() > entry["expires_at"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "code expired"}, status_code=400)

    access_token = issue_token(entry["session"])
    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
        # No expiry — tokens live until server restarts or explicit revoke.
        # Add TTL + refresh tokens for production.
    })


@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/auth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": [],
    })


@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request):
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
    })
