"""
auth/routes.py — minimal OAuth 2.1 Authorization Code flow with PKCE
and RFC 7591 Dynamic Client Registration.

Endpoints:
  GET  /auth/authorize  — show login form (or redirect with code)
  POST /auth/login      — validate Redmine creds, redirect with code
  POST /oauth/token     — exchange code for bearer token
  POST /oauth/register  — RFC 7591 Dynamic Client Registration (stub)

Codes are single-use, stored in memory, expire after 5 minutes.
"""
import base64
import hashlib
import secrets
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Template

from auth.store import validate_redmine_credentials, issue_token

router = APIRouter()

# code -> {session, expires_at, redirect_uri, code_challenge, code_challenge_method}
_pending_codes: dict[str, dict] = {}

_TEMPLATE = Template((Path(__file__).parent / "login.html").read_text())


def _verify_pkce(stored_challenge: str, stored_method: str, verifier: str) -> bool:
    if stored_method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return secrets.compare_digest(computed, stored_challenge)
    if stored_method == "plain":
        return secrets.compare_digest(verifier, stored_challenge)
    return False


@router.get("/auth/authorize", response_class=HTMLResponse)
async def authorize(
    request: Request,
    redirect_uri: str = "",
    state: str = "",
    response_type: str = "code",
    client_id: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "",
):
    return HTMLResponse(_TEMPLATE.render(
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
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
    code_challenge: str = Form(""),
    code_challenge_method: str = Form(""),
):
    session = await validate_redmine_credentials(redmine_url, api_key)
    if session is None:
        html = _TEMPLATE.render(
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            redmine_url=redmine_url,
            error="Could not authenticate with Redmine. Check the URL and API key.",
        )
        return HTMLResponse(html, status_code=400)

    code = secrets.token_urlsafe(24)
    _pending_codes[code] = {
        "session": session,
        "redirect_uri": redirect_uri,
        "expires_at": time.time() + 300,  # 5 min
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method or ("S256" if code_challenge else ""),
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
    code_verifier: Optional[str] = Form(None),
):
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    if not code or code not in _pending_codes:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    entry = _pending_codes.pop(code)
    if time.time() > entry["expires_at"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "code expired"}, status_code=400)

    stored_challenge = entry.get("code_challenge", "")
    if stored_challenge:
        if not code_verifier:
            return JSONResponse({"error": "invalid_request", "error_description": "code_verifier required"}, status_code=400)
        if not _verify_pkce(stored_challenge, entry.get("code_challenge_method", "S256"), code_verifier):
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

    access_token = issue_token(entry["session"])
    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
    })


@router.post("/oauth/register")
async def register(request: Request):
    """RFC 7591 Dynamic Client Registration.

    We don't actually authenticate clients — the real authentication is the
    user's Redmine API key, captured during /auth/login. So we accept any
    registration request, mint a synthetic client_id, and echo the metadata
    back. This is enough to satisfy MCP clients (e.g. the Claude Code SDK)
    that demand RFC 7591 before they will start the OAuth flow.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    client_id = secrets.token_urlsafe(16)
    response = {
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "token_endpoint_auth_method": "none",
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "redirect_uris": body.get("redirect_uris", []),
    }
    for k in ("client_name", "client_uri", "logo_uri", "scope", "contacts", "tos_uri", "policy_uri"):
        if k in body:
            response[k] = body[k]
    return JSONResponse(response, status_code=201)


@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/auth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request):
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
    })
