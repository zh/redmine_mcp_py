"""
auth/routes.py — OAuth 2.1 Authorization Code flow with mandatory PKCE (S256),
CSRF protection, registered-client redirect-URI binding, RFC 7009 revocation,
and RFC 7591 Dynamic Client Registration.

Endpoints:
  GET  /auth/authorize  — show login form (or 400 on invalid params)
  POST /auth/login      — validate Redmine creds, redirect with code
  POST /oauth/token     — exchange code for bearer token
  POST /oauth/revoke    — RFC 7009 token revocation
  POST /oauth/register  — RFC 7591 Dynamic Client Registration

Authorization codes are single-use, in-memory, and expire after CODE_TTL.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urlparse

log = logging.getLogger("redmine_mcp.auth")

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from jinja2 import Environment, FileSystemLoader, select_autoescape

from auth.store import (
    issue_token,
    purge_expired,
    revoke_token,
    validate_redmine_credentials,
)
from config import settings

router = APIRouter()

# code -> {session, expires_at, redirect_uri, code_challenge, code_challenge_method, client_id}
_pending_codes: dict[str, dict] = {}

# client_id -> {redirect_uris, created_at, metadata}
_clients: dict[str, dict] = {}

_CSRF_COOKIE_NAME = "redmine_mcp_csrf"
_CSRF_MAX_AGE = 600  # 10 min; longer than auth-code TTL is fine

_csrf_serializer = URLSafeTimedSerializer(settings.secret_key, salt="redmine-mcp-csrf")

# autoescape=True makes every {{ value }} HTML-safe.
_JINJA_ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent),
    autoescape=select_autoescape(("html",)),
)
_TEMPLATE = _JINJA_ENV.get_template("login.html")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _purge_codes(now: Optional[float] = None) -> None:
    """Drop expired auth codes to keep the dict bounded."""
    cutoff = now or time.time()
    expired = [c for c, e in _pending_codes.items() if cutoff > e["expires_at"]]
    for c in expired:
        _pending_codes.pop(c, None)


def _verify_pkce_s256(stored_challenge: str, verifier: str) -> bool:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, stored_challenge)


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def _redirect_uri_is_allowed(redirect_uri: str, client_id: str) -> bool:
    """Decide whether a redirect_uri may receive an authorization code.

    Accepted in this order:
      1. RFC 8252 loopback (http://127.0.0.1:<port>/..., localhost, ::1) — used
         by every desktop MCP client (Claude Desktop, Claude Code SDK, ...).
         The auth code lands on the victim's own machine, so this is safe and
         standard. Required to survive HF Spaces / Render cold restarts that
         wipe in-memory DCR state.
      2. Exact match against the client's registered redirect_uris (set at
         /oauth/register).
      3. Exact match against REDMINE_MCP_ALLOWED_REDIRECTS env allowlist.
    """
    if not redirect_uri:
        return False
    parsed = urlparse(redirect_uri)
    scheme = parsed.scheme.lower()
    if scheme not in ("https", "http"):
        return False

    host = (parsed.hostname or "").lower()
    if scheme == "http" and host in _LOOPBACK_HOSTS:
        return True  # RFC 8252 §7.3

    if client_id and client_id in _clients:
        return redirect_uri in _clients[client_id]["redirect_uris"]

    return redirect_uri in settings.allowed_redirects


def _issue_csrf_token() -> str:
    return _csrf_serializer.dumps(secrets.token_urlsafe(16))


def _verify_csrf_token(token: str) -> bool:
    if not token:
        return False
    try:
        _csrf_serializer.loads(token, max_age=_CSRF_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


def _client_ip(request: Request) -> str:
    if settings.trust_proxy:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
        xri = request.headers.get("x-real-ip", "")
        if xri:
            return xri.strip()
    return request.client.host if request.client else "?"


def _render_form(
    *,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    client_id: str,
    csrf_token: str,
    redmine_url: str = "",
    error: Optional[str] = None,
    status_code: int = 200,
) -> HTMLResponse:
    html = _TEMPLATE.render(
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        client_id=client_id,
        csrf_token=csrf_token,
        redmine_url=redmine_url,
        error=error,
    )
    resp = HTMLResponse(html, status_code=status_code)
    resp.set_cookie(
        _CSRF_COOKIE_NAME,
        csrf_token,
        max_age=_CSRF_MAX_AGE,
        httponly=True,
        secure=not settings.allow_http,
        samesite="lax",
        path="/auth/",
    )
    return resp


# ---------------------------------------------------------------------------
# Authorization endpoint
# ---------------------------------------------------------------------------

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
    # OAuth 2.1: only "code" is supported.
    if response_type != "code":
        return JSONResponse(
            {"error": "unsupported_response_type"}, status_code=400
        )

    # Mandatory PKCE — RFC 7636 §4, OAuth 2.1 §4.1.
    if not code_challenge:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge is required"},
            status_code=400,
        )
    # We only accept S256. "plain" was removed in OAuth 2.1.
    if code_challenge_method and code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "only S256 is supported"},
            status_code=400,
        )

    # State strongly recommended; we require non-empty to prevent CSRF on the
    # client side (the MCP client correlates state).
    if not state:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "state is required"},
            status_code=400,
        )

    # Redirect-URI must be registered (or on env allowlist for legacy clients).
    if not _redirect_uri_is_allowed(redirect_uri, client_id):
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "redirect_uri is not registered for this client",
            },
            status_code=400,
        )

    csrf_token = _issue_csrf_token()
    return _render_form(
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method="S256",
        client_id=client_id,
        csrf_token=csrf_token,
    )


# ---------------------------------------------------------------------------
# Login handler
# ---------------------------------------------------------------------------

@router.post("/auth/login")
async def login(
    request: Request,
    redmine_url: str = Form(...),
    api_key: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form(""),
    client_id: str = Form(""),
    csrf_token: str = Form(""),
):
    cookie_csrf = request.cookies.get(_CSRF_COOKIE_NAME, "")

    def _form_error(message: str, *, log_reason: str) -> HTMLResponse:
        log.warning(
            "login rejected: %s (ip=%s, client_id=%s, redirect_uri=%s)",
            log_reason,
            _client_ip(request),
            client_id or "-",
            redirect_uri or "-",
        )
        return _render_form(
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            client_id=client_id,
            csrf_token=_issue_csrf_token(),
            redmine_url=redmine_url,
            error=message,
            status_code=400,
        )

    # Anti-CSRF: form token must match cookie *and* be a valid signed token.
    if (
        not csrf_token
        or not cookie_csrf
        or not secrets.compare_digest(csrf_token, cookie_csrf)
        or not _verify_csrf_token(csrf_token)
    ):
        return _form_error(
            "Session expired. Please reload the page and try again.",
            log_reason="csrf_check_failed",
        )

    # PKCE still mandatory at this stage (the form carries it through).
    if not code_challenge:
        return _form_error(
            "Missing PKCE challenge — please restart the OAuth flow from the client.",
            log_reason="missing_pkce",
        )
    if code_challenge_method and code_challenge_method != "S256":
        return _form_error(
            "Only S256 PKCE is supported.",
            log_reason="bad_pkce_method",
        )

    # Redirect-URI must still match the registered list.
    if not _redirect_uri_is_allowed(redirect_uri, client_id):
        return _form_error(
            "This client's callback URL is not allowed. If the server restarted, "
            "restart the OAuth flow from your MCP client.",
            log_reason="redirect_uri_rejected",
        )

    session = await validate_redmine_credentials(redmine_url, api_key)
    if session is None:
        # Re-render the form with a fresh CSRF token so the user can retry.
        return _render_form(
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            client_id=client_id,
            csrf_token=_issue_csrf_token(),
            redmine_url=redmine_url,
            error="Could not authenticate with Redmine. Check the URL and API key.",
            status_code=400,
        )

    _purge_codes()
    code = secrets.token_urlsafe(24)
    _pending_codes[code] = {
        "session": session,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "expires_at": time.time() + settings.code_ttl_seconds,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    log.info(
        "login ok: login=%s ip=%s client_id=%s redirect_uri=%s",
        session.redmine_login,
        _client_ip(request),
        client_id or "-",
        redirect_uri,
    )

    params = {"code": code, "state": state}
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------

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
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "code expired"},
            status_code=400,
        )

    # redirect_uri must match the one used when the code was issued.
    if (redirect_uri or "") != entry.get("redirect_uri", ""):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
            status_code=400,
        )

    # client_id binding (informational — public client, but bind regardless).
    if entry.get("client_id") and (client_id or "") != entry["client_id"]:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "client_id mismatch"},
            status_code=400,
        )

    # PKCE: every code carries a challenge now (enforced at /auth/authorize
    # and /auth/login), so code_verifier is always required.
    stored_challenge = entry.get("code_challenge", "")
    if not stored_challenge:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "missing PKCE binding"},
            status_code=400,
        )
    if not code_verifier:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_verifier required"},
            status_code=400,
        )
    if not _verify_pkce_s256(stored_challenge, code_verifier):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE verification failed"},
            status_code=400,
        )

    access_token, expires_in = issue_token(entry["session"])
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": expires_in,
        }
    )


# ---------------------------------------------------------------------------
# Revocation (RFC 7009)
# ---------------------------------------------------------------------------

@router.post("/oauth/revoke")
async def revoke(
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
):
    # RFC 7009: respond 200 regardless of whether the token existed.
    revoke_token(token)
    purge_expired()
    return Response(status_code=200)


# ---------------------------------------------------------------------------
# Dynamic Client Registration (RFC 7591)
# ---------------------------------------------------------------------------

@router.post("/oauth/register")
async def register(request: Request):
    """Accept a public-client registration, persist redirect_uris, return a
    fresh client_id. We do not authenticate clients — Redmine API key remains
    the real credential — but we DO bind redirect_uris so that an attacker
    can't add an arbitrary redirect_uri after the fact.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    if not isinstance(body, dict):
        body = {}

    redirect_uris = body.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not all(isinstance(u, str) for u in redirect_uris):
        return JSONResponse(
            {"error": "invalid_redirect_uri", "error_description": "redirect_uris must be a list of strings"},
            status_code=400,
        )

    # Reject anything that isn't an http(s) URL.
    for u in redirect_uris:
        sch = urlparse(u).scheme.lower()
        if sch not in ("http", "https"):
            return JSONResponse(
                {"error": "invalid_redirect_uri", "error_description": f"unsupported scheme in {u}"},
                status_code=400,
            )

    client_id = secrets.token_urlsafe(16)
    now = int(time.time())
    _clients[client_id] = {
        "redirect_uris": list(redirect_uris),
        "created_at": now,
    }

    response = {
        "client_id": client_id,
        "client_id_issued_at": now,
        "token_endpoint_auth_method": "none",
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "redirect_uris": redirect_uris,
    }
    for k in ("client_name", "client_uri", "logo_uri", "scope", "contacts", "tos_uri", "policy_uri"):
        if k in body:
            response[k] = body[k]
    return JSONResponse(response, status_code=201)


# ---------------------------------------------------------------------------
# OAuth metadata
# ---------------------------------------------------------------------------

@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/auth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "revocation_endpoint": f"{base}/oauth/revoke",
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
