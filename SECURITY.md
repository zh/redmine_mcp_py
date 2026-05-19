# Security

This document summarizes the threat model of the Redmine MCP server, the
vulnerabilities found during the initial security review, the fixes shipped in
Phase 0, and the operational requirements for running the server safely.

## Reporting a vulnerability

If you believe you've found a security issue, please email the maintainer
**privately** (do not open a public GitHub issue). Include reproduction steps
and the commit hash you tested against. A fix or mitigation will be
acknowledged within 5 working days.

## Threat model

The server is a **public, internet-facing OAuth 2.1 resource** that:

1. Accepts a user-supplied Redmine URL and API key over an HTML login form.
2. Validates that pair against `GET /users/current.json` on the supplied URL.
3. Mints a bearer token and stores the API key in process memory, mapped to
   the token.
4. Forwards every subsequent MCP tool call to the same URL, using the stored
   API key as `X-Redmine-API-Key`.

Two attacker capabilities dominate the risk model:

- **SSRF / credential exfiltration.** Without input validation, the
  attacker controls the outbound URL and can make the server's HTTP client
  hit internal addresses (cloud metadata, private services, localhost). The
  API key the user typed gets sent along.
- **OAuth flow hijack.** A combination of optional PKCE, no CSRF
  protection, and an open redirect on the consent screen lets an attacker
  capture a victim's authorization code and trade it for a bearer token
  bound to the victim's Redmine account.

Everything in Phase 0 below targets one of these two capabilities, plus
defense-in-depth hardening.

## Issues found and fixed (Phase 0)

| # | Issue | Severity | File(s) | Fix |
|---|-------|----------|---------|-----|
| 0.1 | **SSRF via `redmine_url`.** The form accepted any URL; the server then hit it with the user's API key. An attacker could point it at `http://169.254.169.254/` (cloud metadata), `http://127.0.0.1:6379/`, or any RFC1918 address. | **Critical** | `auth/store.py`, `server.py` | New `auth/security.validate_redmine_url`: scheme must be `https` (or `http` only when `REDMINE_MCP_ALLOW_HTTP=1`), hostname is resolved and every returned IP is rejected if private / loopback / link-local / multicast / reserved / unspecified. Bare IP literals rejected by default. Optional `REDMINE_MCP_ALLOWED_HOSTS` allowlist. Re-validated on every outbound call. `httpx` configured with `follow_redirects=False` so a 302 cannot bypass the check. |
| 0.2 | **Open redirect on `/auth/login`.** `redirect_uri` was taken straight from the form. After successful auth the server happily forwarded the authorization code to any URL — one-click code theft. | **Critical** | `auth/routes.py` | `/oauth/register` now persists `redirect_uris` per client. `/auth/authorize` and `/oauth/token` exact-match the supplied `redirect_uri` against the registered list (or the env-configured `REDMINE_MCP_ALLOWED_REDIRECTS` allowlist for legacy clients). Mismatch → HTTP 400, no form rendered. |
| 0.3 | **Optional PKCE.** Public client (`token_endpoint_auth_method: none`) without enforced PKCE: a leaked or stolen code is redeemable. The legacy `plain` PKCE method was also accepted, which is deprecated by OAuth 2.1. | **High** | `auth/routes.py` | `code_challenge` is now mandatory at `/auth/authorize` and `/auth/login`. Only `S256` is accepted. `/oauth/token` always demands `code_verifier`. The `plain` branch was deleted. |
| 0.4 | **Stored-via-reflection XSS in the login template.** `jinja2.Template(...)` does **not** autoescape by default. `redirect_uri`, `state`, `code_challenge`, and `redmine_url` came from request inputs and were interpolated raw into HTML and `value="..."` attributes. | **High** | `auth/routes.py`, `auth/login.html` | Switched to `jinja2.Environment(autoescape=select_autoescape(("html",)))`. A baseline of security headers (CSP, HSTS, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) is now applied to every response by `SecurityHeadersMiddleware` in `server.py`. |
| 0.5 | **Login CSRF.** No anti-CSRF token on `POST /auth/login`. A malicious site could submit the form in the victim's browser, logging the victim into the *attacker's* Redmine account. `state` was echoed but not bound to anything server-side. | **High** | `auth/routes.py`, `auth/login.html` | `/auth/authorize` issues a short-lived (`HttpOnly`, `SameSite=Lax`, `Secure` when not in dev) signed CSRF cookie. The same value is embedded in the form as a hidden field. `/auth/login` requires both, compares them with `secrets.compare_digest`, and verifies the signature via `itsdangerous.URLSafeTimedSerializer`. `state` is also required and non-empty. |
| 0.6 | **Tokens never expired.** Bearer tokens lived for the lifetime of the process. No revocation endpoint. A leaked token (logs, browser history, debug dump) was indefinitely valid. | **High** | `auth/store.py`, `auth/routes.py` | `UserSession.expires_at` defaults to 24h (configurable via `REDMINE_MCP_TOKEN_TTL_SECONDS`). `lookup_token` returns `None` for expired sessions and prunes them lazily. `/oauth/token` returns `expires_in`. New `POST /oauth/revoke` implements RFC 7009. `purge_expired()` is callable for a background sweep. Authorization codes have an independent TTL (`REDMINE_MCP_CODE_TTL_SECONDS`, default 300s) and are GC'd on every code issuance. |
| 0.7 | **API key visible in `repr`/`str`.** The `UserSession` dataclass had a plain `redmine_api_key` field. Any accidental `logger.info(session)` or unhandled-exception traceback would leak the cleartext key. | **Medium** | `auth/store.py`, `auth/security.py` | API keys are wrapped in a `RedactedStr` subclass whose `__repr__` and `__str__` return `***`. The underlying value is intact for `.encode()`, slicing, and an explicit `.reveal()` used by the outbound HTTP path. `UserSession.__repr__` also redacts. |
| 0.8 | **Destructive deletes had no confirm gate.** Only `delete_project` required `confirm=True`. `delete_issue`, `delete_user`, `delete_group`, `delete_version`, `delete_time_entry`, `delete_membership`, `delete_issue_relation` would execute on first call — high-risk surface for an LLM-driven tool client. | **Medium** | `server.py` | Every destructive tool now requires `confirm=True`. Without it, the tool returns `{"error": "Set confirm=true to delete the ..."}`. |
| 0.9 | **Dependencies unpinned for CVE-2025-66416** (Host-header validation bypass in `mcp` < 1.23.0). Upper bounds also missing — accidental major upgrades would silently regress. | **Medium** | `requirements.txt` | Pinned `fastmcp>=2.11,<3` (ships `mcp>=1.23.0`). Added upper bounds to every dependency. |

In addition, **HTTP security headers** that would normally appear in a Phase 1
hardening pass were brought forward and apply to every response:

- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: ()`

## Regression test coverage

Every Phase 0 fix is pinned by a regression test in `tests/test_security.py`
and `tests/test_oauth_flow.py`. Treat any failure of those tests as a
launch-blocker — they encode attacker capabilities, not implementation
details. Run them with:

```bash
pytest
```

(26 tests, ~2s on a laptop.)

## Production checklist

Before deploying to production, set the following environment variables:

| Variable | Required? | Default | Purpose |
|----------|-----------|---------|---------|
| `REDMINE_MCP_SECRET` | **Yes (prod)** | random per-process | Signs CSRF cookies. Without a fixed value, every restart invalidates in-flight logins. Use at least 32 random bytes. |
| `REDMINE_MCP_ALLOWED_HOSTS` | Recommended | (empty = no allowlist) | CSV of permitted Redmine hostnames. If set, no other hostname is accepted by the SSRF validator — strongest defense. |
| `REDMINE_MCP_ALLOWED_REDIRECTS` | Recommended | (empty) | CSV of permitted OAuth `redirect_uri` values for unregistered clients. Leave empty if you only support clients that register via RFC 7591. |
| `REDMINE_MCP_TOKEN_TTL_SECONDS` | No | `86400` | Access-token lifetime. Lower for high-sensitivity deployments. |
| `REDMINE_MCP_CODE_TTL_SECONDS` | No | `300` | Authorization-code lifetime. Don't raise above 600. |
| `REDMINE_MCP_TIMEOUT_SECONDS` | No | `30` | Per-call timeout for outbound Redmine HTTP. |
| `REDMINE_MCP_TRUST_PROXY` | Conditional | `false` | Set to `true` ONLY when running behind a known reverse proxy. Enables reading `X-Forwarded-For` for source-IP logging. |
| `REDMINE_MCP_ALLOW_HTTP` | No | `false` | Permits plaintext `http://` and bare-IP Redmine URLs. **Dev only.** Never enable in production. |

## Known limitations (next phases)

These are documented and tracked; none of them lets an attacker capture
credentials, but they affect durability and operability:

- **In-memory session and code store.** Tokens are lost on restart, and the
  server cannot scale horizontally. Phase 1.1 will introduce a pluggable
  `TokenStore` with a Redis backend and Fernet encryption at rest.
- **No refresh tokens.** Long-running MCP clients must re-authenticate
  every `TOKEN_TTL_SECONDS`. Phase 1.2.
- **No rate limiting.** `/auth/login`, `/oauth/token`, and `/oauth/register`
  are all unmetered. Phase 1.3.
- **No structured upstream error handling.** A 5xx from Redmine surfaces as
  a raw `httpx.HTTPStatusError`, leaking response bodies. Phase 1.5.
- **No audit log.** Login attempts, token issuance, and tool calls are not
  recorded. Phase 1.7.

See the Phase 1–3 plan in `/Users/stoyan/.claude/plans/` (or the
project-local roadmap, if you've copied it in) for the full sequencing.

## Out of scope

This server **does not** attempt to:

- Authenticate the MCP client itself. The Redmine API key is the credential;
  the OAuth layer just maps a bearer token to the key.
- Defend Redmine. If the user has admin in Redmine and asks the LLM to
  delete a project, the LLM can do so (with `confirm=True`). Use Redmine
  roles/permissions to scope what an API key can do.
- Encrypt traffic. Run behind a TLS-terminating proxy (Caddy, nginx,
  Cloudflare, HF Spaces' built-in TLS) or use uvicorn's `--ssl-*` flags.
