# Changelog

All notable changes to this project are documented here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers track the **plan-phase number** in [`TODO.md`](./TODO.md) —
each phase that lands becomes a release. The same number is exposed at runtime
via `GET /version`, on the Docker image as
`org.opencontainers.image.version`, and as the `image:` tag in
[`docker-compose.yml`](./docker-compose.yml).

## [1.7] — 2026-05-19

### Added
- **Structured audit logging** (Phase 1.7) — `audit.py` emits one-line JSON
  to stdout via stdlib `logging` (no third-party dep). Events: `login_ok`,
  `login_rejected`, `token_issued`, `token_refreshed`, `token_revoked`,
  `rate_limit_exceeded`, `redmine_call`, `redmine_call_blocked`.
- `RequestIDMiddleware` sets an 8-char hex `request_id` (or honors an
  inbound `X-Request-Id` ≤ 64 chars) on every HTTP request. The ID
  propagates via a contextvar so multiple audit lines emitted while
  handling one request share the same `request_id`.
- `X-Request-Id` header echoes on every response — pass it from your
  reverse proxy / load balancer for end-to-end tracing.
- Every outbound Redmine call now records `method`, `path`, `status`,
  `latency_ms`, and the operator `login` — never query params or payloads.
- 5 new tests covering request-ID round-trip, audit-event shape,
  end-to-end `login_ok` emission, and rate-limit log levels.

### Security
- Secrets are never passed to `audit()`. API keys are already wrapped in
  `RedactedStr`; tool-call params, form bodies, and Redmine response
  bodies are intentionally **never** part of the audit record.

## [1.6] — 2026-05-19

### Added
- **Input validation** (Phase 1.6):
  - `Literal[...]` types on enum-ish fields: `create_version.status`
    (`"open" | "locked" | "closed"`), `create_version.sharing`
    (`"none" | "descendants" | "hierarchy" | "tree" | "system"`),
    `create_issue_relation.relation_type` (the nine Redmine relation
    types). The MCP tool schema now communicates the allowed values to
    the LLM.
  - `limit` parameter is clamped to 1..100 (Redmine's hard server-side
    max) in `list_projects`, `list_issues`, `list_users`,
    `list_time_entries`, `list_memberships`, `list_queries`.
- 5 new tests for `limit` clamping and the truthiness-bug fix.

### Fixed
- `list_issues` and `list_time_entries` used `if v:` to decide whether to
  forward optional filters — silently dropping `user_id=0`, `status_id=""`,
  and other legitimately-falsy values. Switched to `if v is not None:`,
  matching the pattern already used by `create_issue` and
  `create_time_entry`.

## [1.5] — 2026-05-19

### Added
- **Structured error handling** (Phase 1.5) — new `errors.py`:
  - `RedmineAPIError` with `status_code`, `upstream_body` (server-side
    only), and `validation_errors` list.
  - `ConfirmationRequired` raised by destructive tools instead of
    returning `{"error": "..."}` dicts — a single failure surface for MCP
    clients.
- `_redmine` translates upstream HTTP errors into sanitized messages:
  - **401 / 403** → `"Permission denied."`
  - **404** → `"Not found."`
  - **422** → `"Validation failed: <Redmine's errors[] joined>"` (passed
    through; safe and useful).
  - **5xx** → `"Upstream Redmine error."` (full body logged server-side
    only).
  - Anything else → `"Redmine returned <status>."`
- 5 new tests for each status-code branch + a happy-path success case.

### Security
- Raw upstream response bodies (Redmine version banners, plugin names,
  stack traces, occasional secrets in error pages) no longer reach the
  MCP client — they go to the `redmine_mcp.redmine` logger instead, where
  the operator can inspect them.

### Changed
- All seven destructive tools (`delete_issue`, `delete_issue_relation`,
  `delete_user`, `delete_time_entry`, `delete_membership`, `delete_group`,
  `delete_version`, `delete_project`) now `raise ConfirmationRequired`
  when `confirm=True` is missing, replacing the prior `{"error": "..."}`
  return.

## [1.3] — 2026-05-19

### Added
- **Per-IP rate limiting** on the OAuth endpoints (Phase 1.3):
  - `POST /auth/login` — 5/min and 20/hour (two stacked windows).
  - `POST /oauth/token` — 10/min.
  - `POST /oauth/register` — 5/min.
- `TokenStore.incr_rate(key, window_seconds)` Protocol method:
  - In-memory: dict + `asyncio.Lock`, fixed-window.
  - Redis: atomic `INCR` + `EXPIRE NX` pipeline so the TTL pins on first
    increment (subsequent bumps don't reset the window).
- Over-limit responses return **HTTP 429** with a `Retry-After` header.
- Configurable via `REDMINE_MCP_RATE_LOGIN_PER_MIN`,
  `REDMINE_MCP_RATE_LOGIN_PER_HOUR`, `REDMINE_MCP_RATE_TOKEN_PER_MIN`,
  `REDMINE_MCP_RATE_REGISTER_PER_MIN`.
- 4 new regression tests (rate-limit hit + `incr_rate` window reset).

### Security
- Source IP for rate limiting honors `REDMINE_MCP_TRUST_PROXY`; without
  that flag set, the proxy's IP is used, so deployments behind a proxy
  must enable it or rate limits are effectively shared across all clients.

## [1.2] — 2026-05-19

### Added
- **Refresh tokens with rotation** (Phase 1.2, RFC 6749 §6):
  - `/oauth/token` (authorization_code) now returns
    `{access_token, refresh_token, token_type, expires_in}`.
  - New `grant_type=refresh_token` branch on `/oauth/token`.
  - **Rotation**: each `pop_refresh` is atomic (`GETDEL` in Redis) — a
    redeemed refresh token cannot be replayed.
  - Rolling 30-day TTL, configurable via
    `REDMINE_MCP_REFRESH_TTL_SECONDS`. Active clients stay logged in
    indefinitely; idle ones eventually need to re-auth.
- `/.well-known/oauth-authorization-server` advertises
  `grant_types_supported: ["authorization_code", "refresh_token"]`.
- 6 new regression tests for refresh-token issuance, rotation,
  single-use enforcement, and metadata.

## [1.1] — 2026-05-19

### Added
- **Pluggable token store** (Phase 1.1):
  - `auth/token_store.py` defines the `TokenStore` Protocol (sessions,
    OAuth codes, DCR clients, refresh tokens, rate counters).
  - `InMemoryTokenStore` — zero-deps default, identical to previous
    behavior.
  - `RedisTokenStore` — opt-in via `REDMINE_MCP_REDIS_URL`. Uses
    `redis.asyncio`, lazy-imported so the dep is only required when used.
- **Fernet at-rest encryption** of the user's Redmine API key when stored
  in Redis. `REDMINE_MCP_FERNET_KEY` is required when Redis is enabled.
- `/readyz` now pings the active store backend and returns **503** when
  the backend is unreachable.
- `docker-compose.yml` gained an opt-in `redis` profile with persistent
  volume + healthcheck.
- 8 new regression tests (in-memory contract + Redis contract with
  encryption verification; Redis tests opt-in via
  `REDMINE_MCP_TEST_REDIS_URL`).

### Changed
- All persistence (sessions, OAuth codes, DCR clients) migrated from
  module-level dicts to the store. `_pending_codes` and `_clients` in
  `auth/routes.py` no longer exist.
- `_session()` helper in `server.py` is now `async`; all 53 tool call
  sites updated to `await _session()`.
- FastAPI `lifespan` builds the store before serving any request and
  closes it on shutdown.
- `auth/store.py` slimmed to just `UserSession` + the credential
  validator; storage moved to `token_store.py`.

### Removed
- `auth.store.issue_token`, `lookup_token`, `revoke_token`,
  `purge_expired`, and the module-level `_sessions` dict (replaced by the
  store Protocol).

## [0.x] — 2026-05-19 — Phase 0: critical security hardening

### Security
- **0.1 SSRF via `redmine_url`** — `auth/security.validate_redmine_url`
  rejects non-`http(s)` schemes, plaintext `http://` (unless
  `REDMINE_MCP_ALLOW_HTTP=1` for dev), bare-IP hosts, and any hostname
  whose DNS resolution lands in private / loopback / link-local /
  multicast / reserved address space. Optional `REDMINE_MCP_ALLOWED_HOSTS`
  allowlist. `httpx.AsyncClient(follow_redirects=False)` prevents a 302
  bypass.
- **0.2 Open redirect on `/auth/login`** — `_redirect_uri_is_allowed`
  exact-matches `redirect_uri` against the DCR-registered list or the
  `REDMINE_MCP_ALLOWED_REDIRECTS` env allowlist. RFC 8252 loopback URIs
  (`http://127.0.0.1:*`, `localhost`, `[::1]`) are auto-allowed.
- **0.3 PKCE was optional** — now mandatory, `S256` only. The `plain`
  branch was removed.
- **0.4 Reflected XSS in the login template** — switched
  `jinja2.Template(...)` to
  `Environment(autoescape=select_autoescape(["html"]))`. Added
  `SecurityHeadersMiddleware` (CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- **0.5 Login CSRF** — short-lived signed cookie issued at
  `/auth/authorize` and embedded as a hidden form field; verified at
  `/auth/login` with `secrets.compare_digest` +
  `itsdangerous.URLSafeTimedSerializer` (`REDMINE_MCP_SECRET`).
- **0.6 Tokens never expired** — `UserSession.expires_at` defaults to 24h
  (`REDMINE_MCP_TOKEN_TTL_SECONDS`); `/oauth/token` returns `expires_in`;
  `lookup_token` prunes expired entries; new `POST /oauth/revoke` (RFC
  7009).
- **0.7 API keys visible in logs** — `RedactedStr` wrapper returns `***`
  in `repr`/`str`. `.reveal()` exposes the cleartext only for the
  outbound HTTP-header path.
- **0.8 Destructive deletes had no confirm gate** — `confirm=True`
  required by `delete_issue`, `delete_user`, `delete_group`,
  `delete_version`, `delete_time_entry`, `delete_membership`,
  `delete_issue_relation` (matching the pre-existing pattern on
  `delete_project`).
- **0.9 CVE-2025-66416** (Host-header validation bypass in `mcp<1.23.0`)
  — pinned `fastmcp>=2.11,<3` and added upper bounds to every dependency.

### Added
- `SECURITY.md` — threat model, defect-and-fix matrix, production
  checklist.
- `/healthz` and `/readyz` endpoints (Phase 3.1 brought forward).
- `Dockerfile` runs as UID 1000, exposes `${PORT:-7860}` so the same
  image works on Hugging Face Spaces, Render, Fly.io, Cloud Run, and
  self-hosted Docker (Phase 3.4 partial).
- `render.yaml` blueprint for one-click Render deployment.
- `docker-compose.yml` + `.env.example` for local dev.
- 26 security regression tests (`tests/test_security.py` and
  `tests/test_oauth_flow.py`).

### Fixed
- `/auth/login` form validation errors are re-rendered as HTML (instead
  of JSON) so users can read the error in the browser.
- CSP `form-action` now permits RFC 8252 loopback (`http://127.0.0.1:*`,
  `localhost:*`, `[::1]:*`) and any HTTPS callback — fixes the browser
  blocking the form submit's final 302 to a local MCP-client callback.
