# TODO — remaining work

**Current version: 1.7** — see [`CHANGELOG.md`](./CHANGELOG.md) for the
release history, [`SECURITY.md`](./SECURITY.md) for the threat model and
the Phase 0 defect-and-fix matrix.

This document tracks everything from the original review plan that is
still open or partial, grouped by phase. Items inside a phase are roughly
in dependency / priority order.

Legend: `[ ]` not started · `[~]` partial · `[x]` done (kept for context)

Done so far:
- **Phase 0** (0.1 – 0.9): critical security hardening — complete
- **Phase 1** (1.1 – 1.7): all of high-priority hardening — complete
  - 1.1 pluggable TokenStore (in-memory + Redis with Fernet)
  - 1.2 refresh tokens with rotation
  - 1.3 per-IP rate limiting on auth endpoints
  - 1.4 security headers (brought forward into Phase 0)
  - 1.5 structured error handling (RedmineAPIError + ConfirmationRequired)
  - 1.6 input validation (Literal types, limit clamp, truthiness bug fix)
  - 1.7 structured JSON audit logging + request-ID middleware

---

## Phase 1 — High-priority hardening

### 1.1 Pluggable token store (Redis-ready, in-memory default) `[x]`
**Files:** `auth/token_store.py`, `auth/token_store_redis.py`, `config.py`

Done. `TokenStore` Protocol covers sessions, OAuth codes, and DCR clients.
`InMemoryTokenStore` is the zero-deps default; `RedisTokenStore` activates
when `REDMINE_MCP_REDIS_URL` is set and uses `cryptography.Fernet` with
`REDMINE_MCP_FERNET_KEY` to encrypt the API key field at rest. `_pending_codes`
and `_clients` were both migrated to the store. `/readyz` pings the active
backend (no-op for in-memory, real PING for Redis) and returns 503 on failure.
`docker-compose.yml` gained an opt-in `redis` profile.

### 1.2 Refresh tokens (RFC 6749 §6) `[x]`
**Files:** `auth/routes.py`, `auth/token_store.py`

Done. `/oauth/token` (authorization_code) now returns
`{access_token, refresh_token, expires_in, token_type}`. Refresh tokens have
a rolling 30-day TTL (`REDMINE_MCP_REFRESH_TTL_SECONDS`) and are **rotated**
on every use via `pop_refresh` (atomic GETDEL in Redis): redeeming one
invalidates it and issues a brand-new one, so a leaked refresh token is
good for at most one use. Metadata advertises both grant types.

### 1.3 Rate limiting `[x]`
**Files:** `auth/routes.py`, `auth/token_store.py`, `config.py`

Done. Hand-rolled fixed-window counter via the TokenStore protocol (atomic
INCR + EXPIRE NX in Redis, dict + asyncio.Lock in memory). Limits configurable
via `REDMINE_MCP_RATE_*` env vars; defaults: `/auth/login` 5/min + 20/hour,
`/oauth/token` 10/min, `/oauth/register` 5/min. Source IP honors
`REDMINE_MCP_TRUST_PROXY`. Over-limit responses return 429 with `Retry-After`.

### 1.4 Security headers + HSTS `[x]`
Brought forward into Phase 0; see `SECURITY.md`.

### 1.5 Structured error handling for MCP tools `[x]`
**Files:** `errors.py`, `server.py` (`_redmine` helper)

Done. `_redmine` translates `httpx` non-2xx responses into a `RedmineAPIError`
with a short, sanitized message (401/403 → "Permission denied"; 404 → "Not
found"; 422 → validation errors; 5xx → "Upstream Redmine error"). Raw
upstream body kept on the exception for server logs only. All seven
destructive `delete_*` tools now raise `ConfirmationRequired` when
`confirm=True` is missing instead of returning an error dict.

### 1.6 Input validation `[x]`
**Files:** `server.py`

Done. `Literal` types pin allowed values for `create_version.status`,
`create_version.sharing`, and `create_issue_relation.relation_type`.
`_clamp_limit` enforces 1..100 on every `list_*` tool. The truthiness
bug in `list_issues` and `list_time_entries` (which dropped `user_id=0`
and `status_id=""`) was fixed — `if v is not None:` everywhere.

### 1.7 Audit logging `[x]`
**File:** `audit.py`, wired into `auth/routes.py` and `server.py`

Done. `audit.py` provides `audit(event, **fields)` which emits one-line
JSON to stdout via stdlib `logging` (no third-party formatter dep).
`RequestIDMiddleware` sets an 8-char hex `request_id` per request (or
honors a trimmed inbound `X-Request-Id` ≤ 64 chars) and echoes
`X-Request-Id` on every response. Events: `login_ok`, `login_rejected`,
`token_issued`, `token_refreshed`, `token_revoked`,
`rate_limit_exceeded`, `redmine_call`, `redmine_call_blocked`. Tool params
and payloads are never logged.

---

## Phase 2 — Reliability & code quality

### 2.1 Modularize `server.py` `[ ]`
**Files:** `server.py` → `tools/{projects,issues,users,time_entries,
memberships,groups,versions,custom_fields,queries}.py`

596-line file with 53 tools is hard to review and impossible to test in
isolation. Each module exposes a `register(mcp)` function. `server.py`
becomes the composition root that does only: FastAPI setup, middleware,
auth wiring, tool-module registration.

### 2.2 Shared `httpx.AsyncClient` `[ ]`
**File:** `server.py` (`_redmine` helper)

Creating a fresh `AsyncClient` per call defeats connection pooling and TLS
session reuse. Build one client per process via FastAPI's `lifespan`
(already wired for FastMCP), inject through a small dependency.

### 2.3 Retry + timeout policy `[~]`
**File:** `_redmine` helper, `config.py`

- Configurable timeout: **done** (`REDMINE_MCP_TIMEOUT_SECONDS`).
- **Still to do:** retry on connection errors and 502/503/504 with
  exponential backoff (3 attempts, jitter). Hand-rolled or
  `httpx-retries`.
- Distinct connect timeout (5s) so a black-holed host fails fast.

### 2.4 Test suite expansion + CI `[~]`
- **Done:** 26 security + OAuth-flow regression tests
  (`tests/test_security.py`, `tests/test_oauth_flow.py`).
- **Still to do:**
  - Unit test every tool's request shaping + response handling using
    `respx` to mock httpx.
  - GitHub Actions workflow running `pytest`, `ruff`, `mypy --strict`,
    `bandit -r .` on every PR.
  - Coverage target: 80% line, 100% on `auth/`.

### 2.5 Lint / format / typecheck `[ ]`
**Files:** new `pyproject.toml`, new `.pre-commit-config.yaml`

- `ruff` (covers black + isort + flake8 + pyupgrade).
- `mypy --strict` on `auth/`, `server.py`, `config.py`.
- `bandit` for security smells (catches `requests` without timeout, weak
  crypto, etc.).
- Pre-commit hooks so all of the above run locally.

### 2.6 Pydantic models for tool I/O `[ ]`
**File:** every tool in `server.py`

Replace loose `dict` returns with Pydantic models. Benefits: better LLM
introspection of the tool schema, server-side validation of Redmine
responses (catches API drift), IDE autocomplete for downstream consumers.

Start with the highest-traffic tools: `list_issues`, `get_issue`,
`create_issue`. The rest can follow opportunistically.

---

## Phase 3 — Operability

### 3.1 Health / readiness endpoints `[x]` (partial)
- `/healthz` and `/readyz` exist (`server.py`).
- **Still to do:** `/readyz` should actually check the token-store backend
  (no-op for in-memory, ping for Redis) once Phase 1.1 lands.

### 3.2 Metrics `[ ]`
**File:** new `metrics.py`, `server.py`

- `prometheus-fastapi-instrumentator` for default HTTP metrics.
- Custom counters/histograms: `redmine_mcp_tool_calls_total{tool,outcome}`,
  `redmine_mcp_login_attempts_total{outcome}`, `redmine_mcp_redmine_request_duration_seconds{status}`.
- Gate behind `REDMINE_MCP_METRICS=true` so it doesn't show up by default.
- Document scraping setup for Render (use the service URL +
  `/metrics`; consider basic-auth protection).

### 3.3 Config object polish `[~]`
**File:** `config.py`

- **Done:** central `Settings` dataclass reading from env (`config.py`).
- **Still to do:**
  - Migrate to `pydantic-settings` for type-coerced parsing, `.env` file
    support, and automatic docs.
  - Fail fast at startup if `REDMINE_MCP_SECRET` is missing in production
    mode (detect via env `RENDER_SERVICE_ID` / `FLY_APP_NAME` etc., or an
    explicit `REDMINE_MCP_ENV=production` flag).
  - `REDMINE_MCP_FERNET_KEY` validation once Phase 1.1 needs it.

### 3.4 Dockerfile polish `[~]`
**File:** `Dockerfile`

- **Done:** non-root `app` user, `HEALTHCHECK`, `PORT`-aware via
  `${PORT:-7860}`.
- **Still to do:**
  - Multi-stage build to drop pip cache and any build-time deps.
  - Pin base image by digest (`python:3.12-slim@sha256:...`) so a base
    re-tag can't change behavior.
  - Add `.dockerignore` rules for `tests/`, `.git/`, `*.md` to shrink the
    build context.

### 3.5 Docs `[~]`
- **Done:** `SECURITY.md`, `TODO.md`, `render.yaml`.
- **Still to do:**
  - Update `README.md` to point at `SECURITY.md` and the env-var table.
  - Add an end-to-end deployment walkthrough (Render today; Fly.io and
    self-hosted as appendices).
  - Add a `CHANGELOG.md` once the first non-security PR lands.

---

## Cross-cutting nice-to-haves

These don't belong to any single phase but were noted during the review:

- **Consistent return shapes.** `get_issue_journals` returns
  `{"journals": [...]}` while every other `get_*` returns the raw Redmine
  response. Pick one (probably "raw") and be uniform — Pydantic models
  (2.6) make this enforceable.
- **Avoid the extra round-trip in `get_issue_journals`** — could just call
  `get_issue(include="journals")` from the client side and let the caller
  pick fields. If kept, document it as a convenience wrapper.
- **DCR garbage collection.** `_clients` in `auth/routes.py` grows
  unbounded — every `/oauth/register` adds an entry. Add a TTL and a
  periodic purge once persistence lands (Phase 1.1).
- **Per-tool scopes.** OAuth scopes are stubbed (`["redmine"]`). If
  multi-user deployments take off, define real scopes (`read`, `write`,
  `admin`) and gate destructive tools (`delete_*`, `update_user`,
  `delete_group`) behind `admin`.

---

## Suggested execution order

**Sprint A (durability):** 1.1 (Redis store) → 1.2 (refresh tokens) →
1.3 (rate limiting). Unblocks production for any non-trivial user count.

**Sprint B (quality):** 2.4 (CI + tool tests) → 2.5 (lint/typecheck) →
1.5 (structured errors) → 1.6 (input validation). Reduces accidental
regressions and tightens the contract LLMs see.

**Sprint C (observability):** 1.7 (audit log) → 3.2 (metrics) →
3.3 (config polish). Needed before you have real traffic to debug.

**Opportunistic:** 2.1 (modularize), 2.6 (Pydantic models), 3.4
(Dockerfile polish), 3.5 (docs). No blockers; do during downtime or when
touching the relevant code.
