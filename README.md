---
title: Redmine MCP
emoji: <F0><9F><94><A7>
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# Redmine MCP OAuth Server

A FastMCP HTTP server that exposes 53 Redmine REST endpoints as
Model-Context-Protocol tools, behind an OAuth 2.1 Authorization Code
flow with mandatory PKCE.

The user logs in with their **own Redmine URL + API key** — the server
holds no second account. The API key is validated against
`/users/current.json`, then mapped to a bearer token used by every
subsequent MCP tool call.

**Current version: 1.7** ([`CHANGELOG.md`](./CHANGELOG.md))

## Contents

- [Features](#features)
- [Quick start (local Docker)](#quick-start-local-docker)
- [Configuration](#configuration)
- [Deployment](#deployment)
  - [Docker Compose](#docker-compose-local-or-self-hosted)
  - [Hugging Face Spaces](#hugging-face-spaces)
  - [Render](#render)
  - [Fly.io, Cloud Run, Railway, plain VPS](#flyio-cloud-run-railway-plain-vps)
- [OAuth flow](#oauth-flow)
- [Adding the server to an MCP client](#adding-the-server-to-an-mcp-client)
- [Tools implemented](#tools-implemented)
- [Architecture](#architecture)
- [Security](#security)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [License](#license)

## Features

- **OAuth 2.1** authorization-code flow with mandatory **PKCE S256**.
- **RFC 7591 Dynamic Client Registration** so MCP clients can self-register.
- **RFC 8252 loopback redirect URIs** auto-allowed (works with every
  desktop MCP client out of the box).
- **Refresh tokens with rotation** (RFC 6749 §6) — single-use, rolling
  30-day TTL.
- **RFC 7009 revocation** at `POST /oauth/revoke`.
- **CSRF-protected login form** with `itsdangerous`-signed cookies.
- **SSRF defense** on the user-supplied Redmine URL — DNS-resolved IPs
  in private / loopback / link-local / multicast / reserved space are
  refused. `httpx.AsyncClient(follow_redirects=False)` closes 302
  bypasses.
- **Per-IP rate limiting** on `/auth/login` (5/min + 20/hour),
  `/oauth/token` (10/min), and `/oauth/register` (5/min).
- **Pluggable token store** — in-memory by default; opt-in Redis
  backend with **Fernet at-rest encryption** of API keys.
- **Structured JSON audit log** to stdout, with per-request IDs.
- **Sanitized upstream errors** — Redmine's raw response bodies (version
  banners, plugin names, occasional stack traces) never reach the MCP
  client. Just `Permission denied.` / `Not found.` /
  `Upstream Redmine error.` / parsed 422 validation errors.
- **Confirm gate** on every destructive tool (`delete_*` requires
  `confirm=True`).
- **Health & version endpoints** (`/healthz`, `/readyz`, `/version`).
- **Portable Docker image** — runs unchanged on Hugging Face Spaces
  (port 7860), Render, Fly.io, Cloud Run, and self-hosted Docker.

## Quick start (local Docker)

```bash
git clone <repo> && cd redmine_mcp_py
cp .env.example .env

# 1. Generate the secret that signs CSRF cookies
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
# Paste into .env as REDMINE_MCP_SECRET=...

# 2. (Optional) generate a Fernet key if you want Redis persistence later
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'

# 3. Run it
docker compose up --build
```

Open `http://localhost:8000/healthz` — should return `{"status": "ok"}`.
The MCP endpoint is `http://localhost:8000/mcp`.

## Configuration

All knobs are env-var-driven. Defaults are safe for local dev and
production alike, except where noted.

### Required

| Variable | Notes |
|---|---|
| `REDMINE_MCP_SECRET` | 32+ random bytes; signs CSRF cookies. Generate with `python -c 'import secrets; print(secrets.token_urlsafe(32))'`. **A fresh per-process value is auto-generated when unset**, which means restarts invalidate in-flight CSRF cookies — fine for dev, set it explicitly in production. |

### Recommended for production

| Variable | Default | Notes |
|---|---|---|
| `REDMINE_MCP_ALLOWED_HOSTS` | (empty) | CSV of Redmine hostnames the server is allowed to call. Empty = any public hostname (private/loopback IPs still blocked). The strongest SSRF defense. |
| `REDMINE_MCP_TRUST_PROXY` | `false` | Set `true` when behind a known reverse proxy (HF Spaces, Render, Caddy, nginx). Required for correct rate-limit attribution. |
| `REDMINE_MCP_REDIS_URL` | (empty) | e.g. `redis://redis:6379/0`. Enables the Redis-backed token store so sessions, codes, and rate counters survive restarts. |
| `REDMINE_MCP_FERNET_KEY` | (empty) | Required when `REDMINE_MCP_REDIS_URL` is set. Encrypts API keys at rest. Generate with `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`. |

### Token lifetimes (seconds)

| Variable | Default | Notes |
|---|---|---|
| `REDMINE_MCP_TOKEN_TTL_SECONDS` | `86400` | Access-token TTL. |
| `REDMINE_MCP_REFRESH_TTL_SECONDS` | `2592000` (30d) | Refresh-token TTL. Rolls on each use. |
| `REDMINE_MCP_CODE_TTL_SECONDS` | `300` | Authorization-code TTL. |
| `REDMINE_MCP_CLIENT_TTL_SECONDS` | `2592000` (30d) | DCR client record TTL (Redis only). |

### Rate limits (per IP)

| Variable | Default |
|---|---|
| `REDMINE_MCP_RATE_LOGIN_PER_MIN` | `5` |
| `REDMINE_MCP_RATE_LOGIN_PER_HOUR` | `20` |
| `REDMINE_MCP_RATE_TOKEN_PER_MIN` | `10` |
| `REDMINE_MCP_RATE_REGISTER_PER_MIN` | `5` |

### Other knobs

| Variable | Default | Notes |
|---|---|---|
| `REDMINE_MCP_TIMEOUT_SECONDS` | `30` | Per-call timeout for outbound Redmine HTTP. |
| `REDMINE_MCP_ALLOWED_REDIRECTS` | (empty) | CSV of OAuth `redirect_uri` values for non-loopback web MCP clients. Loopback URIs (`http://127.0.0.1:*`, `localhost:*`, `[::1]:*`) are auto-allowed per RFC 8252. |
| `REDMINE_MCP_ALLOW_HTTP` | `false` | **Dev only.** Permits `http://` Redmine URLs, bare IP hosts, and drops the `Secure` flag from the CSRF cookie (needed for plain `http://localhost`). |
| `PORT` | `7860` | Listen port. HF Spaces uses 7860; Render/Fly/Cloud Run inject their own. |

## Deployment

### Docker Compose (local or self-hosted)

`docker-compose.yml` ships with sensible local-dev defaults. Two
profiles:

```bash
# In-memory store (default profile, ephemeral)
docker compose up --build

# Redis-backed store (sessions survive restart)
docker compose --profile redis up --build
```

The Redis profile starts a sibling `redis:7-alpine` with a persistent
volume and a healthcheck. Set the corresponding env vars first:

```env
REDMINE_MCP_REDIS_URL=redis://redis:6379/0
REDMINE_MCP_FERNET_KEY=<paste-Fernet.generate_key()-output>
```

### Hugging Face Spaces

The `README.md` frontmatter (top of this file) is HF metadata; HF reads
`sdk: docker` and `app_port: 7860` and runs the bundled `Dockerfile`.

1. Push the repo to a Space with `sdk: docker`.
2. In *Settings → Variables and secrets*, set:
   - `REDMINE_MCP_SECRET` (required — generate fresh)
   - `REDMINE_MCP_TRUST_PROXY=true` (HF sits behind a proxy)
   - `REDMINE_MCP_ALLOWED_HOSTS=<your-redmine-host>` (recommended)
3. Restart the Space.

⚠ **HF Spaces free tier sleeps after 15 min idle** — cold start wipes
the in-memory token store, forcing users to reconnect. For always-on
behavior either upgrade to a paid tier or enable Redis (point
`REDMINE_MCP_REDIS_URL` at an external Redis like Upstash, since HF
doesn't provide one).

### Render

The repo includes [`render.yaml`](./render.yaml) for one-click
Blueprint deploys.

1. Push to GitHub/GitLab.
2. Render dashboard → **New +** → **Blueprint** → connect the repo →
   **Apply**.
3. In the service's *Environment* tab, fill in the two `sync: false`
   values:
   - `REDMINE_MCP_ALLOWED_HOSTS` (recommended — CSV of permitted
     Redmine hostnames)
   - `REDMINE_MCP_ALLOWED_REDIRECTS` (leave empty for desktop MCP
     clients)
4. First build takes ~3 min. You get `https://redmine-mcp-XXXX.onrender.com`.

The blueprint defaults to `plan: free`, which **sleeps after 15 min
idle** like HF. Change to `plan: starter` ($7/mo) for always-on, or
keep free and add Render's *Key Value* (Redis-compatible) addon for
persistence across cold starts.

### Fly.io, Cloud Run, Railway, plain VPS

The Dockerfile listens on `${PORT:-7860}` and runs as UID 1000 with a
baked-in `HEALTHCHECK`. It works unchanged on any platform that builds
a Dockerfile.

Minimum env vars: `REDMINE_MCP_SECRET`, `REDMINE_MCP_TRUST_PROXY=true`
(when behind a proxy), and ideally `REDMINE_MCP_ALLOWED_HOSTS`.

For self-hosted behind nginx / Caddy / Traefik, terminate TLS at the
proxy and forward to the container's `${PORT}`. Add
`proxy_set_header X-Forwarded-For $remote_addr;` (nginx) or equivalent
so rate-limit attribution works.

## OAuth flow

```
User clicks "Connect" in Claude Desktop / Coworks / custom MCP client
  ↓
GET  /oauth/register              (DCR — client registers its redirect_uri)
  ↓
GET  /auth/authorize?response_type=code
                    &client_id=<dcr-issued>
                    &redirect_uri=http://127.0.0.1:<port>/callback
                    &code_challenge=<S256(verifier)>
                    &code_challenge_method=S256
                    &state=<csrf-state>
  → server returns the HTML login form + a CSRF cookie
  ↓
POST /auth/login                  (user submits Redmine URL + API key)
  → server validates creds against /users/current.json on that URL
  → server mints a single-use auth code, 302s to redirect_uri?code=...&state=...
  ↓
POST /oauth/token                 (PKCE verification, code exchange)
  → server returns {access_token, refresh_token, token_type, expires_in}
  ↓
Every MCP tool call carries the access_token as Bearer
  → looked up in the token store → Redmine API key extracted → upstream call
  ↓
POST /oauth/token (grant_type=refresh_token) once the access token expires
  → old refresh_token consumed atomically (GETDEL in Redis), new pair issued
  ↓
POST /oauth/revoke (optional, on logout)
```

The user only ever supplies their **own Redmine credentials** — no
second account is required on the MCP server side.

## Adding the server to an MCP client

### Claude Desktop, Claude Code, Coworks, …

Settings → Connectors → **Add custom connector** → URL =
`https://your-server/mcp`.

OAuth Client ID and Secret can be left blank — the server is a public
OAuth client (`token_endpoint_auth_method: none`). The real credential
is the user's Redmine API key, captured during `/auth/login`.

### From the Anthropic API or other MCP SDKs

Use the standard MCP `streamable-http` transport pointed at
`https://your-server/mcp`. The SDK handles DCR + PKCE automatically.

## Tools implemented

All 53 tools accept structured arguments and return raw Redmine JSON
(or `{}` for `204 No Content` responses). Tools that mutate state
require their respective Redmine role/permission. Destructive `delete_*`
tools require `confirm=True`.

| Category | Tools |
|---|---|
| **Projects** | `list_projects`, `get_project`, `create_project`, `update_project`, `delete_project` |
| **Issues** | `list_issues`, `get_issue`, `create_issue`, `update_issue`, `delete_issue`, `copy_issue`, `move_issue`, `add_issue_watcher`, `remove_issue_watcher`, `get_issue_relations`, `create_issue_relation`, `delete_issue_relation`, `get_issue_journals` |
| **Users** | `list_users`, `get_user`, `create_user`, `update_user`, `delete_user` |
| **Time entries** | `list_time_entries`, `get_time_entry`, `create_time_entry`, `update_time_entry`, `delete_time_entry` |
| **Memberships** | `list_memberships`, `get_membership`, `create_membership`, `update_membership`, `delete_membership` |
| **Groups** | `list_groups`, `get_group`, `create_group`, `update_group`, `delete_group` |
| **Versions** | `list_versions`, `get_version`, `create_version`, `update_version`, `delete_version` |
| **Custom fields** | `list_custom_fields` |
| **Queries** | `list_queries` |

`limit` parameters are clamped to 1..100 (Redmine's hard server-side
max). `create_issue_relation.relation_type`, `create_version.status`,
and `create_version.sharing` use `typing.Literal` so the MCP tool
schema surfaces the allowed values to the LLM.

## Architecture

```
┌──────────────────────┐
│  MCP client          │  Claude Desktop / Coworks / custom SDK
│  (loopback callback) │
└──────────┬───────────┘
           │ HTTPS
┌──────────▼─────────────────────────────────────────────────────────────┐
│  FastAPI app (server.py)                                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  RequestIDMiddleware   →  contextvar request_id                   │  │
│  │  SecurityHeadersMiddleware → HSTS, CSP, X-Frame-Options, …        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────┐  ┌────────────────────────────────────┐   │
│  │  auth/routes.py         │  │  53 MCP tools (FastMCP)            │   │
│  │  /auth/authorize        │  │  list_issues, create_project, …    │   │
│  │  /auth/login            │  │  call _redmine() → outbound httpx  │   │
│  │  /oauth/token           │  │  with SSRF re-validation + audit   │   │
│  │  /oauth/revoke          │  │                                    │   │
│  │  /oauth/register        │  │                                    │   │
│  └─────────────┬───────────┘  └────────────┬───────────────────────┘   │
│                │                           │                           │
│  ┌─────────────▼───────────────────────────▼───────────────────────┐   │
│  │  auth/token_store.py — TokenStore Protocol                      │   │
│  │  ┌─────────────────────┐    ┌────────────────────────────────┐  │   │
│  │  │ InMemoryTokenStore  │ OR │ RedisTokenStore                │  │   │
│  │  │ (default)           │    │ (Fernet-encrypted API keys)    │  │   │
│  │  └─────────────────────┘    └────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  audit.py — one-line JSON to stdout                             │   │
│  │  login_ok / login_rejected / token_issued / token_refreshed /   │   │
│  │  token_revoked / rate_limit_exceeded / redmine_call             │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
                                            │
                                            │ httpx, follow_redirects=False
                                            ▼
                              ┌───────────────────────────────┐
                              │  User's Redmine instance      │
                              │  X-Redmine-API-Key: <secret>  │
                              └───────────────────────────────┘
```

Key invariants:

- API keys are wrapped in `RedactedStr` (returns `'***'` from `repr`/
  `str`); they only reach the outbound HTTP path via `.reveal()`.
- Every outbound URL is re-validated against the SSRF block-list on
  every call, not just at login.
- The CSRF cookie is `HttpOnly`, `SameSite=Lax`, `Secure` (unless
  `REDMINE_MCP_ALLOW_HTTP=true`), path-scoped to `/auth/`.
- Audit records never contain API keys, query params, request bodies,
  or response bodies — only method, path, status, latency, and the
  operator's Redmine login.

## Security

[`SECURITY.md`](./SECURITY.md) documents the threat model, every
defect found during the Phase 0 review, the fix, and the regression
test that pins it.

Vulnerabilities should be reported privately to the maintainer rather
than as a public GitHub issue.

## Testing

```bash
pip install -r requirements.txt
pip install pytest pytest-asyncio respx
pytest
```

Currently **60 tests** covering Phase 0 + Phase 1 (~2s on a laptop)
plus 2 opt-in Redis tests, run with:

```bash
docker run --rm -d -p 6379:6379 --name redis-test redis:7-alpine
REDMINE_MCP_TEST_REDIS_URL=redis://localhost:6379/15 pytest
docker stop redis-test
```

## Roadmap

[`TODO.md`](./TODO.md) tracks remaining work. Phase 0 (critical
security) and Phase 1 (high-priority hardening) are complete. Phase 2
(reliability + code quality: modularization, shared httpx client,
retries, CI, ruff/mypy) and Phase 3 (operability: Prometheus metrics,
pydantic-settings, multi-stage Dockerfile) are the next chunks.

## License

[MIT](./LICENSE)
