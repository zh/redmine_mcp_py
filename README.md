---
title: Redmine MCP
emoji: 🔧
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# Redmine MCP OAuth Server

Python FastMCP HTTP server wrapping the Redmine REST API as MCP tools,
with a minimal OAuth 2.1 Authorization Code flow backed by Redmine API key validation (Option B).

## Auth flow

```
User clicks "Connect" in Coworks/Claude Desktop
  → GET /auth/authorize  (shows form)
  → POST /auth/login     (validates Redmine URL + API key, issues code)
  → POST /oauth/token    (exchanges code for bearer token)
  → Bearer token stored server-side, mapped to per-user Redmine creds
  → Every MCP tool call uses that token to look up credentials
```

No second account. User only needs their Redmine credentials.

## Setup

```bash
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8000
```

For HTTPS (required by Coworks custom connectors):

```bash
uvicorn server:app --host 0.0.0.0 --port 8000 \
  --ssl-keyfile key.pem --ssl-certfile cert.pem
```

Or put it behind nginx/caddy with TLS termination.

## Add to Claude Desktop / Coworks

Settings → Connectors → Add custom connector → `https://your-server/mcp`

OAuth Client ID and Secret can be left blank (public client, no secret needed
with this implementation).

## Tools implemented (53 Redmine API endpoints)

- Projects: list, get, create, update, delete
- Issues: list, get, create, update, delete, watchers, relations, journals, copy, move
- Users: list, get, create, update, delete
- Time Entries: list, get, create, update, delete
- Memberships: list, get, create, update, delete
- Groups: list, get, create, update, delete
- Versions: list, get, create, update, delete
- Custom Fields: list
- Queries: list

## Production notes

- Token store is in-memory — tokens lost on restart. Replace `auth/store.py`
  `_sessions` dict with Redis or a DB for persistence.
- Add token expiry + refresh tokens if needed.
- Rate-limit `/auth/login` and `/oauth/token` endpoints.
- Pin `mcp>=1.23.0` to avoid CVE-2025-66416 (Host header validation).
