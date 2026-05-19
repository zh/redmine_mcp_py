"""
server.py — FastMCP HTTP server wrapping Redmine REST API.

Auth flow (Option B):
  1. User hits /auth/authorize, fills Redmine URL + API key
  2. Credentials validated against /users/current.json
  3. Code issued → exchanged for bearer token
  4. Every MCP tool call carries that token → looked up to get per-user Redmine creds

Run:
  uvicorn server:app --host 0.0.0.0 --port 8000
"""
import httpx
from typing import Any, Optional

from fastapi import FastAPI
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_access_token
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from auth.security import (
    InvalidRedmineURL,
    SECURITY_HEADERS,
    validate_redmine_url,
)
from auth.store import lookup_token, UserSession
from auth.routes import router as auth_router
from config import settings


# ---------------------------------------------------------------------------
# Token verifier — bridges our simple store to FastMCP's auth interface
# ---------------------------------------------------------------------------

class RedmineTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> Optional[AccessToken]:
        session = lookup_token(token)
        if session is None:
            return None
        return AccessToken(
            token=token,
            client_id="redmine",
            scopes=["redmine"],
        )


# ---------------------------------------------------------------------------
# FastMCP instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="Redmine MCP",
    auth=RedmineTokenVerifier(),
)


# ---------------------------------------------------------------------------
# Auth helper — pulls the bearer token out of the current request and
# resolves it to a UserSession from our in-memory store.
# ---------------------------------------------------------------------------

def _session() -> UserSession:
    token = get_access_token()
    if token is None:
        raise PermissionError("Not authenticated")
    session = lookup_token(token.token)
    if session is None:
        raise PermissionError("Session not found")
    return session


# ---------------------------------------------------------------------------
# Redmine HTTP helper — per-request, uses token-bound credentials
# ---------------------------------------------------------------------------

async def _redmine(
    method: str,
    session: UserSession,
    path: str,
    params: dict = None,
    json: dict = None,
) -> Any:
    # Defense-in-depth: re-validate the stored base URL on every call so a
    # session minted under older / looser code can't continue exfiltrating.
    try:
        safe_base = validate_redmine_url(session.redmine_url)
    except InvalidRedmineURL as e:
        raise PermissionError(f"Refusing outbound call: {e}") from e

    url = f"{safe_base}{path}"
    headers = {
        "X-Redmine-API-Key": session.redmine_api_key.reveal(),
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(
        timeout=settings.redmine_timeout_seconds,
        follow_redirects=False,
    ) as client:
        resp = await client.request(method, url, headers=headers, params=params, json=json)
    resp.raise_for_status()
    if resp.content:
        return resp.json()
    return {}


# ---------------------------------------------------------------------------
# Tools — Projects
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_projects(
    limit: int = 25,
    offset: int = 0,
    status: Optional[str] = None,
    include: Optional[str] = None,
) -> dict:
    """List all accessible Redmine projects."""
    s = _session()
    p = {"limit": limit, "offset": offset}
    if status: p["status"] = status
    if include: p["include"] = include
    return await _redmine("GET", s, "/projects.json", params=p)


@mcp.tool()
async def get_project(id: str, include: Optional[str] = None) -> dict:
    """Get a specific Redmine project by ID or identifier."""
    s = _session()
    p = {"include": include} if include else {}
    return await _redmine("GET", s, f"/projects/{id}.json", params=p)


@mcp.tool()
async def create_project(
    name: str,
    identifier: str,
    description: Optional[str] = None,
    is_public: bool = True,
    parent_id: Optional[int] = None,
    inherit_members: bool = False,
) -> dict:
    """Create a new Redmine project."""
    s = _session()
    body: dict = {"name": name, "identifier": identifier, "is_public": is_public, "inherit_members": inherit_members}
    if description: body["description"] = description
    if parent_id: body["parent_id"] = parent_id
    return await _redmine("POST", s, "/projects.json", json={"project": body})


@mcp.tool()
async def update_project(id: str, updates: dict[str, Any]) -> dict:
    """Update an existing Redmine project (partial update). `updates` is a dict of fields to change."""
    s = _session()
    return await _redmine("PUT", s, f"/projects/{id}.json", json={"project": updates})


@mcp.tool()
async def delete_project(id: str, confirm: bool = False) -> dict:
    """Delete a Redmine project. confirm must be true."""
    if not confirm:
        return {"error": "Set confirm=true to delete the project."}
    s = _session()
    return await _redmine("DELETE", s, f"/projects/{id}.json")


# ---------------------------------------------------------------------------
# Tools — Issues
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_issues(
    project_id: Optional[str] = None,
    tracker_id: Optional[int] = None,
    status_id: Optional[str] = None,
    assigned_to_id: Optional[int] = None,
    query_id: Optional[int] = None,
    sort: Optional[str] = None,
    limit: int = 25,
    offset: int = 0,
    include: Optional[str] = None,
) -> dict:
    """List Redmine issues with filtering and pagination."""
    s = _session()
    p: dict = {"limit": limit, "offset": offset}
    if project_id: p["project_id"] = project_id
    if tracker_id: p["tracker_id"] = tracker_id
    if status_id: p["status_id"] = status_id
    if assigned_to_id: p["assigned_to_id"] = assigned_to_id
    if query_id: p["query_id"] = query_id
    if sort: p["sort"] = sort
    if include: p["include"] = include
    return await _redmine("GET", s, "/issues.json", params=p)


@mcp.tool()
async def get_issue(issue_id: int, include: Optional[str] = None) -> dict:
    """Get a specific Redmine issue."""
    s = _session()
    p = {"include": include} if include else {}
    return await _redmine("GET", s, f"/issues/{issue_id}.json", params=p)


@mcp.tool()
async def create_issue(
    project_id: str,
    tracker_id: int,
    subject: str,
    description: Optional[str] = None,
    status_id: Optional[int] = None,
    priority_id: Optional[int] = None,
    assigned_to_id: Optional[int] = None,
    parent_issue_id: Optional[int] = None,
    estimated_hours: Optional[float] = None,
    done_ratio: Optional[int] = None,
    start_date: Optional[str] = None,
    due_date: Optional[str] = None,
) -> dict:
    """Create a new Redmine issue."""
    s = _session()
    body: dict = {"project_id": project_id, "tracker_id": tracker_id, "subject": subject}
    for k, v in [
        ("description", description), ("status_id", status_id),
        ("priority_id", priority_id), ("assigned_to_id", assigned_to_id),
        ("parent_issue_id", parent_issue_id), ("estimated_hours", estimated_hours),
        ("done_ratio", done_ratio), ("start_date", start_date), ("due_date", due_date),
    ]:
        if v is not None: body[k] = v
    return await _redmine("POST", s, "/issues.json", json={"issue": body})


@mcp.tool()
async def update_issue(issue_id: int, updates: dict[str, Any], notes: Optional[str] = None) -> dict:
    """Update a Redmine issue. `updates` is a dict of issue fields; `notes` is added as a journal comment."""
    s = _session()
    body = dict(updates)
    if notes: body["notes"] = notes
    return await _redmine("PUT", s, f"/issues/{issue_id}.json", json={"issue": body})


@mcp.tool()
async def delete_issue(issue_id: int, confirm: bool = False) -> dict:
    """Delete a Redmine issue. confirm must be true."""
    if not confirm:
        return {"error": "Set confirm=true to delete the issue."}
    s = _session()
    return await _redmine("DELETE", s, f"/issues/{issue_id}.json")


@mcp.tool()
async def add_issue_watcher(issue_id: int, user_id: int) -> dict:
    """Add a watcher to a Redmine issue."""
    s = _session()
    return await _redmine("POST", s, f"/issues/{issue_id}/watchers.json", json={"user_id": user_id})


@mcp.tool()
async def remove_issue_watcher(issue_id: int, user_id: int) -> dict:
    """Remove a watcher from a Redmine issue."""
    s = _session()
    return await _redmine("DELETE", s, f"/issues/{issue_id}/watchers/{user_id}.json")


@mcp.tool()
async def get_issue_relations(issue_id: int) -> dict:
    """Get all relations for a Redmine issue."""
    s = _session()
    return await _redmine("GET", s, f"/issues/{issue_id}/relations.json")


@mcp.tool()
async def create_issue_relation(
    issue_id: int,
    issue_to_id: int,
    relation_type: str,
    delay: Optional[int] = None,
) -> dict:
    """Create a relation between two Redmine issues."""
    s = _session()
    body: dict = {"issue_to_id": issue_to_id, "relation_type": relation_type}
    if delay is not None: body["delay"] = delay
    return await _redmine("POST", s, f"/issues/{issue_id}/relations.json", json={"relation": body})


@mcp.tool()
async def delete_issue_relation(relation_id: int, confirm: bool = False) -> dict:
    """Delete a Redmine issue relation. confirm must be true."""
    if not confirm:
        return {"error": "Set confirm=true to delete the issue relation."}
    s = _session()
    return await _redmine("DELETE", s, f"/relations/{relation_id}.json")


@mcp.tool()
async def get_issue_journals(issue_id: int) -> dict:
    """Get the change history (journals) for a Redmine issue."""
    s = _session()
    result = await _redmine("GET", s, f"/issues/{issue_id}.json", params={"include": "journals"})
    return {"journals": result.get("issue", {}).get("journals", [])}


@mcp.tool()
async def copy_issue(
    issue_id: int,
    project_id: Optional[str] = None,
    copy_attachments: bool = False,
    copy_subtasks: bool = False,
    copy_watchers: bool = False,
) -> dict:
    """Copy a Redmine issue."""
    s = _session()
    body: dict = {"copy_from": issue_id, "copy_attachments": copy_attachments,
                  "copy_subtasks": copy_subtasks, "copy_watchers": copy_watchers}
    if project_id: body["project_id"] = project_id
    return await _redmine("POST", s, "/issues.json", json={"issue": body})


@mcp.tool()
async def move_issue(issue_id: int, project_id: str, tracker_id: Optional[int] = None) -> dict:
    """Move a Redmine issue to another project."""
    s = _session()
    body: dict = {"project_id": project_id}
    if tracker_id: body["tracker_id"] = tracker_id
    return await _redmine("PUT", s, f"/issues/{issue_id}.json", json={"issue": body})


# ---------------------------------------------------------------------------
# Tools — Users
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_users(
    limit: int = 25,
    offset: int = 0,
    status: int = 1,
    name: Optional[str] = None,
    group_id: Optional[int] = None,
) -> dict:
    """List Redmine users (requires admin)."""
    s = _session()
    p: dict = {"limit": limit, "offset": offset, "status": status}
    if name: p["name"] = name
    if group_id: p["group_id"] = group_id
    return await _redmine("GET", s, "/users.json", params=p)


@mcp.tool()
async def get_user(user_id: str, include: Optional[str] = None) -> dict:
    """Get a Redmine user. Use 'current' for the authenticated user."""
    s = _session()
    p = {"include": include} if include else {}
    return await _redmine("GET", s, f"/users/{user_id}.json", params=p)


@mcp.tool()
async def create_user(
    login: str,
    firstname: str,
    lastname: str,
    mail: str,
    password: Optional[str] = None,
    must_change_password: bool = False,
    generate_password: bool = False,
    send_information: bool = False,
    admin: bool = False,
) -> dict:
    """Create a Redmine user (requires admin)."""
    s = _session()
    body: dict = {"login": login, "firstname": firstname, "lastname": lastname, "mail": mail,
                  "must_change_password": must_change_password, "generate_password": generate_password,
                  "send_information": send_information, "admin": admin}
    if password: body["password"] = password
    return await _redmine("POST", s, "/users.json", json={"user": body})


@mcp.tool()
async def update_user(user_id: int, updates: dict[str, Any]) -> dict:
    """Update a Redmine user. `updates` is a dict of user fields to change."""
    s = _session()
    return await _redmine("PUT", s, f"/users/{user_id}.json", json={"user": updates})


@mcp.tool()
async def delete_user(user_id: int, confirm: bool = False) -> dict:
    """Delete a Redmine user (requires admin). confirm must be true."""
    if not confirm:
        return {"error": "Set confirm=true to delete the user."}
    s = _session()
    return await _redmine("DELETE", s, f"/users/{user_id}.json")


# ---------------------------------------------------------------------------
# Tools — Time Entries
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_time_entries(
    user_id: Optional[int] = None,
    project_id: Optional[int] = None,
    issue_id: Optional[int] = None,
    spent_on: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = 25,
    offset: int = 0,
) -> dict:
    """List Redmine time entries with optional filters."""
    s = _session()
    p: dict = {"limit": limit, "offset": offset}
    for k, v in [("user_id", user_id), ("project_id", project_id), ("issue_id", issue_id),
                 ("spent_on", spent_on), ("from", from_date), ("to", to_date)]:
        if v: p[k] = v
    return await _redmine("GET", s, "/time_entries.json", params=p)


@mcp.tool()
async def get_time_entry(time_entry_id: int) -> dict:
    """Get a specific Redmine time entry."""
    s = _session()
    return await _redmine("GET", s, f"/time_entries/{time_entry_id}.json")


@mcp.tool()
async def create_time_entry(
    hours: float,
    activity_id: int,
    issue_id: Optional[int] = None,
    project_id: Optional[int] = None,
    spent_on: Optional[str] = None,
    comments: Optional[str] = None,
) -> dict:
    """Log time on a Redmine issue or project."""
    s = _session()
    body: dict = {"hours": hours, "activity_id": activity_id}
    for k, v in [("issue_id", issue_id), ("project_id", project_id),
                 ("spent_on", spent_on), ("comments", comments)]:
        if v is not None: body[k] = v
    return await _redmine("POST", s, "/time_entries.json", json={"time_entry": body})


@mcp.tool()
async def update_time_entry(time_entry_id: int, updates: dict[str, Any]) -> dict:
    """Update a Redmine time entry. `updates` is a dict of fields to change."""
    s = _session()
    return await _redmine("PUT", s, f"/time_entries/{time_entry_id}.json", json={"time_entry": updates})


@mcp.tool()
async def delete_time_entry(time_entry_id: int, confirm: bool = False) -> dict:
    """Delete a Redmine time entry. confirm must be true."""
    if not confirm:
        return {"error": "Set confirm=true to delete the time entry."}
    s = _session()
    return await _redmine("DELETE", s, f"/time_entries/{time_entry_id}.json")


# ---------------------------------------------------------------------------
# Tools — Memberships
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_memberships(project_id: int, limit: int = 25, offset: int = 0) -> dict:
    """List memberships for a Redmine project."""
    s = _session()
    return await _redmine("GET", s, f"/projects/{project_id}/memberships.json",
                          params={"limit": limit, "offset": offset})


@mcp.tool()
async def get_membership(membership_id: int) -> dict:
    """Get a specific Redmine project membership."""
    s = _session()
    return await _redmine("GET", s, f"/memberships/{membership_id}.json")


@mcp.tool()
async def create_membership(project_id: int, user_id: int, role_ids: list[int]) -> dict:
    """Add a user or group to a Redmine project."""
    s = _session()
    return await _redmine("POST", s, f"/projects/{project_id}/memberships.json",
                          json={"membership": {"user_id": user_id, "role_ids": role_ids}})


@mcp.tool()
async def update_membership(membership_id: int, role_ids: list[int]) -> dict:
    """Update roles for a Redmine project membership."""
    s = _session()
    return await _redmine("PUT", s, f"/memberships/{membership_id}.json",
                          json={"membership": {"role_ids": role_ids}})


@mcp.tool()
async def delete_membership(membership_id: int, confirm: bool = False) -> dict:
    """Remove a user from a Redmine project. confirm must be true."""
    if not confirm:
        return {"error": "Set confirm=true to delete the membership."}
    s = _session()
    return await _redmine("DELETE", s, f"/memberships/{membership_id}.json")


# ---------------------------------------------------------------------------
# Tools — Groups
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_groups() -> dict:
    """List all Redmine groups (requires admin)."""
    s = _session()
    return await _redmine("GET", s, "/groups.json")


@mcp.tool()
async def get_group(group_id: int, include: Optional[str] = None) -> dict:
    """Get a specific Redmine group."""
    s = _session()
    p = {"include": include} if include else {}
    return await _redmine("GET", s, f"/groups/{group_id}.json", params=p)


@mcp.tool()
async def create_group(name: str, user_ids: Optional[list[int]] = None) -> dict:
    """Create a Redmine group."""
    s = _session()
    body: dict = {"name": name}
    if user_ids: body["user_ids"] = user_ids
    return await _redmine("POST", s, "/groups.json", json={"group": body})


@mcp.tool()
async def update_group(group_id: int, name: Optional[str] = None, user_ids: Optional[list[int]] = None) -> dict:
    """Update a Redmine group."""
    s = _session()
    body: dict = {}
    if name: body["name"] = name
    if user_ids is not None: body["user_ids"] = user_ids
    return await _redmine("PUT", s, f"/groups/{group_id}.json", json={"group": body})


@mcp.tool()
async def delete_group(group_id: int, confirm: bool = False) -> dict:
    """Delete a Redmine group. confirm must be true."""
    if not confirm:
        return {"error": "Set confirm=true to delete the group."}
    s = _session()
    return await _redmine("DELETE", s, f"/groups/{group_id}.json")


# ---------------------------------------------------------------------------
# Tools — Versions
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_versions(project_id: int) -> dict:
    """List versions/milestones for a Redmine project."""
    s = _session()
    return await _redmine("GET", s, f"/projects/{project_id}/versions.json")


@mcp.tool()
async def get_version(version_id: int) -> dict:
    """Get a specific Redmine version."""
    s = _session()
    return await _redmine("GET", s, f"/versions/{version_id}.json")


@mcp.tool()
async def create_version(
    project_id: int,
    name: str,
    description: Optional[str] = None,
    status: str = "open",
    due_date: Optional[str] = None,
    sharing: str = "none",
) -> dict:
    """Create a Redmine version/milestone."""
    s = _session()
    body: dict = {"name": name, "status": status, "sharing": sharing}
    if description: body["description"] = description
    if due_date: body["due_date"] = due_date
    return await _redmine("POST", s, f"/projects/{project_id}/versions.json", json={"version": body})


@mcp.tool()
async def update_version(version_id: int, updates: dict[str, Any]) -> dict:
    """Update a Redmine version. `updates` is a dict of fields to change."""
    s = _session()
    return await _redmine("PUT", s, f"/versions/{version_id}.json", json={"version": updates})


@mcp.tool()
async def delete_version(version_id: int, confirm: bool = False) -> dict:
    """Delete a Redmine version. confirm must be true."""
    if not confirm:
        return {"error": "Set confirm=true to delete the version."}
    s = _session()
    return await _redmine("DELETE", s, f"/versions/{version_id}.json")


# ---------------------------------------------------------------------------
# Tools — Custom Fields
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_custom_fields() -> dict:
    """List all Redmine custom fields."""
    s = _session()
    return await _redmine("GET", s, "/custom_fields.json")


# ---------------------------------------------------------------------------
# Tools — Queries
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_queries(limit: int = 25, offset: int = 0) -> dict:
    """List all accessible Redmine saved queries."""
    s = _session()
    return await _redmine("GET", s, "/queries.json", params={"limit": limit, "offset": offset})


# ---------------------------------------------------------------------------
# FastAPI app — mount MCP + auth routes
# ---------------------------------------------------------------------------

mcp_app = mcp.http_app(path="/", transport="streamable-http")

app = FastAPI(title="Redmine MCP OAuth Server", lifespan=mcp_app.lifespan)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply a baseline set of security headers to every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.include_router(auth_router)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    """Liveness probe. 200 means the process is up."""
    return {"status": "ok"}


@app.get("/readyz", include_in_schema=False)
async def readyz() -> dict:
    """Readiness probe. Currently identical to healthz; will check the token
    store backend once a remote backend is wired up (Phase 1.1)."""
    return {"status": "ready"}


app.mount("/mcp", mcp_app)
