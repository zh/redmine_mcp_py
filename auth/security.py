"""
auth/security.py — defensive helpers shared by login and tool dispatch.

* validate_redmine_url: blocks SSRF by resolving the hostname and refusing
  private / loopback / link-local / multicast / reserved address space.
* RedactedStr: wrapping type that prevents accidental logging of secrets.
* SECURITY_HEADERS: dict of hardening headers applied by middleware.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from config import settings


class InvalidRedmineURL(ValueError):
    """Raised when redmine_url fails scheme/host validation."""


def _ip_is_disallowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_redmine_url(url: str) -> str:
    """Return a canonical (trailing-slash-stripped) URL, or raise InvalidRedmineURL.

    Blocks:
      * non-http(s) schemes
      * plaintext http unless REDMINE_MCP_ALLOW_HTTP=1
      * hostnames missing
      * resolved IPs in private / loopback / link-local / multicast / reserved
      * bare IP literals (unless ALLOW_HTTP=1, dev mode)
      * hosts not on REDMINE_MCP_ALLOWED_HOSTS when that allowlist is set
    """
    if not url or not isinstance(url, str):
        raise InvalidRedmineURL("redmine_url is required")

    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if scheme not in ("http", "https"):
        raise InvalidRedmineURL("redmine_url must use http(s)")

    if scheme == "http" and not settings.allow_http:
        raise InvalidRedmineURL("redmine_url must use https")

    if not host:
        raise InvalidRedmineURL("redmine_url is missing a hostname")

    if settings.allowed_hosts and host not in settings.allowed_hosts:
        raise InvalidRedmineURL("redmine_url host is not on the allowlist")

    # Reject bare-IP hosts in production mode — too easy to slip a private IP through.
    try:
        ipaddress.ip_address(host)
        is_bare_ip = True
    except ValueError:
        is_bare_ip = False

    if is_bare_ip and not settings.allow_http:
        raise InvalidRedmineURL("redmine_url must be a hostname, not a bare IP")

    # Resolve and check every address — covers DNS rebinding at least at this
    # check point. We re-validate in the outbound call path too.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise InvalidRedmineURL(f"could not resolve {host}") from e

    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        if ip_str in seen:
            continue
        seen.add(ip_str)
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise InvalidRedmineURL(f"unparseable resolved address {ip_str}")
        if _ip_is_disallowed(ip):
            raise InvalidRedmineURL(
                f"redmine_url resolves to a non-public address ({ip_str})"
            )

    # Canonicalize: scheme://host[:port], no trailing slash, no path
    netloc = parsed.netloc
    return f"{scheme}://{netloc}".rstrip("/")


class RedactedStr(str):
    """A str that prints as `***` in repr/str but compares & hashes like the original.

    Comparison, hashing, encoding, slicing — all use the underlying value, so this
    is safe to drop into outbound HTTP headers. Only the textual repr/str path
    is overridden so accidental logging shows `***` instead of the secret.

    Use `.reveal()` only when an internal API explicitly needs the cleartext.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "'***'"

    def __str__(self) -> str:
        return "***"

    def reveal(self) -> str:
        """Return the underlying cleartext as a plain str."""
        return self[:]


SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
}
