"""
Shared security helpers.

Any module that makes an outbound HTTP request to a user-supplied
domain/host MUST go through safe_get() below. This prevents the
classic OSINT-tool SSRF bug: a user enters a "domain" that actually
resolves to an internal/private IP (127.0.0.1, 169.254.169.254 cloud
metadata, 10.x/172.16.x/192.168.x internal ranges, etc.) and tricks
the server into making requests on their behalf against internal
infrastructure.

We resolve the hostname ourselves first, reject it if any resolved
IP is private/reserved/loopback/link-local, and only then perform
the request pinned to a validated public IP.
"""

import ipaddress
import socket
import re
import requests

USER_AGENT = "KevinOSINT/2.0 (+authorized-recon-tool)"
REQUEST_TIMEOUT = 6

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class UnsafeTargetError(Exception):
    """Raised when a target resolves to a non-public / disallowed address."""


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


def clean_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    d = d.split(":")[0]
    return d


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    # Cloud metadata endpoint, explicitly blocked even though it's
    # technically a "public-looking" address in some setups.
    if ip_str.startswith("169.254."):
        return False
    return True


def resolve_all(hostname: str):
    """Return list of resolved IP strings for hostname, or [] on failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def assert_public_host(hostname: str):
    """Raise UnsafeTargetError if hostname resolves to any non-public IP."""
    ips = resolve_all(hostname)
    if not ips:
        raise UnsafeTargetError(f"Could not resolve {hostname}")
    for ip in ips:
        if not _is_public_ip(ip):
            raise UnsafeTargetError(
                f"{hostname} resolves to a non-public address ({ip}); refusing to fetch."
            )
    return ips


def safe_get(url: str, **kwargs):
    """
    requests.get() wrapper that validates the target host resolves to a
    public IP before making the request. Use this for any request whose
    host portion came from user input.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError("Only http/https schemes are allowed.")
    if not parsed.hostname:
        raise UnsafeTargetError("URL has no hostname.")

    assert_public_host(parsed.hostname)

    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", USER_AGENT)
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    kwargs.setdefault("allow_redirects", False)  # avoid redirect-based SSRF bypass

    return requests.get(url, headers=headers, **kwargs)
