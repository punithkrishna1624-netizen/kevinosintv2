"""
HTTP security header audit — checks whether standard defensive
headers are present on a single GET request to the target's homepage.
This is a passive, single-request check (the same request a browser
makes), not a scan.
"""

from .security import safe_get, UnsafeTargetError

CHECKED_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS on future visits (HSTS).",
    "Content-Security-Policy": "Restricts what scripts/styles/frames can load.",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks.",
    "X-Frame-Options": "Mitigates clickjacking.",
    "Referrer-Policy": "Controls what's leaked in the Referer header.",
    "Permissions-Policy": "Restricts access to browser features/APIs.",
}


def audit_headers(domain: str):
    findings = []
    error = None
    server_banner = None
    try:
        resp = safe_get(f"https://{domain}/")
        headers = resp.headers
        server_banner = headers.get("Server")

        for name, description in CHECKED_HEADERS.items():
            present = name in headers
            findings.append({
                "label": name,
                "value": headers.get(name, "Missing") if present else "Missing",
                "status": "good" if present else "warn",
                "hint": description,
            })

        findings.append({
            "label": "Server banner",
            "value": server_banner or "Not disclosed",
            "status": "info",
        })
    except UnsafeTargetError as exc:
        error = str(exc)
    except Exception as exc:
        error = f"Request failed: {exc}"

    return {
        "title": "HTTP Security Headers",
        "source": "Single passive GET request to https://<domain>/",
        "findings": findings,
        "error": error,
    }
