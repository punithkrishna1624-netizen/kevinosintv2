"""
Basic technology fingerprinting from a single passive HTTP response —
the same signals browser extensions like Wappalyzer read: response
headers and a handful of telltale strings in the HTML. No active
probing of endpoints beyond the homepage.
"""

import re
from .security import safe_get, UnsafeTargetError

SIGNATURES = [
    ("WordPress", re.compile(r"wp-content|wp-includes", re.I)),
    ("Shopify", re.compile(r"cdn\.shopify\.com", re.I)),
    ("React", re.compile(r"__NEXT_DATA__|data-reactroot|react-dom", re.I)),
    ("Vue.js", re.compile(r"__vue__|data-v-", re.I)),
    ("Cloudflare", re.compile(r"cloudflare", re.I)),
    ("Google Analytics", re.compile(r"www\.google-analytics\.com|gtag\(", re.I)),
    ("jQuery", re.compile(r"jquery(\.min)?\.js", re.I)),
    ("Bootstrap", re.compile(r"bootstrap(\.min)?\.css", re.I)),
    ("Django", re.compile(r"csrfmiddlewaretoken", re.I)),
    ("Laravel", re.compile(r"laravel_session", re.I)),
]


def fingerprint(domain: str):
    findings = []
    error = None
    try:
        resp = safe_get(f"https://{domain}/")
        body = resp.text[:200_000]  # cap to avoid huge pages
        headers = resp.headers

        detected = [name for name, pattern in SIGNATURES if pattern.search(body)]

        powered_by = headers.get("X-Powered-By")
        via = headers.get("Via")

        findings.append({
            "label": "Detected technologies",
            "value": ", ".join(detected) if detected else "None matched (passive signature set)",
            "status": "good" if detected else "info",
        })
        if powered_by:
            findings.append({"label": "X-Powered-By", "value": powered_by, "status": "info"})
        if via:
            findings.append({"label": "Via", "value": via, "status": "info"})
        findings.append({"label": "HTTP status", "value": str(resp.status_code), "status": "info"})

    except UnsafeTargetError as exc:
        error = str(exc)
    except Exception as exc:
        error = f"Request failed: {exc}"

    return {
        "title": "Technology Fingerprint",
        "source": "Passive signature match against homepage HTML/headers",
        "findings": findings,
        "error": error,
    }
