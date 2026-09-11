"""
Subdomain enumeration via Certificate Transparency logs (crt.sh).

This is standard, passive bug-bounty recon: CT logs are public by
design (every publicly-trusted TLS cert gets logged there), so this
reveals nothing that wasn't already published the moment a cert was
issued. No active scanning of the target is performed.
"""

import requests

CRTSH_URL = "https://crt.sh/?q=%25.{}&output=json"


def enumerate_subdomains(domain: str, limit: int = 40):
    subs = set()
    error = None
    try:
        r = requests.get(
            CRTSH_URL.format(domain),
            timeout=10,
            headers={"User-Agent": "KevinOSINT/2.0"},
        )
        if r.status_code == 200 and r.text.strip():
            for entry in r.json():
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(domain) and "*" not in name:
                        subs.add(name)
    except Exception as exc:
        error = str(exc)

    sorted_subs = sorted(subs)[:limit]

    return {
        "title": "Subdomains (Certificate Transparency)",
        "source": "crt.sh public CT log search",
        "count": len(subs),
        "items": sorted_subs,
        "truncated": len(subs) > limit,
        "error": error,
        "notice": "Passive only — sourced from public certificate transparency logs. No ports or hosts were scanned.",
    }
