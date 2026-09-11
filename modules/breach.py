"""
Breach-awareness lookup via the Have I Been Pwned API.

Access rules (enforced by HIBP's own API terms, and mirrored here):
- Requires a paid HIBP API key (HIBP_API_KEY env var). Without one this
  module returns a clear "not configured" result instead of failing.
- This tool does not — and cannot, via this API — return leaked
  passwords or raw record contents. HIBP's breach-search API only ever
  returns which named breaches an email address appeared in and what
  data classes were exposed (e.g. "Email addresses, Passwords").
- This is intended for checking accounts you own or are formally
  authorized to investigate (e.g. a police cybercrime unit checking a
  victim's email with their consent, or a student checking their own
  inbox). It is not a bulk lookup tool — the UI should require an
  explicit authorization acknowledgment before calling this.
"""

import os
import requests

HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"


def check_breach(email: str, authorized: bool = False):
    api_key = os.environ.get("HIBP_API_KEY")

    if not authorized:
        return {
            "type": "breach",
            "target": email,
            "summary": "Authorization required",
            "findings": [],
            "notice": "You must confirm you own this email or are formally authorized to check it before this lookup runs.",
        }

    if not api_key:
        return {
            "type": "breach",
            "target": email,
            "summary": "Breach check not configured",
            "findings": [{
                "label": "HIBP API key",
                "value": "Not set (HIBP_API_KEY). Get one at haveibeenpwned.com/API/Key.",
                "status": "warn",
            }],
            "notice": "Server administrator has not configured breach-checking.",
        }

    try:
        r = requests.get(
            HIBP_API.format(email),
            headers={"hibp-api-key": api_key, "user-agent": "KevinOSINT/2.0"},
            params={"truncateResponse": "false"},
            timeout=8,
        )
        if r.status_code == 404:
            findings = [{"label": "Result", "value": "No breaches found", "status": "good"}]
        elif r.status_code == 200:
            breaches = r.json()
            findings = [{
                "label": b.get("Name", "Unknown breach"),
                "value": f"{b.get('BreachDate', '?')} — exposed: {', '.join(b.get('DataClasses', []))}",
                "status": "bad",
            } for b in breaches]
        elif r.status_code == 401:
            findings = [{"label": "Error", "value": "Invalid HIBP API key", "status": "bad"}]
        elif r.status_code == 429:
            findings = [{"label": "Error", "value": "Rate limited by HIBP — try again shortly", "status": "warn"}]
        else:
            findings = [{"label": "Error", "value": f"HIBP returned HTTP {r.status_code}", "status": "warn"}]
    except requests.RequestException as exc:
        findings = [{"label": "Error", "value": str(exc), "status": "bad"}]

    return {
        "type": "breach",
        "target": email,
        "summary": "Breach exposure check (Have I Been Pwned)",
        "findings": findings,
        "notice": "Shows only which named breaches this address appeared in and what data types were exposed — never actual leaked passwords.",
    }
