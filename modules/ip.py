import ipaddress
import socket
import requests


def analyze_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
        valid = True
        is_private = obj.is_private or obj.is_loopback or obj.is_link_local
    except ValueError:
        valid = False
        is_private = False

    findings = [
        {"label": "IP syntax", "value": "Valid" if valid else "Invalid", "status": "good" if valid else "bad"},
    ]

    if valid and is_private:
        findings.append({
            "label": "Scope",
            "value": "Private/reserved address — no public geolocation or ownership data exists for this.",
            "status": "warn",
        })
        return {
            "type": "ip",
            "target": ip,
            "summary": "Private/internal IP",
            "findings": findings,
            "notice": "Private IPs are not publicly routable; there is nothing to look up.",
        }

    if valid:
        try:
            host = socket.getfqdn(ip)
            findings.append({
                "label": "Reverse DNS (PTR)",
                "value": host if host != ip else "No PTR record",
                "status": "good" if host != ip else "info",
            })
        except Exception:
            findings.append({"label": "Reverse DNS (PTR)", "value": "Lookup failed", "status": "warn"})

        try:
            r = requests.get(f"https://ipwho.is/{ip}", timeout=6)
            data = r.json()
            if data.get("success"):
                for label, key in [
                    ("Country", "country"),
                    ("Region", "region"),
                    ("City", "city"),
                    ("ISP", "connection"),
                ]:
                    value = data.get(key)
                    if isinstance(value, dict):
                        value = value.get("isp") or value.get("org") or value.get("asn")
                    findings.append({"label": label, "value": value or "Unavailable", "status": "info"})
        except requests.RequestException:
            findings.append({"label": "Geo/ASN lookup", "value": "Unavailable", "status": "warn"})

    return {
        "type": "ip",
        "target": ip,
        "summary": "Approximate IP/network intelligence",
        "findings": findings,
        "notice": "IP geolocation is approximate (typically city/ISP level) and is not a residential address or proof of who used the IP at any given time.",
    }
