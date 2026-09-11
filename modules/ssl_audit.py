"""
SSL/TLS certificate inspection.

Connects to the target's HTTPS port only to read the certificate the
server presents during the TLS handshake — the same information
your browser reads on every HTTPS visit. No vulnerability scanning,
no cipher-downgrade attempts, no exploitation.
"""

import ssl
import socket
import datetime

from .security import assert_public_host, UnsafeTargetError


def _parse_cert_name(name_tuples):
    parts = []
    for rdn in name_tuples:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def inspect_ssl(domain: str, port: int = 443):
    findings = []
    try:
        assert_public_host(domain)
    except UnsafeTargetError as exc:
        return {
            "title": "SSL/TLS Certificate",
            "error": str(exc),
            "findings": [],
        }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days

        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        findings = [
            {"label": "Subject", "value": _parse_cert_name(cert.get("subject", [])), "status": "info"},
            {"label": "Issuer", "value": _parse_cert_name(cert.get("issuer", [])), "status": "info"},
            {"label": "Valid from", "value": str(not_before), "status": "info"},
            {"label": "Valid until", "value": str(not_after), "status": "warn" if days_left < 21 else "good"},
            {"label": "Days remaining", "value": str(days_left), "status": "warn" if days_left < 21 else "good"},
            {"label": "Subject Alt Names", "value": ", ".join(sans[:12]) or "None", "status": "info"},
            {"label": "TLS version / cipher", "value": f"{cipher[1]} / {cipher[0]}" if cipher else "Unknown", "status": "info"},
        ]
        error = None
    except Exception as exc:
        error = f"Could not retrieve certificate: {exc}"

    return {
        "title": "SSL/TLS Certificate",
        "source": "Live TLS handshake (read-only, no exploitation)",
        "findings": findings,
        "error": error if not findings else None,
    }
