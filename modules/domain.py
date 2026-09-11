import socket

from .security import clean_domain, is_valid_domain
from .subdomains import enumerate_subdomains
from .ssl_audit import inspect_ssl
from .headers_audit import audit_headers
from .techstack import fingerprint


def _dns_section(domain):
    findings = []
    try:
        ip = socket.gethostbyname(domain)
        findings.append({"label": "IPv4", "value": ip, "status": "good"})
    except socket.gaierror:
        findings.append({"label": "IPv4", "value": "Not resolved", "status": "warn"})

    try:
        import dns.resolver
        for record_type in ["A", "AAAA", "MX", "TXT", "NS"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                values = [str(a).rstrip(".") for a in answers]
                findings.append({"label": record_type, "value": ", ".join(values[:8]), "status": "good"})
            except Exception:
                findings.append({"label": record_type, "value": "None / unavailable", "status": "info"})
    except Exception:
        pass

    return {"title": "DNS Records", "source": "Public DNS", "findings": findings}


def analyze_domain(raw_domain):
    domain = clean_domain(raw_domain)

    if not is_valid_domain(domain):
        return {
            "type": "domain",
            "target": raw_domain,
            "summary": "Invalid domain",
            "sections": [],
            "notice": "Enter a valid domain, e.g. example.com",
        }

    sections = [
        _dns_section(domain),
        enumerate_subdomains(domain),
        inspect_ssl(domain),
        audit_headers(domain),
        fingerprint(domain),
    ]

    return {
        "type": "domain",
        "target": domain,
        "summary": "Domain & attack-surface recon",
        "sections": sections,
        "notice": "All data sourced passively from public DNS, certificate transparency logs, and a single homepage request. No active scanning or exploitation was performed.",
    }
