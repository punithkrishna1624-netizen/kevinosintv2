import re

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _txt_records(domain, prefix=None):
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "TXT")
        records = [b"".join(r.strings).decode(errors="ignore") if hasattr(r, "strings") else str(r) for r in answers]
        if prefix:
            records = [r for r in records if r.lower().startswith(prefix)]
        return records
    except Exception:
        return []


def analyze_email(email):
    valid = bool(EMAIL_RE.match(email))
    domain = email.split("@", 1)[1].lower() if "@" in email else ""

    mx = []
    spf = []
    dmarc = []

    if domain:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            mx = sorted([str(a.exchange).rstrip(".") for a in answers])
        except Exception:
            pass

        spf = _txt_records(domain, prefix="v=spf1")
        dmarc = _txt_records(f"_dmarc.{domain}", prefix="v=dmarc1")

    findings = [
        {"label": "Syntax", "value": "Valid" if valid else "Invalid", "status": "good" if valid else "bad"},
        {"label": "Domain", "value": domain or "—", "status": "info"},
        {"label": "MX records", "value": ", ".join(mx) if mx else "Not resolved", "status": "good" if mx else "warn"},
        {"label": "SPF record", "value": spf[0] if spf else "Not found", "status": "good" if spf else "warn"},
        {"label": "DMARC record", "value": dmarc[0] if dmarc else "Not found", "status": "good" if dmarc else "warn"},
    ]

    return {
        "type": "email",
        "target": email,
        "summary": "Public email/domain intelligence & spoofing-risk indicators",
        "findings": findings,
        "notice": "This module checks public DNS records only. It does not reveal account ownership, passwords, or whether the mailbox exists.",
    }
