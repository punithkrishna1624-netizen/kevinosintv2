# KevinOSINT v2.0

A passive, authorized-source recon dashboard for bug bounty recon, cybersecurity
education, and authorized investigations (e.g. police cybercrime units).

**Scope, by design:** this tool maps public *infrastructure* (DNS, TLS certs,
HTTP headers, tech stack, certificate-transparency subdomains) and does
lightweight *metadata* checks (phone validity/region, email deliverability
records, username presence). It does not aggregate personal records, and the
breach-check module requires an explicit authorization confirmation before it
will run.

## What's new in v2.0

- **Domain / attack-surface module**: DNS, subdomain enumeration (crt.sh
  certificate transparency), live SSL/TLS certificate inspection, HTTP
  security header audit, and passive tech-stack fingerprinting — all in one
  investigation.
- **Email module**: now also checks SPF/DMARC records (spoofing-risk
  indicators), useful for both bug bounty and cybercrime/phishing
  investigations.
- **IP module**: adds reverse DNS (PTR) lookup.
- **Breach-check module**: optional Have I Been Pwned integration, gated
  behind an explicit "I own this / I'm authorized" confirmation. Returns only
  breach names + exposed data categories, never passwords.
- **Auth**: shared access-code login (`ACCESS_CODE` env var) for team/class
  deployments — the app is no longer open to anonymous public use once set.
- **Rate limiting**: per-IP limits on the investigate and breach-check
  endpoints (Flask-Limiter).
- **SSRF protections**: any module that fetches a user-supplied
  domain/host now resolves it first and refuses to proceed if it points at a
  private, loopback, or link-local address (see `modules/security.py`).
- **Tests**: `tests/test_modules.py` covers validation and safety logic.

## Local setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env: set ACCESS_CODE and SECRET_KEY at minimum for anything
# beyond solo local testing

python3 app.py
```

Open http://127.0.0.1:5000 — you'll be prompted for the access code if
`ACCESS_CODE` is set.

## Deploying for a team/class

1. Set these environment variables on your host (Render, Docker, etc.):
   - `ACCESS_CODE` — shared password for your team/class
   - `SECRET_KEY` — random value (`python3 -c "import secrets; print(secrets.token_hex(32))"`)
   - `HIBP_API_KEY` — optional, enables breach-check
2. Deploy with `gunicorn app:app` (see `render.yaml` / `Dockerfile`).
3. Give students/team the URL + access code out of band (not in the repo).

For a real classroom/multi-team rollout, consider swapping the single
shared access code for per-user accounts if you need individual
accountability for who ran which query — the current logging
(`log.info(...)` in `app.py`) records target + type + requester IP but not
a named user.

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

## API

`POST /api/investigate`
```json
{ "type": "domain", "target": "example.com" }
```
Types: `auto`, `email`, `phone`, `username`, `domain`, `ip`

`POST /api/breach-check`
```json
{ "email": "you@example.com", "authorized": true }
```

## Ground rules

- Public/authorized sources only. No active exploitation, no brute forcing,
  no credential stuffing, no scanning beyond a single passive request.
- The breach-check module is for accounts you own or are formally
  authorized to investigate — not a bulk lookup tool.
- Do not point this at targets you don't have permission to test, per
  standard bug-bounty program rules of engagement.
