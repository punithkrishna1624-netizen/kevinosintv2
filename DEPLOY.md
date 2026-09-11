# KevinOSINT v2.0 — Deployment

## Render

1. Push this folder to a GitHub repository.
2. On Render: New → Web Service → connect the repo (or use the included
   `render.yaml` as a Blueprint).
3. Set environment variables in the Render dashboard:
   - `ACCESS_CODE` (required for anything beyond a private test)
   - `SECRET_KEY` (Render can auto-generate this if using the Blueprint)
   - `HIBP_API_KEY` (optional)
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn --workers 2 --timeout 30 app:app`
6. Deploy — Render gives you a public HTTPS URL.

## Docker (any host)

```bash
docker build -t kevinosint .
docker run -p 5000:5000 \
  -e ACCESS_CODE=your-team-code \
  -e SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
  -e HIBP_API_KEY=your-hibp-key \
  kevinosint
```

## Bare metal / VM

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export ACCESS_CODE=your-team-code
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
gunicorn --workers 2 --timeout 30 app:app
```

Put this behind nginx/Caddy with HTTPS if it's reachable from the internet.

## Production checklist

- [ ] `ACCESS_CODE` set to something non-trivial, shared out-of-band
- [ ] `SECRET_KEY` set to a random value (not the dev default)
- [ ] HTTPS in front of the app (Render/most PaaS do this automatically)
- [ ] If you expect >1 instance/dyno, point `RATELIMIT_STORAGE_URI` at Redis
      instead of the default in-memory store, or rate limits won't be shared
      across instances
- [ ] Decide on a log retention policy for `investigate`/`breach-check`
      request logs (they contain the targets users searched)
- [ ] Read the "Ground rules" section in README.md with your team/class
      before rollout

## Branding

Logo/avatar: `static/kevin-avatar.jpeg` — replace anytime.
