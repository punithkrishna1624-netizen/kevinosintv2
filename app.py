import os
import secrets
import logging
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

from modules.email import analyze_email
from modules.phone import analyze_phone
from modules.username import analyze_username
from modules.domain import analyze_domain
from modules.ip import analyze_ip
from modules.breach import check_breach

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

ACCESS_CODE = os.environ.get("ACCESS_CODE")  # if unset, auth is disabled (local dev only)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("kevinosint")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if ACCESS_CODE and not session.get("authed"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.get("/login")
def login():
    if not ACCESS_CODE:
        return redirect(url_for("index"))
    return render_template("login.html", error=None)


@app.post("/login")
@limiter.limit("10 per minute")
def login_post():
    code = (request.form.get("code") or "").strip()
    if ACCESS_CODE and secrets.compare_digest(code, ACCESS_CODE):
        session["authed"] = True
        return redirect(url_for("index"))
    return render_template("login.html", error="Incorrect access code."), 401


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    return render_template("index.html")


@app.post("/api/investigate")
@login_required
@limiter.limit("20 per minute")
def investigate():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    target_type = (data.get("type") or "auto").lower()

    if not target:
        return jsonify({"error": "Enter a target."}), 400
    if len(target) > 253:
        return jsonify({"error": "Target is too long."}), 400

    client_ip = get_remote_address()
    log.info("investigate type=%s target=%s ip=%s", target_type, target, client_ip)

    try:
        if target_type == "email":
            result = analyze_email(target)
        elif target_type == "phone":
            result = analyze_phone(target)
        elif target_type == "username":
            result = analyze_username(target)
        elif target_type == "domain":
            result = analyze_domain(target)
        elif target_type == "ip":
            result = analyze_ip(target)
        else:
            if "@" in target:
                result = analyze_email(target)
            elif target.replace(".", "").isdigit() and target.count(".") == 3:
                result = analyze_ip(target)
            elif target.startswith("+") or target.replace(" ", "").isdigit():
                result = analyze_phone(target)
            elif "." in target:
                result = analyze_domain(target)
            else:
                result = analyze_username(target)

        return jsonify(result)
    except Exception as exc:
        log.exception("investigate failed")
        return jsonify({"error": "Investigation failed. Check target format and try again."}), 500


@app.post("/api/breach-check")
@login_required
@limiter.limit("10 per minute")
def breach_check():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    authorized = bool(data.get("authorized"))

    if not email:
        return jsonify({"error": "Enter an email."}), 400

    result = check_breach(email, authorized=authorized)
    return jsonify(result)


@app.get("/api/health")
def health():
    return jsonify({"status": "online", "service": "KevinOSINT", "auth_enabled": bool(ACCESS_CODE)})


@app.errorhandler(429)
def ratelimited(e):
    return jsonify({"error": "Too many requests. Slow down and try again shortly."}), 429


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
