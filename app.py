import os
import pathlib
import secrets
import time
import logging
import traceback
from urllib.parse import urljoin

from flask import (
    Flask, redirect, url_for, session, request, Response, jsonify, current_app
)
from werkzeug.middleware.proxy_fix import ProxyFix
from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from config import settings
from reverse_proxy import proxy_get

# ---------- Logging ----------
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, logging.INFO))
logger = logging.getLogger("prom-oidc")

# ---------- Kill corporate proxy influence for outbound HTTP(s) ----------
for var in ("HTTP_PROXY","HTTPS_PROXY","http_proxy","https_proxy","REQUESTS_CA_BUNDLE","CURL_CA_BUNDLE"):
    os.environ.pop(var, None)
os.environ.setdefault("NO_PROXY", "*")

# ---------- Flask app ----------
app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Session / cookies
app.secret_key = settings.SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=settings.SESSION_COOKIE_SECURE,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=settings.SESSION_COOKIE_SAMESITE,
    PERMANENT_SESSION_LIFETIME=settings.PERMANENT_SESSION_LIFETIME,
)

# Debug banner
print("[prom-oidc] PUBLIC_BASE_URL =", settings.PUBLIC_BASE_URL)
print("[prom-oidc] PROMETHEUS_UPSTREAM =", settings.PROM_UPSTREAM)
print("[prom-oidc] OKTA_ISSUER =", settings.OKTA_ISSUER)
print("[prom-oidc] PROM_VERIFY_TLS =", settings.PROM_VERIFY_TLS)
print("[prom-oidc] PROM_CA_BUNDLE =", settings.PROM_CA_BUNDLE)
print("[prom-oidc] CERT_PATH =", getattr(settings, "CERT_PATH", None))
print("[prom-oidc] ALLOW_ANON =", settings.ALLOW_ANON)

# ---------- OAuth (Okta) ----------
oauth = OAuth(app)
okta = oauth.register(
    name="okta",
    client_id=settings.OKTA_CLIENT_ID,
    client_secret=settings.OKTA_CLIENT_SECRET,
    server_metadata_url=settings.OKTA_DISCOVERY,
    client_kwargs={"scope": settings.OKTA_SCOPES},
)
CALLBACK = f"{settings.PUBLIC_BASE_URL}/oidc/callback"

# ---------- Routes ----------
@app.route("/", methods=["GET", "HEAD"])
def root():
    # Prom/Alertmanager SPA default
    return proxy_get(settings.PROM_UPSTREAM, "")
   #return redirect("/#/alerts")

@app.route("/login")
def login():
    # Keep where the user was going; default to SPA alerts
    session.setdefault("post_login_redirect", request.args.get("next") or settings.DEFAULT_REDIRECT_PATH)

    # PKCE
    v = secrets.token_urlsafe(64)
    session["pkce_verifier"] = v
    ch = create_s256_code_challenge(v)

    return okta.authorize_redirect(
        redirect_uri=CALLBACK,
        code_challenge=ch,
        code_challenge_method="S256",
    )

'''@app.route("/oidc/callback")
def oidc_callback():
    # If Okta sent an error
    if 'error' in request.args:
        err = request.args.get('error')
        desc = request.args.get('error_description')
        try:
            current_app.logger.error("OIDC error: %s %s", err, desc)
        except Exception:
            pass
        return Response(f"OIDC error: {err}: {desc}", status=401, mimetype="text/plain")

    code = request.args.get("code")
    if not code:
        return redirect(url_for("login"))

    verifier = session.pop("pkce_verifier", None)
    if not verifier:
        return redirect(url_for("login"))

    # 🔸 Preserve next BEFORE clearing session
    nxt = session.get("post_login_redirect", settings.DEFAULT_REDIRECT_PATH)
    session.clear()
    session["user"] = {
        "sub": userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name") or userinfo.get("preferred_username"),
    }
    session.permanent = True

    return redirect(nxt if isinstance(nxt, str) and nxt.startswith("/") else settings.DEFAULT_REDIRECT_PATH)

    try:
        token = okta.authorize_access_token(code_verifier=verifier)
    except Exception:
        try:
            current_app.logger.exception("OIDC token exchange failed")
        except Exception:
            pass
        return Response("Login failed. Please try again.", status=401, mimetype="text/plain")

    # Prefer /userinfo; fallback to ID token for claims
    userinfo = {}
    try:
        userinfo = okta.userinfo() or {}
    except Exception:
        try:
            userinfo = okta.parse_id_token(token) or {}
        except Exception:
            userinfo = {}

    # Minimal cookie (Flask session is cookie-based by default)
    safe_user = {
        "sub":   userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name":  userinfo.get("name") or userinfo.get("preferred_username"),
    }

    session.clear()
    session["user"] = safe_user
    session.permanent = True

    # Only allow internal redirects
    if isinstance(nxt, str) and nxt.startswith("/"):
        return redirect(nxt)
    return redirect(settings.DEFAULT_REDIRECT_PATH)
'''

@app.route("/oidc/callback")
def oidc_callback():
    # If Okta sent an error
    if 'error' in request.args:
        err = request.args.get('error')
        desc = request.args.get('error_description')
        current_app.logger.error("OIDC error: %s %s", err, desc)
        return Response(f"OIDC error: {err}: {desc}", status=401, mimetype="text/plain")

    code = request.args.get("code")
    if not code:
        return redirect(url_for("login"))

    verifier = session.pop("pkce_verifier", None)
    if not verifier:
        return redirect(url_for("login"))

    # Preserve next BEFORE clearing session
    nxt = session.get("post_login_redirect", settings.DEFAULT_REDIRECT_PATH)

    # --- Exchange code for tokens ---
    try:
        token = okta.authorize_access_token(code_verifier=verifier)
    except Exception:
        current_app.logger.exception("OIDC token exchange failed")
        return Response("Login failed. Please try again.", status=401, mimetype="text/plain")

    # --- Fetch user claims ---
    userinfo = {}
    try:
        userinfo = okta.userinfo() or {}
    except Exception:
        try:
            userinfo = okta.parse_id_token(token) or {}
        except Exception:
            userinfo = {}

    safe_user = {
        "sub":   userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name":  userinfo.get("name") or userinfo.get("preferred_username"),
    }

    # --- Save user session ---
    session.clear()
    session["user"] = safe_user
    session.permanent = True

    # --- Redirect back to original page or default ---
    if isinstance(nxt, str) and nxt.startswith("/"):
        return redirect(nxt)
    return redirect(settings.DEFAULT_REDIRECT_PATH)

@app.route("/logout")
def logout():
    session.clear()
    # Okta logout → back to app
    return redirect(f"{settings.OKTA_ISSUER}/v1/logout?post_logout_redirect_uri={settings.PUBLIC_BASE_URL}{settings.DEFAULT_REDIRECT_PATH}")

# ---- Public health/debug ----
@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/debug/upstream")
def debug_upstream():
    import requests
    verify = settings.resolve_verify_path()
    url = urljoin(settings.PROM_UPSTREAM.rstrip("/") + "/", "/#/alerts")
    t0 = time.time()
    try:
        s = requests.Session(); s.trust_env = False
        r = s.get(url, timeout=10, allow_redirects=False, verify=verify)
        dt = int((time.time() - t0) * 1000)
        return Response(f"GET {url} -> {r.status_code} in {dt}ms (verify={verify})", mimetype="text/plain")
    except Exception as e:
        body = (
            f"ERROR fetching {url}\n"
            f"verify={verify}\n"
            f"PROM_CA_BUNDLE={settings.PROM_CA_BUNDLE}\n"
            f"CERT_PATH={getattr(settings, 'CERT_PATH', None)}\n"
            f"Error={repr(e)}\n\n{traceback.format_exc()}"
        )
        return Response(body, status=500, mimetype="text/plain")

@app.route("/debug/ssl")
def debug_ssl():
    cp = getattr(settings, "CERT_PATH", None)
    body = "\n".join([
        f"PROM_VERIFY_TLS={settings.PROM_VERIFY_TLS}",
        f"PROM_CA_BUNDLE={settings.PROM_CA_BUNDLE} exists={bool(settings.PROM_CA_BUNDLE and pathlib.Path(settings.PROM_CA_BUNDLE).exists())}",
        f"CERT_PATH={cp} exists={bool(cp and pathlib.Path(cp).exists())}",
    ])
    return Response(body, mimetype="text/plain")

@app.route("/whoami")
def whoami():
    u = session.get("user") or {}
    return jsonify({"logged_in": bool(u), "sub": u.get("sub"), "email": u.get("email")})

# ---- Static asset passthrough to upstream (Prom/Alertmanager) ----
@app.route("/static/<path:asset>", methods=["GET", "HEAD"])
def proxy_static(asset):
    return proxy_get(settings.PROM_UPSTREAM, f"static/{asset}")

@app.route("/favicon.ico", methods=["GET", "HEAD"])
def proxy_favicon():
    return proxy_get(settings.PROM_UPSTREAM, "favicon.ico")

# ---- Auth guard ----
@app.before_request
def guard():
    # Methods
    if request.method not in ("GET", "HEAD"):
        return Response("Only GET/HEAD allowed", status=405)

    # Public URLs
    public_paths = {"/login", "/oidc/callback", "/healthz", "/debug/upstream", "/debug/ssl", "/favicon.ico", "/whoami"}
    if request.path in public_paths or request.path.startswith("/static/"):
        return

    # Dev bypass
    if settings.ALLOW_ANON:
        return

    # Require login
    if not session.get("user"):
        # Remember target page
        session["post_login_redirect"] = request.full_path if request.query_string else request.path
        return redirect(url_for("login"))

# ---- Main catch-all reverse proxy (read-only) ----
#@app.route("/#/alerts", methods=["GET", "HEAD"])
@app.route("/<path:path>", methods=["GET", "HEAD"])
def catch_all(path=""):
    return proxy_get(settings.PROM_UPSTREAM, path)
