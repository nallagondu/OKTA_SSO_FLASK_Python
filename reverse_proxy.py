#reverse_proxy.py
from flask import Response, request, stream_with_context, current_app
import requests
from urllib.parse import urljoin, urlsplit
import traceback

from config import settings

BLOCKED_HEADERS = {"connection", "content-length", "transfer-encoding", "content-encoding"}

def proxy_get(upstream_base: str, path: str):
    if request.method not in ("GET", "HEAD"):
        return Response("Only GET/HEAD allowed", status=405)

    upstream_url = urljoin(upstream_base.rstrip("/") + "/", path)

    # Forward headers but never Authorization to the upstream
    headers = {k: v for k, v in request.headers.items() if k.lower() != "authorization"}
    headers["Host"] = urlsplit(upstream_url).netloc
    headers["Connection"] = "close"

    s = requests.Session()
    s.trust_env = False  # ignore corporate proxies

    verify = settings.resolve_verify_path()

    try:
        upstream_resp = s.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            params=request.args,
            stream=True,
            timeout=30,
            allow_redirects=False,
            verify=verify,
        )
    except Exception as e:
        msg = (
            f"Upstream request failed\n"
            f"URL: {upstream_url}\n"
            f"verify: {verify}\n"
            f"PROM_CA_BUNDLE: {settings.PROM_CA_BUNDLE}\n"
            f"CERT_PATH: {getattr(settings, 'CERT_PATH', None)}\n"
            f"Error: {repr(e)}\n\n{traceback.format_exc()}"
        )
        current_app.logger.error(msg)
        return Response(msg, status=502, mimetype="text/plain")

    def generate():
        for chunk in upstream_resp.iter_content(chunk_size=64 * 1024):
            if chunk:
                yield chunk

    # Strip hop-by-hop headers
    resp_headers = [(k, v) for k, v in upstream_resp.headers.items() if k.lower() not in BLOCKED_HEADERS]
    body = stream_with_context(generate()) if request.method == "GET" else b""
    return Response(body, status=upstream_resp.status_code, headers=resp_headers, direct_passthrough=True)
