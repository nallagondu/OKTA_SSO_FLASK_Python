#wsgi.py
from app import app
from werkzeug.middleware.proxy_fix import ProxyFix

# Ensure ProxyFix is applied (defense-in-depth; app.py already applies it)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

if __name__ == "__main__":
    # For local debug only; production uses waitress/gunicorn behind NGINX
    app.run(host="127.0.0.1", port=8444, debug=False)

'''from app import app
from werkzeug.middleware.proxy_fix import ProxyFix

# Tell Flask it's behind a TLS proxy on 443 and to trust the headers NGINX sets
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1,
)

# Prefer https when building absolute URLs (url_for(..., _external=True))
app.config['PREFERRED_URL_SCHEME'] = 'https'

if __name__ == "__main__":
    # local/dev only; in prod you're running behind NGINX+Waitress
    app.run()
'''
