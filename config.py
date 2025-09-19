import os
import pathlib
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

def _env_or_default(name: str, default: str) -> str:
    val = os.getenv(name, default)
    return val.rstrip("/") if isinstance(val, str) else default.rstrip("/")

def _env_required(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise RuntimeError(f"Missing required env var: {name}")
    return val.rstrip("/")

def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name, str(default)).lower()
    return val in ("true", "1", "yes")

def _env_int(name: str, default: int = 0) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default

class Settings:
    # General
    ENV_NAME = os.getenv("ENV_NAME", "production")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

    # Secrets
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())

    # Public URL
    PUBLIC_BASE_URL = _env_or_default("PUBLIC_BASE_URL", "http://127.0.0.1:8444")
    DEFAULT_REDIRECT_PATH = os.getenv("DEFAULT_REDIRECT_PATH", "/#/alerts")

    # Okta OIDC
    OKTA_ISSUER = _env_required("OKTA_ISSUER")
    OKTA_DISCOVERY = f"{OKTA_ISSUER}/.well-known/openid-configuration"
    OKTA_CLIENT_ID = _env_required("OKTA_CLIENT_ID")
    OKTA_CLIENT_SECRET = _env_required("OKTA_CLIENT_SECRET")
    OKTA_SCOPES = os.getenv("OKTA_SCOPES", "openid profile email")

    # Upstream (Prometheus/Alertmanager)
    PROM_UPSTREAM = _env_or_default("PROMETHEUS_UPSTREAM", "http://127.0.0.1:9093")
    PROM_VERIFY_TLS = _env_bool("PROMETHEUS_VERIFY_TLS", True)
    PROM_CA_BUNDLE = os.getenv("PROMETHEUS_CA_BUNDLE")  # path to CA chain file
    CERT_PATH = os.getenv("CERT_PATH")                  # optional client cert bundle

    # Session
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", True)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_env_int("SESSION_LIFETIME_MIN", 480))

    # Access control
    ALLOW_ANON = _env_bool("ALLOW_ANON", False)

    def resolve_verify_path(self):
        """
        Decide what to pass as 'verify' to requests:
          - If PROM_CA_BUNDLE exists -> use it
          - elif CERT_PATH exists     -> use it
          - elif PROM_VERIFY_TLS==False -> False
          - else -> True (system store)
        """
        if self.PROM_CA_BUNDLE:
            p = pathlib.Path(self.PROM_CA_BUNDLE)
            if p.exists() and p.is_file():
                return str(p)
        if self.CERT_PATH:
            p = pathlib.Path(self.CERT_PATH)
            if p.exists() and p.is_file():
                return str(p)
        if self.PROM_VERIFY_TLS is False:
            return False
        return True

settings = Settings()
