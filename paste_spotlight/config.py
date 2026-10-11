"""Environment configuration. Secrets are read at call time and never hardcoded."""

import os

DEFAULT_SEARCHES_PER_HOUR = 8
DEFAULT_IP_SEARCHES_PER_HOUR = 12
DEFAULT_LOGIN_ATTEMPTS_PER_HOUR = 10


def _int_env(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(low, min(value, high))


def access_password() -> str:
    return os.environ.get("APP_ACCESS_PASSWORD", "").strip()


def session_secret() -> bytes:
    explicit = os.environ.get("SESSION_SECRET", "").strip()
    if len(explicit) < 32:
        raise RuntimeError(
            "SESSION_SECRET must be set to a random string of at least 32 characters. "
            "The app will not start without it."
        )
    return explicit.encode("utf-8")


def searches_per_hour() -> int:
    return _int_env("SEARCHES_PER_HOUR", DEFAULT_SEARCHES_PER_HOUR, 1, 60)


def ip_searches_per_hour() -> int:
    return _int_env("IP_SEARCHES_PER_HOUR", DEFAULT_IP_SEARCHES_PER_HOUR, 1, 120)


def login_attempts_per_hour() -> int:
    return _int_env("LOGIN_ATTEMPTS_PER_HOUR", DEFAULT_LOGIN_ATTEMPTS_PER_HOUR, 3, 30)


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def env_value(name: str) -> str:
    return os.environ.get(name, "").strip()
