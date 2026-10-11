"""Keep provider secrets out of log lines.

Google's Custom Search API only accepts the key as a query parameter. Logging that URL,
or an exception that embeds it, would expose the key. This filter strips those values.
"""

import logging
import os
import re

_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:key|api_key|access_token|client_secret|token)=)[^&\s\"']+"
)
_HEADER_SECRET = re.compile(
    r"(?i)((?:authorization|x-subscription-token|hibp-api-key|x-key)\s*[:=]\s*)\S+"
)
_SECRET_ENV = (
    "GOOGLE_CSE_API_KEY",
    "GOOGLE_CSE_ID",
    "BRAVE_SEARCH_API_KEY",
    "HIBP_API_KEY",
    "INTELX_API_KEY",
    "GITHUB_TOKEN",
    "SESSION_SECRET",
    "APP_ACCESS_PASSWORD",
)

_installed = False
_previous_factory = logging.getLogRecordFactory()


def redact(text: str) -> str:
    cleaned = _QUERY_SECRET.sub(r"\1REDACTED", text)
    cleaned = _HEADER_SECRET.sub(r"\1REDACTED", cleaned)
    for name in _SECRET_ENV:
        secret = os.environ.get(name, "").strip()
        if len(secret) >= 8 and secret in cleaned:
            cleaned = cleaned.replace(secret, "REDACTED")
    return cleaned


def _redact_arg(value):
    if isinstance(value, str):
        return redact(value)
    return value


def _redact_record(record: logging.LogRecord) -> None:
    """Rewrite the record before any handler, including ones attached later, sees it.

    Query-string redaction runs on the formatted message. Doing it earlier would
    eat ``%s`` placeholders and then crash the logger.
    """
    if isinstance(record.args, dict):
        record.args = {key: _redact_arg(value) for key, value in record.args.items()}
    elif isinstance(record.args, tuple):
        record.args = tuple(_redact_arg(value) for value in record.args)
    try:
        rendered = record.getMessage()
    except Exception:
        rendered = str(record.msg)
    extra = ""
    if record.exc_info:
        _typ, exc, _tb = record.exc_info
        record.exc_info = None
        record.exc_text = None
        if exc is not None:
            extra = " | " + redact(f"{type(exc).__name__}: {exc}")
    if record.stack_info:
        record.stack_info = redact(record.stack_info)
    if record.exc_text:
        record.exc_text = redact(record.exc_text)
    record.msg = redact(rendered) + extra
    record.args = None


def _record_factory(*args, **kwargs):
    record = _previous_factory(*args, **kwargs)
    _redact_record(record)
    return record


def install_log_redaction() -> None:
    global _installed
    if _installed:
        return
    logging.setLogRecordFactory(_record_factory)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    _installed = True
