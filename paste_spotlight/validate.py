"""Server-side query validation."""

import re

from paste_spotlight.models import SearchQuery

KINDS = ("email", "domain", "username", "keyword")

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class ValidationError(ValueError):
    pass


def validate_query(text: str, kind: str) -> SearchQuery:
    kind = (kind or "").strip().lower()
    if kind not in KINDS:
        raise ValidationError("Choose email, domain, username, or keyword.")
    cleaned = " ".join((text or "").split())
    if _CONTROL_RE.search(text or ""):
        raise ValidationError("The query contains characters this tool does not accept.")
    if "://" in cleaned or cleaned.startswith("//"):
        raise ValidationError("Enter a selector, not a URL. This tool does not fetch links you type.")
    if len(cleaned) < 2 or len(cleaned) > 200:
        raise ValidationError("Use a query between 2 and 200 characters.")
    if not re.search(r"[A-Za-z0-9]", cleaned):
        raise ValidationError("Use a query that contains letters or numbers.")

    if kind == "email" and not _EMAIL_RE.fullmatch(cleaned):
        raise ValidationError("That does not look like an email address.")
    elif kind == "domain":
        if "@" in cleaned or not _DOMAIN_RE.fullmatch(cleaned):
            raise ValidationError("That does not look like a domain name.")
    elif kind == "username" and not _USERNAME_RE.fullmatch(cleaned):
        raise ValidationError("Usernames can use letters, numbers, dots, underscores, and hyphens.")
    return SearchQuery(text=cleaned, kind=kind)
