"""Snippet cleanup. Display text only; nothing here fetches a URL."""

import re

_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")


def clean_snippet(text: str, limit: int = 280) -> str:
    flattened = _SPACE_RE.sub(" ", text or "").strip()
    if len(flattened) <= limit:
        return flattened
    return flattened[: limit - 1].rstrip() + "…"


def strip_tags(text: str) -> str:
    return _TAG_RE.sub(" ", text or "")


def window(text: str, query: str, radius: int = 110) -> str:
    """Return a short window around the first match."""
    if not text:
        return ""
    lowered = text.lower()
    needle = (query or "").lower()
    idx = lowered.find(needle) if needle else -1
    if idx < 0:
        return clean_snippet(text)
    start = max(0, idx - radius)
    end = min(len(text), idx + len(query) + radius)
    piece = text[start:end]
    if start:
        piece = "…" + piece
    if end < len(text):
        piece = piece + "…"
    return clean_snippet(piece)
