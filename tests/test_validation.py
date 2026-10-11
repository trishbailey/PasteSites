"""Query validation and the outbound URL allow-list."""

import pytest

from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.validate import ValidationError, validate_query
import httpx


@pytest.mark.parametrize(
    "text,kind",
    [
        ("analyst@example.com", "email"),
        ("example.com", "domain"),
        ("beacon_ops", "username"),
        ("HelloWorldMessage", "keyword"),
    ],
)
def test_accepts_selectors(text, kind):
    query = validate_query(text, kind)
    assert query.text == text
    assert query.kind == kind


@pytest.mark.parametrize(
    "text,kind",
    [
        ("http://169.254.169.254/latest/meta-data", "keyword"),
        ("https://pastebin.com/raw/abc", "keyword"),
        ("//evil.example/path", "keyword"),
        ("not-an-email", "email"),
        ("http://example.com", "domain"),
        ("../etc/passwd", "username"),
        ("a", "keyword"),
        ("ok", "phone"),
        ("bad\nname", "keyword"),
    ],
)
def test_rejects_urls_and_malformed_selectors(text, kind):
    with pytest.raises(ValidationError):
        validate_query(text, kind)


def test_guard_blocks_user_supplied_host():
    def handler(request):
        raise AssertionError(f"should not fetch {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(UnsafeURL):
        guarded_request(client, "GET", "http://169.254.169.254/latest/meta-data")
    with pytest.raises(UnsafeURL):
        guarded_request(client, "GET", "https://example.com/paste")
