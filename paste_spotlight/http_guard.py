"""Allow-list for outbound provider calls.

User queries are never used as request URLs. Redirects are not followed.
"""

from urllib.parse import urlsplit

import httpx

ALLOWED_HOSTS = frozenset(
    {
        "api.search.brave.com",
        "www.googleapis.com",
        "api.github.com",
        "github.com",
        "haveibeenpwned.com",
        "free.intelx.io",
        "2.intelx.io",
        "public.intelx.io",
        "scrape.pastebin.com",
        "psbdmp.ws",
        "psbdmp.cc",
    }
)


class UnsafeURL(Exception):
    """The provider tried to call a host this app does not allow."""


def guarded_request(client: httpx.Client, method: str, url: str, **kwargs) -> httpx.Response:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in ALLOWED_HOSTS:
        raise UnsafeURL("That provider URL is not on the allow-list.")
    if parsed.username or parsed.password:
        raise UnsafeURL("Provider URLs cannot embed credentials.")
    kwargs["follow_redirects"] = False
    return client.request(method, url, **kwargs)


def make_client() -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(12.0, connect=5.0),
        trust_env=False,
        headers={
            "User-Agent": "Paste-Site-Spotlight/1.0 (+https://beaconintelligencegroup.com/)",
            "Accept": "application/json,text/plain;q=0.8,*/*;q=0.5",
        },
        follow_redirects=False,
    )
