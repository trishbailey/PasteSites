"""Mocked provider behavior."""

import httpx

from paste_spotlight.models import SearchQuery, Status
from paste_spotlight.providers.brave_dorks import BraveDorks
from paste_spotlight.providers.github_code import GitHubCode
from paste_spotlight.providers.github_gist import GitHubGist, _star_disallows
from paste_spotlight.providers.github_public import GitHubPublic
from paste_spotlight.providers.google_cse import GoogleCse
from paste_spotlight.providers.hibp import Hibp
from paste_spotlight.providers.intelx import IntelX
from paste_spotlight.providers.pastebin_scrape import PastebinScrape
from paste_spotlight.providers.psbdmp import Psbdmp
from paste_spotlight.sites import DORK_SITES


def client_for(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_dork_sites_are_paste_hosts_only():
    blob = " ".join(DORK_SITES)
    for excluded in ("doxbin.com", "breachforums", "xss.is", "kiwifarms"):
        assert excluded not in blob
    assert "pastebin.com" in DORK_SITES
    assert "gist.github.com" in DORK_SITES
    assert "rentry.co" in DORK_SITES


def test_brave_needs_key(monkeypatch):
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    result = BraveDorks().search(SearchQuery("example.com", "domain"), client_for(lambda request: httpx.Response(500)))
    assert result.status is Status.NEEDS_KEY
    assert "BRAVE_SEARCH_API_KEY" in result.message


def test_brave_returns_hits(monkeypatch):
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "test-key")
    seen = {}

    def handler(request: httpx.Request):
        seen["host"] = request.url.host
        seen["q"] = request.url.params["q"]
        assert request.headers["X-Subscription-Token"] == "test-key"
        return httpx.Response(
            200,
            json={
                "web": {
                    "results": [
                        {
                            "title": "Example paste",
                            "url": "https://pastebin.com/cxiuQk6P",
                            "description": "HelloWorldMessage in a public paste",
                            "page_age": "2016-01-22",
                            "meta_url": {"hostname": "pastebin.com"},
                        }
                    ]
                }
            },
        )

    result = BraveDorks().search(SearchQuery("HelloWorldMessage", "keyword"), client_for(handler))
    assert seen["host"] == "api.search.brave.com"
    assert "site:pastebin.com" in seen["q"]
    assert "site:rentry.co" in seen["q"]
    assert result.status is Status.OK
    assert result.hits[0].url == "https://pastebin.com/cxiuQk6P"
    assert result.hits[0].timestamp == "2016-01-22"


def test_brave_rate_limit(monkeypatch):
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "test-key")
    result = BraveDorks().search(
        SearchQuery("example.com", "domain"),
        client_for(lambda request: httpx.Response(429, json={"error": "slow down"})),
    )
    assert result.status is Status.BLOCKED


def test_google_needs_both_keys(monkeypatch):
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "key-only")
    monkeypatch.delenv("GOOGLE_CSE_ID", raising=False)
    result = GoogleCse().search(SearchQuery("example.com", "domain"), client_for(lambda request: httpx.Response(200)))
    assert result.status is Status.NEEDS_KEY


def test_google_empty_items_are_reported(monkeypatch):
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "key")
    monkeypatch.setenv("GOOGLE_CSE_ID", "cx")
    result = GoogleCse().search(
        SearchQuery("HelloWorldMessage", "keyword"),
        client_for(lambda request: httpx.Response(200, json={"items": []})),
    )
    assert result.status is Status.NO_RESULTS
    assert result.hits == []


def test_google_rejects_bad_key(monkeypatch):
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "key")
    monkeypatch.setenv("GOOGLE_CSE_ID", "cx")
    result = GoogleCse().search(
        SearchQuery("example.com", "domain"),
        client_for(lambda request: httpx.Response(403, json={"error": {"message": "forbidden"}})),
    )
    assert result.status is Status.ERROR


def test_github_public_parses_commits_and_repos():
    def handler(request: httpx.Request):
        if request.url.path.endswith("/commits"):
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "sha": "abcdef1234567890",
                            "html_url": "https://github.com/example/repo/commit/abcdef1234567890",
                            "commit": {
                                "message": "Add HelloWorldMessage helper",
                                "author": {"date": "2024-05-01T00:00:00Z"},
                            },
                            "repository": {"full_name": "example/repo"},
                        }
                    ]
                },
            )
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "full_name": "example/HelloWorldMessage",
                        "html_url": "https://github.com/example/HelloWorldMessage",
                        "description": "A public demo repository",
                        "updated_at": "2024-06-01T00:00:00Z",
                    }
                ]
            },
        )

    result = GitHubPublic().search(SearchQuery("HelloWorldMessage", "keyword"), client_for(handler))
    assert result.status is Status.OK
    assert len(result.hits) == 2
    assert result.hits[0].timestamp == "2024-05-01T00:00:00Z"
    assert "commit messages" in result.message


def test_github_public_rate_limit():
    result = GitHubPublic().search(
        SearchQuery("example.com", "domain"),
        client_for(lambda request: httpx.Response(403, text="API rate limit exceeded")),
    )
    assert result.status is Status.BLOCKED


def test_github_code_needs_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    result = GitHubCode().search(SearchQuery("example.com", "domain"), client_for(lambda request: httpx.Response(401)))
    assert result.status is Status.NEEDS_KEY


def test_github_code_uses_text_match(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "gh-test")

    def handler(request: httpx.Request):
        assert request.headers["Authorization"] == "Bearer gh-test"
        assert request.url.host == "api.github.com"
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "name": "app.py",
                        "path": "src/app.py",
                        "html_url": "https://github.com/example/repo/blob/main/src/app.py",
                        "repository": {"full_name": "example/repo"},
                        "text_matches": [{"fragment": "contact ops@example.com"}],
                    }
                ]
            },
        )

    result = GitHubCode().search(SearchQuery("ops@example.com", "email"), client_for(handler))
    assert result.status is Status.OK
    assert "ops@example.com" in result.hits[0].snippet


def test_gist_reports_robots_block():
    robots = "User-agent: *\nDisallow: /gist/\nDisallow: /search$\n"

    def handler(request: httpx.Request):
        assert request.url.host == "github.com"
        assert "HelloWorld" not in str(request.url)
        return httpx.Response(200, text=robots)

    result = GitHubGist().search(SearchQuery("HelloWorldMessage", "keyword"), client_for(handler))
    assert result.status is Status.BLOCKED
    assert "does not scrape" in result.message
    assert "/gist/" in _star_disallows(robots)


def test_hibp_needs_key_and_skips_non_email(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return httpx.Response(200, json=[])

    assert Hibp().search(SearchQuery("a@example.com", "email"), client_for(handler)).status is Status.NEEDS_KEY
    monkeypatch.setenv("HIBP_API_KEY", "hibp-test")
    skipped = Hibp().search(SearchQuery("example.com", "domain"), client_for(handler))
    assert skipped.status is Status.NO_RESULTS
    assert called["n"] == 0
    assert "email" in skipped.message


def test_hibp_paste_and_breach(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "hibp-test")

    def handler(request: httpx.Request):
        assert request.url.host == "haveibeenpwned.com"
        if "pasteaccount" in request.url.path:
            return httpx.Response(
                200,
                json=[{"Source": "Pastebin", "Id": "cxiuQk6P", "Title": "Hello world", "Date": "2016-01-22", "EmailCount": 1}],
            )
        return httpx.Response(
            200,
            json=[{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "Description": "<p>Test breach.</p>", "DataClasses": ["Email addresses"]}],
        )

    result = Hibp().search(SearchQuery("person@example.com", "email"), client_for(handler))
    assert result.status is Status.OK
    assert result.hits[0].url == "https://pastebin.com/cxiuQk6P"
    assert "<p>" not in result.hits[1].snippet


def test_hibp_not_found(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "hibp-test")
    result = Hibp().search(
        SearchQuery("nobody@example.com", "email"),
        client_for(lambda request: httpx.Response(404, json={"statusCode": 404})),
    )
    assert result.status is Status.NO_RESULTS


def test_intelx_needs_key(monkeypatch):
    monkeypatch.delenv("INTELX_API_KEY", raising=False)
    result = IntelX().search(SearchQuery("example.com", "domain"), client_for(lambda request: httpx.Response(200)))
    assert result.status is Status.NEEDS_KEY


def test_intelx_rejects_off_allowlist_host(monkeypatch):
    monkeypatch.setenv("INTELX_API_KEY", "ix-test")
    monkeypatch.setenv("INTELX_API_URL", "https://169.254.169.254/latest/meta-data")
    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return httpx.Response(200, json={})

    result = IntelX().search(SearchQuery("example.com", "domain"), client_for(handler))
    assert called["n"] == 0
    assert result.status is Status.ERROR
    assert "169.254.169.254" not in result.message


def test_intelx_metadata_only(monkeypatch):
    monkeypatch.setenv("INTELX_API_KEY", "ix-test")
    monkeypatch.setenv("INTELX_API_URL", "https://free.intelx.io")
    monkeypatch.delenv("INTELX_BUCKETS", raising=False)
    paths = []

    def handler(request: httpx.Request):
        paths.append(request.url.path)
        assert request.url.host == "free.intelx.io"
        if request.url.path.endswith("/intelligent/search"):
            return httpx.Response(200, json={"id": "8f1c0b2e-1111-2222-3333-abcdefabcdef"})
        if request.url.path.endswith("/result"):
            return httpx.Response(
                200,
                json={
                    "records": [
                        {
                            "name": "paste-record",
                            "date": "2020-01-02T00:00:00Z",
                            "bucket": "pastes",
                            "systemid": "8f1c0b2e-1111-2222-3333-abcdefabcdef",
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"status": 0})

    result = IntelX().search(SearchQuery("example.com", "domain"), client_for(handler))
    assert result.status is Status.OK
    assert result.hits[0].url.startswith("https://intelx.io/?did=")
    assert "/file/read" not in " ".join(paths)
    assert "/file/view" not in " ".join(paths)


def test_pastebin_disabled_by_default(monkeypatch):
    monkeypatch.delenv("PASTEBIN_SCRAPING_ENABLED", raising=False)
    result = PastebinScrape().search(SearchQuery("example.com", "domain"), client_for(lambda request: httpx.Response(200)))
    assert result.status is Status.NEEDS_KEY
    assert "whitelist" in result.message.lower()


def test_pastebin_blocked_ip_and_title_match(monkeypatch):
    monkeypatch.setenv("PASTEBIN_SCRAPING_ENABLED", "true")
    monkeypatch.setenv("PASTEBIN_SCRAPE_DELAY", "0")
    blocked = PastebinScrape().search(
        SearchQuery("example.com", "domain"),
        client_for(lambda request: httpx.Response(403, text="Forbidden: YOUR IP DOES NOT HAVE ACCESS")),
    )
    assert blocked.status is Status.BLOCKED

    def handler(request: httpx.Request):
        assert request.url.host == "scrape.pastebin.com"
        assert "example.com" not in request.url.path
        if request.url.path.endswith("api_scraping.php"):
            return httpx.Response(
                200,
                json=[{"key": "cxiuQk6P", "title": "notes for example.com", "date": "1700000000", "syntax": "text"}],
            )
        raise AssertionError("body fetch is unnecessary for a title match")

    found = PastebinScrape().search(SearchQuery("example.com", "domain"), client_for(handler))
    assert found.status is Status.OK
    assert found.hits[0].url == "https://pastebin.com/cxiuQk6P"


def test_psbdmp_does_not_send_the_query():
    def handler(request: httpx.Request):
        assert "HelloWorldMessage" not in str(request.url)
        if request.url.host == "psbdmp.ws":
            raise httpx.ConnectError("No address associated with hostname")
        return httpx.Response(200, json={"info": {"title": "Weakpass - API", "description": "hash-password pairs"}})

    result = Psbdmp().search(SearchQuery("HelloWorldMessage", "keyword"), client_for(handler))
    assert result.status is Status.BLOCKED
    assert "Weakpass" in result.message
    assert "No paste query was sent" in result.message

