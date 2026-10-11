"""Mocked provider behavior."""

import logging

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
        assert "is:public" in request.url.params["q"]
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
                        "full_name": "example/secret",
                        "html_url": "https://github.com/example/secret",
                        "description": "Private",
                        "private": True,
                        "updated_at": "2024-06-01T00:00:00Z",
                    },
                    {
                        "full_name": "example/HelloWorldMessage",
                        "html_url": "https://github.com/example/HelloWorldMessage",
                        "description": "A public demo repository",
                        "private": False,
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
    assert "https://github.com/example/secret" not in [hit.url for hit in result.hits]


def test_github_public_error_when_a_call_fails_with_no_hits():
    def handler(request: httpx.Request):
        if request.url.path.endswith("/commits"):
            return httpx.Response(500, text="nope")
        return httpx.Response(200, json={"items": []})

    result = GitHubPublic().search(SearchQuery("example.com", "domain"), client_for(handler))
    assert result.status is Status.ERROR
    assert result.hits == []


def test_github_public_flags_incomplete_and_partial_failure():
    def incomplete(request: httpx.Request):
        return httpx.Response(
            200,
            json={
                "incomplete_results": True,
                "items": [
                    {
                        "full_name": "example/HelloWorldMessage",
                        "html_url": "https://github.com/example/HelloWorldMessage",
                        "description": "A public demo repository",
                        "updated_at": "2024-06-01T00:00:00Z",
                    }
                ],
            },
        )

    partial = GitHubPublic().search(SearchQuery("HelloWorldMessage", "keyword"), client_for(incomplete))
    assert partial.status is Status.OK
    assert "partial" in partial.message.lower()

    def failed(request: httpx.Request):
        if request.url.path.endswith("/commits"):
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "sha": "abcdef1234567890",
                            "html_url": "https://github.com/example/repo/commit/abcdef1234567890",
                            "commit": {"message": "public hit", "author": {"date": "2024-05-01T00:00:00Z"}},
                            "repository": {"full_name": "example/repo", "private": False},
                        }
                    ]
                },
            )
        return httpx.Response(502, text="bad gateway")

    broken = GitHubPublic().search(SearchQuery("HelloWorldMessage", "keyword"), client_for(failed))
    assert broken.status is Status.ERROR
    assert broken.hits
    assert "partial" in broken.message.lower()


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
        assert "is:public" in request.url.params["q"]
        return httpx.Response(
            200,
            json={
                "incomplete_results": True,
                "items": [
                    {
                        "name": "secret.py",
                        "path": "src/secret.py",
                        "html_url": "https://github.com/example/private/blob/main/src/secret.py",
                        "repository": {"full_name": "example/private", "private": True},
                        "text_matches": [{"fragment": "hidden"}],
                    },
                    {
                        "name": "app.py",
                        "path": "src/app.py",
                        "html_url": "https://github.com/example/repo/blob/main/src/app.py",
                        "repository": {"full_name": "example/repo", "private": False},
                        "text_matches": [{"fragment": "contact ops@example.com"}],
                    }
                ]
            },
        )

    result = GitHubCode().search(SearchQuery("ops@example.com", "email"), client_for(handler))
    assert result.status is Status.OK
    assert "ops@example.com" in result.hits[0].snippet
    assert "partial" in result.message.lower()
    assert len(result.hits) == 1


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
    assert skipped.status is Status.SKIPPED
    assert "skipped" in skipped.message.lower()
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
                    "status": 1,
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
    assert any(path.endswith("/terminate") for path in paths)


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


def test_brave_query_rejection_does_not_blame_the_key(monkeypatch):
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "test-key")
    result = BraveDorks().search(
        SearchQuery("example.com", "domain"),
        client_for(lambda request: httpx.Response(422, json={"error": "query too long"})),
    )
    assert result.status is Status.ERROR
    assert "query" in result.message.lower()
    assert "api key" not in result.message.lower()


def test_google_key_is_not_logged(monkeypatch, caplog):
    from paste_spotlight.logutil import install_log_redaction

    secret = "super-secret-google-key"
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", secret)
    monkeypatch.setenv("GOOGLE_CSE_ID", "search-engine-id")
    install_log_redaction()
    caplog.set_level(logging.DEBUG)
    logging.getLogger("paste_spotlight").error(
        "request failed https://www.googleapis.com/customsearch/v1?key=%s&cx=search-engine-id",
        secret,
    )
    try:
        raise RuntimeError(f"https://www.googleapis.com/customsearch/v1?key={secret}")
    except RuntimeError:
        logging.getLogger("paste_spotlight").exception("google call failed")
    GoogleCse().search(
        SearchQuery("example.com", "domain"),
        client_for(lambda request: httpx.Response(500, text="nope")),
    )
    assert secret not in caplog.text
    assert "key=REDACTED" in caplog.text


def test_intelx_polls_until_finished_and_terminates(monkeypatch):
    monkeypatch.setenv("INTELX_API_KEY", "ix-test")
    monkeypatch.setenv("INTELX_API_URL", "https://free.intelx.io")
    monkeypatch.setattr("paste_spotlight.providers.intelx.time.sleep", lambda seconds: None)
    polls = {"n": 0}
    paths = []

    def handler(request: httpx.Request):
        paths.append(request.url.path)
        if request.url.path.endswith("/result"):
            polls["n"] += 1
            if polls["n"] == 1:
                return httpx.Response(200, json={"status": 0, "records": []})
            if polls["n"] == 2:
                return httpx.Response(200, json={"status": 3, "records": []})
            return httpx.Response(
                200,
                json={
                    "status": 1,
                    "records": [
                        {
                            "name": "paste-record",
                            "date": "2020-01-02T00:00:00Z",
                            "bucket": "pastes",
                            "systemid": "8f1c0b2e-1111-2222-3333-abcdefabcdef",
                        }
                    ],
                },
            )
        if request.url.path.endswith("/intelligent/search"):
            return httpx.Response(200, json={"id": "8f1c0b2e-1111-2222-3333-abcdefabcdef"})
        return httpx.Response(200, json={"status": 0})

    result = IntelX().search(SearchQuery("example.com", "domain"), client_for(handler))
    assert polls["n"] == 3
    assert result.status is Status.OK
    assert any(path.endswith("/terminate") for path in paths)


def test_intelx_timeout_is_an_error_not_empty(monkeypatch):
    monkeypatch.setenv("INTELX_API_KEY", "ix-test")
    monkeypatch.setenv("INTELX_API_URL", "https://free.intelx.io")
    clock = {"t": 1000.0}
    monkeypatch.setattr("paste_spotlight.providers.intelx.time.monotonic", lambda: clock["t"])

    def sleep(seconds):
        clock["t"] += seconds

    monkeypatch.setattr("paste_spotlight.providers.intelx.time.sleep", sleep)
    paths = []
    polls = {"n": 0}

    def handler(request: httpx.Request):
        paths.append(request.url.path)
        if request.url.path.endswith("/result"):
            polls["n"] += 1
            if polls["n"] == 1:
                return httpx.Response(
                    200,
                    json={
                        "status": 0,
                        "records": [
                            {
                                "name": "early-record",
                                "date": "2020-01-02T00:00:00Z",
                                "bucket": "pastes",
                                "systemid": "8f1c0b2e-1111-2222-3333-abcdefabcdef",
                            }
                        ],
                    },
                )
            return httpx.Response(200, json={"status": 3, "records": []})
        if request.url.path.endswith("/intelligent/search"):
            return httpx.Response(200, json={"id": "8f1c0b2e-1111-2222-3333-abcdefabcdef"})
        return httpx.Response(200, json={"status": 0})

    result = IntelX().search(SearchQuery("example.com", "domain"), client_for(handler))
    assert result.status is Status.ERROR
    assert "timed out" in result.message
    assert result.hits
    assert any(path.endswith("/terminate") for path in paths)


def test_intelx_terminates_when_the_result_call_fails(monkeypatch):
    monkeypatch.setenv("INTELX_API_KEY", "ix-test")
    monkeypatch.setenv("INTELX_API_URL", "https://free.intelx.io")
    paths = []

    def handler(request: httpx.Request):
        paths.append(request.url.path)
        if request.url.path.endswith("/result"):
            return httpx.Response(500, text="nope")
        if request.url.path.endswith("/intelligent/search"):
            return httpx.Response(200, json={"id": "8f1c0b2e-1111-2222-3333-abcdefabcdef"})
        return httpx.Response(200, json={"status": 0})

    result = IntelX().search(SearchQuery("example.com", "domain"), client_for(handler))
    assert result.status is Status.ERROR
    assert any(path.endswith("/terminate") for path in paths)

