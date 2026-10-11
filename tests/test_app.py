"""Web app auth, limits, export, and error pages."""

import pytest
from fastapi.testclient import TestClient

from paste_spotlight.app import LIMITER, app
from paste_spotlight.auth import clear_revoked
from paste_spotlight.models import Hit, ProviderResult, Status
from paste_spotlight.search import STORE


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_PASSWORD", "correct-horse")
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-at-least-32-chars")
    LIMITER.reset()
    STORE.clear()
    clear_revoked()
    return TestClient(app)


def _login(client: TestClient, password: str = "correct-horse"):
    page = client.get("/login")
    assert page.status_code == 200
    token = client.cookies.get("pss_csrf")
    return client.post("/login", data={"password": password, "csrf": token, "next": "/"}, follow_redirects=False)


def test_health_is_public(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_search_requires_login(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_wrong_password_and_missing_configuration(client, monkeypatch):
    denied = _login(client, "nope")
    assert denied.status_code == 401
    assert "not correct" in denied.text
    assert "Traceback" not in denied.text

    monkeypatch.setenv("APP_ACCESS_PASSWORD", "")
    page = client.get("/login")
    token = client.cookies.get("pss_csrf")
    closed = client.post("/login", data={"password": "correct-horse", "csrf": token, "next": "/"})
    assert closed.status_code == 503
    assert "APP_ACCESS_PASSWORD" in closed.text


def test_search_shows_provider_status_and_exports_csv(client, monkeypatch):
    assert _login(client).status_code == 303

    def fake_search(query, provider_ids, http_client):
        assert query.text == "analyst@example.com"
        assert "brave_dorks" in provider_ids
        return [
            ProviderResult(
                provider_id="github_public",
                name="GitHub commits and repositories",
                status=Status.OK,
                message="GitHub returned 1 public result(s).",
                hits=[
                    Hit(
                        title="example/repo",
                        url="https://github.com/example/repo",
                        snippet="mention of analyst@example.com",
                        timestamp="2024-01-02T00:00:00Z",
                        source="github.com",
                    )
                ],
            ),
            ProviderResult(
                provider_id="brave_dorks",
                name="Brave Search dorks",
                status=Status.NEEDS_KEY,
                message="Set BRAVE_SEARCH_API_KEY.",
            ),
        ]

    monkeypatch.setattr("paste_spotlight.app.run_search", fake_search)
    page = client.get("/")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/search",
        data={
            "csrf": token,
            "q": "analyst@example.com",
            "kind": "email",
            "providers": ["github_public", "brave_dorks"],
        },
    )
    assert response.status_code == 200
    assert "needs key" in response.text
    assert "https://github.com/example/repo" in response.text
    assert "analyst@example.com" in response.text
    exported = client.post("/export.csv", data={"csrf": token})
    assert exported.status_code == 200
    assert "text/csv" in exported.headers["content-type"]
    assert "analyst@example.com" in exported.text
    assert "Brave Search dorks" in exported.text
    assert "Set BRAVE_SEARCH_API_KEY." in exported.text


def test_csv_neutralizes_formulas(client):
    assert _login(client).status_code == 303
    page = client.get("/")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    session = client.cookies.get("pss_session")
    assert session
    from paste_spotlight.auth import read_session

    sid = read_session(session)["sid"]
    STORE.put(
        sid,
        {
            "query": "example.com",
            "kind": "domain",
            "results": [
                {
                    "name": "GitHub",
                    "status": "ok",
                    "message": "ok",
                    "hits": [
                        {
                            "title": "=cmd()",
                            "url": "https://github.com/example/repo",
                            "snippet": "+1+1",
                            "timestamp": "",
                            "source": "github.com",
                        }
                    ],
                }
            ],
        },
    )
    exported = client.post("/export.csv", data={"csrf": token})
    assert "'=cmd()" in exported.text
    assert "'+1+1" in exported.text


def test_rejects_url_queries_without_searching(client, monkeypatch):
    assert _login(client).status_code == 303
    called = {"n": 0}

    def fake_search(*args, **kwargs):
        called["n"] += 1
        return []

    monkeypatch.setattr("paste_spotlight.app.run_search", fake_search)
    page = client.get("/")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/search",
        data={"csrf": token, "q": "http://169.254.169.254/latest/meta-data", "kind": "keyword", "providers": ["github_public"]},
    )
    assert response.status_code == 400
    assert called["n"] == 0
    assert "URL" in response.text


def test_rate_limit(client, monkeypatch):
    monkeypatch.setenv("SEARCHES_PER_HOUR", "1")
    monkeypatch.setenv("IP_SEARCHES_PER_HOUR", "1")
    assert _login(client).status_code == 303
    monkeypatch.setattr(
        "paste_spotlight.app.run_search",
        lambda *args, **kwargs: [
            ProviderResult("github_public", "GitHub", Status.NO_RESULTS, "none", [])
        ],
    )
    page = client.get("/")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    first = client.post(
        "/search",
        data={"csrf": token, "q": "example.com", "kind": "domain", "providers": ["github_public"]},
    )
    assert first.status_code == 200
    second = client.post(
        "/search",
        data={"csrf": token, "q": "example.com", "kind": "domain", "providers": ["github_public"]},
    )
    assert second.status_code == 429
    assert "Hourly search limit" in second.text


def test_unhandled_errors_hide_exception_text(client, monkeypatch):
    # Starlette re-raises after the 500 handler so servers can log it.
    # The browser still receives the friendly page, which this client captures.
    quiet = TestClient(app, raise_server_exceptions=False)
    assert _login(quiet).status_code == 303
    page = quiet.get("/")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    def explode(*args, **kwargs):
        raise RuntimeError("SUPER_SECRET_TRACE token=abc")

    monkeypatch.setattr("paste_spotlight.app.run_search", explode)
    response = quiet.post(
        "/search",
        data={"csrf": token, "q": "example.com", "kind": "domain", "providers": ["github_public"]},
    )
    assert response.status_code == 500
    assert "SUPER_SECRET_TRACE" not in response.text
    assert "Traceback" not in response.text


def test_unknown_page(client):
    response = client.get("/missing")
    assert response.status_code == 404
    assert "Traceback" not in response.text


def test_missing_session_secret_refuses_startup(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_PASSWORD", "correct-horse")
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        with TestClient(app) as probe:
            probe.get("/health")


def test_short_session_secret_refuses_startup(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_PASSWORD", "correct-horse")
    monkeypatch.setenv("SESSION_SECRET", "too-short")
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        with TestClient(app) as probe:
            probe.get("/health")


def test_duplicate_providers_run_once(client, monkeypatch):
    assert _login(client).status_code == 303
    seen = {}

    def fake_search(query, provider_ids, http_client):
        seen["ids"] = list(provider_ids)
        return [ProviderResult("github_public", "GitHub", Status.NO_RESULTS, "none", [])]

    monkeypatch.setattr("paste_spotlight.app.run_search", fake_search)
    page = client.get("/")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/search",
        data={
            "csrf": token,
            "q": "example.com",
            "kind": "domain",
            "providers": ["github_public", "nope", "github_public", "github_public"],
        },
    )
    assert response.status_code == 200
    assert seen["ids"] == ["github_public"]


def test_logout_revokes_the_session_cookie(client):
    assert _login(client).status_code == 303
    page = client.get("/")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    cookie = client.cookies.get("pss_session")
    assert cookie
    signed_out = client.post("/logout", data={"csrf": token}, follow_redirects=False)
    assert signed_out.status_code == 303
    client.cookies.set("pss_session", cookie)
    again = client.get("/", follow_redirects=False)
    assert again.status_code == 303
    assert again.headers["location"] == "/login"


def test_search_does_not_block_health(monkeypatch):
    import asyncio
    import time

    import httpx

    monkeypatch.setenv("APP_ACCESS_PASSWORD", "correct-horse")
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-at-least-32-chars")
    LIMITER.reset()
    clear_revoked()

    def slow_search(*args, **kwargs):
        time.sleep(4)
        return [ProviderResult("github_public", "GitHub", Status.NO_RESULTS, "slow", [])]

    monkeypatch.setattr("paste_spotlight.app.run_search", slow_search)

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            login_page = await http.get("/login")
            assert login_page.status_code == 200
            token = http.cookies.get("pss_csrf")
            signed_in = await http.post(
                "/login",
                data={"password": "correct-horse", "csrf": token, "next": "/"},
                follow_redirects=False,
            )
            assert signed_in.status_code == 303
            home = await http.get("/")
            csrf = home.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

            async def do_search():
                return await http.post(
                    "/search",
                    data={"csrf": csrf, "q": "example.com", "kind": "domain", "providers": ["github_public"]},
                )

            search_task = asyncio.create_task(do_search())
            await asyncio.sleep(0.3)
            started = time.perf_counter()
            health = await http.get("/health")
            elapsed = time.perf_counter() - started
            search_response = await search_task
            return health.status_code, elapsed, search_response.status_code

    status, elapsed, search_status = asyncio.run(scenario())
    assert status == 200
    assert elapsed < 1
    assert search_status == 200


def test_client_ip_uses_cloudflare_or_socket_peer():
    from paste_spotlight.ratelimit import client_ip

    class Peer:
        def __init__(self, host):
            self.host = host

    class Req:
        def __init__(self, headers, host):
            self.headers = headers
            self.client = Peer(host)

    cloudflare = Req(
        {"cf-connecting-ip": "203.0.113.50", "x-forwarded-for": "198.51.100.9, 10.0.0.4"},
        "10.0.0.4",
    )
    assert client_ip(cloudflare) == "203.0.113.50"

    forwarded_only = Req({"x-forwarded-for": "198.51.100.20"}, "10.0.0.8")
    assert client_ip(forwarded_only) == "10.0.0.8"

    invalid = Req({"cf-connecting-ip": "not-an-ip"}, "192.0.2.10")
    assert client_ip(invalid) == "192.0.2.10"
