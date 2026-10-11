"""Web app auth, limits, export, and error pages."""

import pytest
from fastapi.testclient import TestClient

from paste_spotlight.app import LIMITER, app
from paste_spotlight.models import Hit, ProviderResult, Status
from paste_spotlight.search import STORE


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("APP_ACCESS_PASSWORD", "correct-horse")
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    LIMITER.reset()
    STORE.clear()
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
