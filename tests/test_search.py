"""Search deadline and provider selection."""

import time

import httpx

from paste_spotlight.deadline import seconds_left
from paste_spotlight.models import SearchQuery, Status
from paste_spotlight.providers.github_public import GitHubPublic
from paste_spotlight.search import normalize_provider_ids, run_search


def test_provider_ids_are_deduped_and_capped():
    assert normalize_provider_ids(["github_public", "github_public", "nope", "hibp"]) == ["github_public", "hibp"]
    assert normalize_provider_ids(["nope"] * 20 + ["github_public"]) == []
    selected = normalize_provider_ids(["github_public", "hibp", "intelx"] * 10)
    assert selected == ["github_public", "hibp", "intelx"]


def test_unfinished_provider_times_out(monkeypatch):
    monkeypatch.setattr("paste_spotlight.search.SEARCH_DEADLINE_SECONDS", 0.2)

    def slow(self, query, client):
        time.sleep(0.8)
        return self.finish(Status.NO_RESULTS, "late")

    monkeypatch.setattr(GitHubPublic, "search", slow)
    with httpx.Client() as http:
        results = run_search(SearchQuery("example.com", "domain"), ["github_public", "github_public"], http)
    assert len(results) == 1
    assert results[0].status is Status.ERROR
    assert "timed out" in results[0].message


def test_deadline_is_visible_to_the_provider(monkeypatch):
    seen = {}

    def fake(self, query, client):
        seen["left"] = seconds_left()
        return self.finish(Status.NO_RESULTS, "none")

    monkeypatch.setattr(GitHubPublic, "search", fake)
    with httpx.Client() as http:
        run_search(SearchQuery("example.com", "domain"), ["github_public"], http)
    assert seen["left"] is not None
    assert 0 < seen["left"] <= 25
