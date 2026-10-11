"""Gist availability. The website search is disallowed by GitHub's robots.txt."""

import httpx

from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.models import SearchQuery, Status
from paste_spotlight.providers.base import Provider

ROBOTS = "https://github.com/robots.txt"


class GitHubGist(Provider):
    id = "github_gist"
    name = "GitHub Gist"
    summary = (
        "Checks GitHub's robots.txt and reports whether gist content can be searched "
        "through an allowed API. This provider does not scrape gist.github.com."
    )
    readiness = "status_only"

    def search(self, query: SearchQuery, client: httpx.Client):
        del query
        try:
            response = guarded_request(client, "GET", ROBOTS, headers={"Accept": "text/plain"})
        except UnsafeURL:
            return self.finish(Status.ERROR, "The robots.txt request was blocked by the outbound allow-list.")
        except httpx.HTTPError:
            return self.finish(Status.ERROR, "GitHub robots.txt could not be reached, so gist search was not attempted.")

        if response.status_code != 200:
            return self.finish(
                Status.ERROR,
                f"GitHub robots.txt returned HTTP {response.status_code}. Gist search was not attempted.",
            )
        rules = _star_disallows(response.text)
        blocked_paths = [rule for rule in rules if rule.startswith("/gist") or rule.startswith("/search")]
        if blocked_paths:
            shown = ", ".join(blocked_paths[:4])
            return self.finish(
                Status.BLOCKED,
                "GitHub's robots.txt for User-agent: * disallows "
                f"{shown}. The REST API has no gist-content search, and code search does not index gists. "
                "This tool does not scrape gist.github.com. Use Brave or Google dorks, which include "
                "site:gist.github.com, for gist pages those engines have indexed.",
            )
        return self.finish(
            Status.BLOCKED,
            "GitHub's public REST API still has no gist-content search. "
            "This tool does not scrape gist.github.com. Indexed gist pages are covered by the dork providers.",
        )


def _star_disallows(robots: str) -> list[str]:
    """Return Disallow paths from the User-agent: * group."""
    agents: list[str] = []
    rules: list[str] = []
    groups: list[tuple[list[str], list[str]]] = []

    def flush() -> None:
        nonlocal agents, rules
        if agents:
            groups.append((agents, rules))
        agents = []
        rules = []

    for raw in robots.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            if rules:
                flush()
            agents.append(value)
        elif key == "disallow":
            rules.append(value)
    flush()
    for group_agents, group_rules in groups:
        if "*" in group_agents:
            return group_rules
    return []
