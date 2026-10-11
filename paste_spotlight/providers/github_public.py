"""GitHub repository and commit search. Official API, no token required."""

import httpx

from paste_spotlight.config import env_value
from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.models import Hit, SearchQuery, Status
from paste_spotlight.providers.base import Provider
from paste_spotlight.textutil import clean_snippet

COMMITS = "https://api.github.com/search/commits"
REPOS = "https://api.github.com/search/repositories"


class GitHubPublic(Provider):
    id = "github_public"
    name = "GitHub commits and repositories"
    summary = (
        "Official search API for public commit messages and public repository names, descriptions, and topics. "
        "Queries include is:public and skip private repositories. "
        "Works without a token (about 10 searches a minute). File contents are a separate provider."
    )
    readiness = "ready"

    def search(self, query: SearchQuery, client: httpx.Client):
        phrase = query.text.replace('"', " ").strip()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = env_value("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        hits: list[Hit] = []
        notes: list[str] = []
        failures = 0
        incomplete = False
        for label, url in (("commits", COMMITS), ("repositories", REPOS)):
            try:
                response = guarded_request(
                    client,
                    "GET",
                    url,
                    params={"q": f'"{phrase}" is:public', "per_page": "5"},
                    headers=headers,
                )
            except UnsafeURL:
                return self.finish(Status.ERROR, "The GitHub request was blocked by the outbound allow-list.")
            except httpx.HTTPError:
                failures += 1
                notes.append(f"{label}: could not be reached")
                continue
            if response.status_code == 403 and "rate limit" in response.text.lower():
                return self.finish(
                    Status.BLOCKED,
                    "GitHub's unauthenticated search limit was reached (about 10 searches a minute). "
                    "Wait, or set GITHUB_TOKEN for a higher limit.",
                )
            if response.status_code != 200:
                failures += 1
                notes.append(f"{label}: HTTP {response.status_code}")
                continue
            try:
                payload = response.json()
            except ValueError:
                failures += 1
                notes.append(f"{label}: response was not JSON")
                continue
            if payload.get("incomplete_results") is True:
                incomplete = True
                notes.append(f"{label}: incomplete results")
            if label == "commits":
                hits.extend(_commit_hits(payload))
            else:
                hits.extend(_repo_hits(payload))

        scope = (
            "Matches public commit messages and public repository metadata. "
            "File contents are searched only by the GitHub code provider when GITHUB_TOKEN is set."
        )
        detail = (" " + " ".join(notes)) if notes else ""
        if failures and not hits:
            return self.finish(Status.ERROR, f"GitHub search failed.{detail} {scope}")
        if failures:
            return self.finish(
                Status.ERROR,
                f"Partial result. GitHub returned {len(hits)} public result(s), but a call failed.{detail} {scope}",
                hits,
            )
        if hits:
            prefix = "Partial result. " if incomplete else ""
            extra = " GitHub marked the result incomplete." if incomplete else ""
            return self.finish(Status.OK, f"{prefix}GitHub returned {len(hits)} public result(s). {scope}{extra}", hits)
        if incomplete:
            return self.finish(
                Status.NO_RESULTS,
                f"Partial result. No public commits or repositories matched. GitHub marked the result incomplete. {scope}",
            )
        return self.finish(Status.NO_RESULTS, f"No public commits or repositories matched. {scope}")


def _is_private(row: dict) -> bool:
    if row.get("private") is True:
        return True
    repository = row.get("repository")
    return isinstance(repository, dict) and repository.get("private") is True


def _commit_hits(payload: dict) -> list[Hit]:
    hits = []
    for row in (payload.get("items") or [])[:5]:
        if not isinstance(row, dict) or _is_private(row):
            continue
        commit = row.get("commit") or {}
        url = row.get("html_url") or ""
        if not url.startswith("https://github.com/"):
            continue
        repo = (row.get("repository") or {}).get("full_name") or "commit"
        hits.append(
            Hit(
                title=clean_snippet(f"{repo} {row.get('sha', '')[:7]}", 180),
                url=url,
                snippet=clean_snippet(commit.get("message") or ""),
                timestamp=((commit.get("author") or {}).get("date") or ""),
                source="github.com",
            )
        )
    return hits


def _repo_hits(payload: dict) -> list[Hit]:
    hits = []
    for row in (payload.get("items") or [])[:5]:
        if not isinstance(row, dict) or _is_private(row):
            continue
        url = row.get("html_url") or ""
        if not url.startswith("https://github.com/"):
            continue
        hits.append(
            Hit(
                title=clean_snippet(row.get("full_name") or url, 180),
                url=url,
                snippet=clean_snippet(row.get("description") or "Public repository"),
                timestamp=row.get("updated_at") or "",
                source="github.com",
            )
        )
    return hits
