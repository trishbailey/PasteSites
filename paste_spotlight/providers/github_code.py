"""GitHub code search. Requires a token. Does not index gist contents."""

import httpx

from paste_spotlight.config import env_value
from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.models import Hit, SearchQuery, Status
from paste_spotlight.providers.base import Provider, missing_key
from paste_spotlight.textutil import clean_snippet

ENDPOINT = "https://api.github.com/search/code"


class GitHubCode(Provider):
    id = "github_code"
    name = "GitHub code search"
    summary = (
        "Searches public file contents through the official code-search API. "
        "Use a token with public-only access: a classic token with only the public_repo scope, "
        "or a fine-grained token limited to public repositories. Do not use the full repo scope. "
        "Queries include is:public. Gist contents are not in this index."
    )

    def configured(self) -> bool:
        return bool(env_value("GITHUB_TOKEN"))

    @property
    def readiness(self) -> str:
        return "ready" if self.configured() else "needs_key"

    def search(self, query: SearchQuery, client: httpx.Client):
        missing = missing_key(
            self,
            "GITHUB_TOKEN",
            "Create a GitHub token with public-only access (classic public_repo, or a fine-grained "
            "public-repository token). Do not use the full repo scope. Code search allows about 10 requests a minute.",
        )
        if missing:
            return missing
        phrase = query.text.replace('"', " ").strip()
        try:
            response = guarded_request(
                client,
                "GET",
                ENDPOINT,
                params={"q": f'"{phrase}" is:public', "per_page": "10"},
                headers={
                    "Authorization": f"Bearer {env_value('GITHUB_TOKEN')}",
                    "Accept": "application/vnd.github.text-match+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
        except UnsafeURL:
            return self.finish(Status.ERROR, "The GitHub code request was blocked by the outbound allow-list.")
        except httpx.HTTPError:
            return self.finish(Status.ERROR, "GitHub code search could not be reached.")

        if response.status_code == 401:
            return self.finish(Status.ERROR, "GitHub rejected the token. Code search requires authentication.")
        if response.status_code == 403:
            return self.finish(Status.BLOCKED, "GitHub code search refused the request (rate limit or token scope).")
        if response.status_code == 422:
            return self.finish(Status.ERROR, "GitHub could not run that code query.")
        if response.status_code != 200:
            return self.finish(Status.ERROR, f"GitHub code search returned HTTP {response.status_code}.")
        try:
            payload = response.json()
        except ValueError:
            return self.finish(Status.ERROR, "GitHub code search returned a response that was not JSON.")

        hits = []
        for row in (payload.get("items") or [])[:10]:
            if not isinstance(row, dict):
                continue
            repository = row.get("repository") if isinstance(row.get("repository"), dict) else {}
            if row.get("private") is True or repository.get("private") is True:
                continue
            url = row.get("html_url") or ""
            if not url.startswith("https://github.com/"):
                continue
            repo = repository.get("full_name") or "repository"
            fragments = [match.get("fragment") or "" for match in row.get("text_matches") or []]
            snippet = clean_snippet(" ".join(fragments) or row.get("path") or "")
            hits.append(
                Hit(
                    title=clean_snippet(f"{repo}/{row.get('path') or row.get('name') or ''}", 180),
                    url=url,
                    snippet=snippet,
                    timestamp="",
                    source="github.com",
                )
            )
        incomplete = payload.get("incomplete_results") is True
        partial = " Partial result. GitHub marked the result incomplete." if incomplete else ""
        if not hits:
            return self.finish(
                Status.NO_RESULTS,
                "GitHub code search returned no public files. Gist contents are not in this index." + partial,
            )
        return self.finish(Status.OK, f"GitHub code search returned {len(hits)} file(s).{partial}", hits)
