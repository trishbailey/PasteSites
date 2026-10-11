"""Brave Search API dorks across public paste hosts."""

import httpx

from paste_spotlight.config import env_value
from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.models import Hit, SearchQuery, Status
from paste_spotlight.providers.base import Provider, missing_key
from paste_spotlight.sites import DORK_SITES, dork_query
from paste_spotlight.textutil import clean_snippet

ENDPOINT = "https://api.search.brave.com/res/v1/web/search"


class BraveDorks(Provider):
    id = "brave_dorks"
    name = "Brave Search dorks"
    summary = (
        f"One web-search query across {len(DORK_SITES)} paste hosts "
        "(pastebin, rentry, ghostbin, dpaste, hastebin, gist, and others)."
    )

    def configured(self) -> bool:
        return bool(env_value("BRAVE_SEARCH_API_KEY"))

    @property
    def readiness(self) -> str:
        return "ready" if self.configured() else "needs_key"

    def search(self, query: SearchQuery, client: httpx.Client):
        missing = missing_key(
            self,
            "BRAVE_SEARCH_API_KEY",
            "Brave's Search plan includes a monthly credit (about 1,000 searches) and then bills per thousand. "
            "One Spotlight search uses one Brave request.",
        )
        if missing:
            return missing
        try:
            response = guarded_request(
                client,
                "GET",
                ENDPOINT,
                params={"q": dork_query(query.text), "count": "10", "text_decorations": "0"},
                headers={
                    "X-Subscription-Token": env_value("BRAVE_SEARCH_API_KEY"),
                    "Accept": "application/json",
                },
            )
        except UnsafeURL:
            return self.finish(Status.ERROR, "The Brave request was blocked by the outbound allow-list.")
        except httpx.HTTPError:
            return self.finish(Status.ERROR, "Brave Search could not be reached.")

        if response.status_code in {401, 403}:
            return self.finish(Status.ERROR, "Brave rejected the API key.")
        if response.status_code == 429:
            return self.finish(Status.BLOCKED, "Brave rate-limited this key. Wait before searching again.")
        if response.status_code in {400, 422}:
            return self.finish(
                Status.ERROR,
                "Brave rejected the query. It may be too long for one request.",
            )
        if response.status_code != 200:
            return self.finish(Status.ERROR, f"Brave returned HTTP {response.status_code}.")

        try:
            payload = response.json()
        except ValueError:
            return self.finish(Status.ERROR, "Brave returned a response that was not JSON.")

        rows = (payload.get("web") or {}).get("results") or []
        hits = []
        for row in rows[:10]:
            url = row.get("url") or ""
            if not isinstance(url, str) or not url.startswith("https://"):
                continue
            meta = row.get("meta_url") if isinstance(row.get("meta_url"), dict) else {}
            hits.append(
                Hit(
                    title=clean_snippet(row.get("title") or url, 180),
                    url=url,
                    snippet=clean_snippet(row.get("description") or ""),
                    timestamp=str(row.get("page_age") or row.get("age") or ""),
                    source=str(meta.get("hostname") or "brave"),
                )
            )
        if not hits:
            return self.finish(
                Status.NO_RESULTS,
                "Brave returned no indexed pages for these paste hosts. Web results by Brave Search API.",
            )
        return self.finish(
            Status.OK,
            f"Brave returned {len(hits)} indexed page(s). Web results by Brave Search API.",
            hits,
        )
