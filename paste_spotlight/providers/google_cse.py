"""Google Programmable Search (Custom Search JSON API) dorks."""

import httpx

from paste_spotlight.config import env_value
from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.models import Hit, SearchQuery, Status
from paste_spotlight.providers.base import Provider
from paste_spotlight.sites import DORK_SITES, dork_query
from paste_spotlight.textutil import clean_snippet

ENDPOINT = "https://www.googleapis.com/customsearch/v1"


class GoogleCse(Provider):
    id = "google_cse"
    name = "Google Programmable Search"
    summary = (
        f"The same paste-host dork as Brave, through Google's Custom Search JSON API "
        f"({len(DORK_SITES)} hosts, one request). The engine must be set to search the entire web."
    )

    def configured(self) -> bool:
        return bool(env_value("GOOGLE_CSE_API_KEY") and env_value("GOOGLE_CSE_ID"))

    @property
    def readiness(self) -> str:
        return "ready" if self.configured() else "needs_key"

    def search(self, query: SearchQuery, client: httpx.Client):
        if not self.configured():
            return self.finish(
                Status.NEEDS_KEY,
                "Set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID. The free tier is 100 queries a day, "
                "then about $5 per 1,000. This provider sends one query per search, not one per site.",
            )
        try:
            response = guarded_request(
                client,
                "GET",
                ENDPOINT,
                params={
                    "key": env_value("GOOGLE_CSE_API_KEY"),
                    "cx": env_value("GOOGLE_CSE_ID"),
                    "q": dork_query(query.text),
                    "num": "10",
                },
            )
        except UnsafeURL:
            return self.finish(Status.ERROR, "The Google request was blocked by the outbound allow-list.")
        except httpx.HTTPError:
            return self.finish(Status.ERROR, "Google Custom Search could not be reached.")

        if response.status_code == 429:
            return self.finish(Status.BLOCKED, "Google Custom Search rate-limited this key.")
        if response.status_code in {400, 403}:
            return self.finish(
                Status.ERROR,
                "Google rejected the API key or the search engine ID. "
                "Confirm the key is enabled for Custom Search and the engine searches the whole web.",
            )
        if response.status_code != 200:
            return self.finish(Status.ERROR, f"Google Custom Search returned HTTP {response.status_code}.")
        try:
            payload = response.json()
        except ValueError:
            return self.finish(Status.ERROR, "Google returned a response that was not JSON.")

        hits = []
        for row in (payload.get("items") or [])[:10]:
            url = row.get("link") or ""
            if not url.startswith("https://"):
                continue
            hits.append(
                Hit(
                    title=clean_snippet(row.get("title") or url, 180),
                    url=url,
                    snippet=clean_snippet(row.get("snippet") or ""),
                    timestamp="",
                    source=row.get("displayLink") or "google",
                )
            )
        if not hits:
            return self.finish(
                Status.NO_RESULTS,
                "Google Programmable Search returned no items. An empty index result is reported here "
                "instead of a blank page.",
            )
        return self.finish(Status.OK, f"Google returned {len(hits)} indexed page(s).", hits)
