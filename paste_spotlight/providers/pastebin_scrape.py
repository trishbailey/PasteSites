"""Pastebin scraping API. Official recent-paste feed, IP whitelist required."""

import re
import time
from urllib.parse import quote

import httpx

from paste_spotlight.config import env_flag, env_value
from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.models import Hit, SearchQuery, Status
from paste_spotlight.providers.base import Provider
from paste_spotlight.textutil import clean_snippet, window

LIST_URL = "https://scrape.pastebin.com/api_scraping.php"
ITEM_URL = "https://scrape.pastebin.com/api_scrape_item.php"
_KEY_RE = re.compile(r"^[A-Za-z0-9]{4,32}$")


class PastebinScrape(Provider):
    id = "pastebin_scrape"
    name = "Pastebin scraping API"
    summary = (
        "Official recent-paste feed. Requires a Pastebin PRO account and one whitelisted IP. "
        "It is not a historical search. PRO accounts were sold out when this was checked."
    )

    def configured(self) -> bool:
        return env_flag("PASTEBIN_SCRAPING_ENABLED")

    @property
    def readiness(self) -> str:
        return "ready" if self.configured() else "needs_key"

    def search(self, query: SearchQuery, client: httpx.Client):
        if not self.configured():
            return self.finish(
                Status.NEEDS_KEY,
                "Set PASTEBIN_SCRAPING_ENABLED=true only on a machine whose IP is whitelisted at "
                "https://pastebin.com/doc_scraping_api. Pastebin PRO is required and was sold out "
                "with no public price. The feed is the most recent public pastes, not an archive. "
                "Render free web services do not have a stable outbound IP, so a whitelist will not hold there. "
                "Historical Pastebin hits come from Brave, Google, or Intelligence X.",
            )
        limit = _limit()
        try:
            listed = guarded_request(client, "GET", LIST_URL, params={"limit": str(limit)})
        except UnsafeURL:
            return self.finish(Status.ERROR, "The Pastebin request was blocked by the outbound allow-list.")
        except httpx.HTTPError:
            return self.finish(Status.ERROR, "Pastebin's scraping API could not be reached.")

        if listed.status_code in {401, 403}:
            return self.finish(
                Status.BLOCKED,
                "Pastebin refused the scraping API for this IP. Whitelist one IP on a PRO account. "
                + _access_hint(listed.text),
            )
        if listed.status_code == 429:
            return self.finish(Status.BLOCKED, "Pastebin rate-limited the scraping API.")
        if listed.status_code != 200:
            return self.finish(Status.ERROR, f"Pastebin scraping API returned HTTP {listed.status_code}.")
        try:
            rows = listed.json()
        except ValueError:
            return self.finish(Status.ERROR, "Pastebin scraping API returned a response that was not JSON.")
        if not isinstance(rows, list):
            return self.finish(Status.ERROR, "Pastebin scraping API returned an unexpected payload.")

        hits: list[Hit] = []
        body_checks = 0
        max_bodies = 5
        delay = _delay()
        for row in rows:
            if not isinstance(row, dict):
                continue
            key = str(row.get("key") or "")
            if not _KEY_RE.fullmatch(key):
                continue
            title = str(row.get("title") or "")
            page = f"https://pastebin.com/{key}"
            if query.text.lower() in title.lower():
                hits.append(
                    Hit(
                        title=clean_snippet(title or f"Pastebin {key}", 180),
                        url=page,
                        snippet=clean_snippet(f"Title match in the recent public feed. Syntax: {row.get('syntax') or 'text'}."),
                        timestamp=_timestamp(row.get("date")),
                        source="pastebin.com",
                    )
                )
                continue
            if body_checks >= max_bodies or len(hits) >= 8:
                continue
            if body_checks and delay:
                time.sleep(delay)
            body_checks += 1
            matched = _body_hit(client, key, query.text, title, page, row)
            if matched:
                hits.append(matched)

        message = (
            f"Checked {min(len(rows), limit)} recent public pastes and read the body of {body_checks}. "
            "This feed is not a historical archive."
        )
        if not hits:
            return self.finish(Status.NO_RESULTS, message + " The query was not in that sample.")
        return self.finish(Status.OK, message, hits)


def _body_hit(client, key: str, query: str, title: str, page: str, row: dict):
    try:
        response = guarded_request(
            client,
            "GET",
            ITEM_URL,
            params={"i": quote(key, safe="")},
            headers={"Accept": "text/plain"},
        )
    except (UnsafeURL, httpx.HTTPError):
        return None
    if response.status_code != 200:
        return None
    text = response.content[:200_000].decode("utf-8", "replace")
    if query.lower() not in text.lower():
        return None
    return Hit(
        title=clean_snippet(title or f"Pastebin {key}", 180),
        url=page,
        snippet=window(text, query),
        timestamp=_timestamp(row.get("date")),
        source="pastebin.com",
    )


def _limit() -> int:
    raw = env_value("PASTEBIN_SCRAPING_LIMIT") or "25"
    try:
        return max(1, min(int(raw), 50))
    except ValueError:
        return 25


def _delay() -> float:
    raw = env_value("PASTEBIN_SCRAPE_DELAY") or "1"
    try:
        return max(0.0, min(float(raw), 5.0))
    except ValueError:
        return 1.0


def _timestamp(value) -> str:
    if value is None:
        return ""
    return str(value)


def _access_hint(body: str) -> str:
    text = " ".join((body or "").split())
    if "DOES NOT HAVE ACCESS" in text.upper():
        return "The API said this IP does not have access."
    return ""
