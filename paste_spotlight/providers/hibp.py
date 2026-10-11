"""Have I Been Pwned breach and paste lookups. Email queries only."""

import httpx

from paste_spotlight.config import env_value
from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.models import Hit, SearchQuery, Status
from paste_spotlight.providers.base import Provider, missing_key
from paste_spotlight.textutil import clean_snippet, strip_tags
from urllib.parse import quote

API = "https://haveibeenpwned.com/api/v3"

_PASTE_URLS = {
    "Pastebin": "https://pastebin.com/{id}",
    "Pastie": "https://pastie.org/pastes/{id}",
    "Slexy": "https://slexy.org/view/{id}",
    "Ghostbin": "https://ghostbin.com/paste/{id}",
    "QuickLeak": "https://quickleak.ir/{id}",
    "JustPaste": "https://justpaste.it/{id}",
}


class Hibp(Provider):
    id = "hibp"
    name = "Have I Been Pwned"
    summary = (
        "Breach names and paste metadata for an email address. "
        "Requires a paid HIBP API key. Responses are titles, dates, and descriptions, not dump files."
    )

    def configured(self) -> bool:
        return bool(env_value("HIBP_API_KEY"))

    @property
    def readiness(self) -> str:
        return "ready" if self.configured() else "needs_key"

    def search(self, query: SearchQuery, client: httpx.Client):
        missing = missing_key(
            self,
            "HIBP_API_KEY",
            "Core plans start at $4.39 per month billed annually ($52.68/year) for 10 requests a minute. "
            "The same key covers the breach and paste endpoints.",
        )
        if missing:
            return missing
        if query.kind != "email":
            return self.finish(
                Status.SKIPPED,
                "Skipped. Have I Been Pwned searches email addresses only. No request was sent.",
            )
        headers = {
            "hibp-api-key": env_value("HIBP_API_KEY"),
            "user-agent": "Paste-Site-Spotlight",
        }
        account = quote(query.text, safe="")
        paste_status, pastes, paste_note = _get(client, f"{API}/pasteaccount/{account}", headers)
        breach_status, breaches, breach_note = _get(
            client, f"{API}/breachedaccount/{account}", headers, params={"truncateResponse": "false"}
        )
        for status, note in ((paste_status, paste_note), (breach_status, breach_note)):
            if status == "auth":
                return self.finish(Status.ERROR, note)
            if status == "blocked":
                return self.finish(Status.BLOCKED, note)
            if status == "error":
                return self.finish(Status.ERROR, note)

        hits = _paste_hits(pastes) + _breach_hits(breaches)
        if not hits:
            return self.finish(Status.NO_RESULTS, "HIBP has no breach or paste record for this email.")
        return self.finish(Status.OK, f"HIBP returned {len(hits)} breach or paste record(s).", hits)


def _get(client, url, headers, params=None):
    try:
        response = guarded_request(client, "GET", url, headers=headers, params=params)
    except UnsafeURL:
        return "error", None, "The HIBP request was blocked by the outbound allow-list."
    except httpx.HTTPError:
        return "error", None, "Have I Been Pwned could not be reached."
    if response.status_code == 404:
        return "empty", [], ""
    if response.status_code == 401:
        return "auth", None, "HIBP rejected the API key."
    if response.status_code == 403:
        return "blocked", None, "HIBP refused this lookup for the current subscription."
    if response.status_code == 429:
        return "blocked", None, "HIBP rate-limited this key."
    if response.status_code != 200:
        return "error", None, f"HIBP returned HTTP {response.status_code}."
    try:
        return "ok", response.json(), ""
    except ValueError:
        return "error", None, "HIBP returned a response that was not JSON."


def _paste_hits(rows) -> list[Hit]:
    hits = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        source = str(row.get("Source") or "paste")
        paste_id = str(row.get("Id") or "")
        hits.append(
            Hit(
                title=clean_snippet(row.get("Title") or f"{source} paste", 180),
                url=_paste_url(source, paste_id),
                snippet=clean_snippet(
                    f"{source} paste {paste_id}. Emails in paste: {row.get('EmailCount', 'unknown')}."
                ),
                timestamp=str(row.get("Date") or ""),
                source="haveibeenpwned.com",
            )
        )
    return hits


def _paste_url(source: str, paste_id: str) -> str:
    parts = paste_id.split("/")
    if (
        source == "AdHocUrl"
        and paste_id.startswith("https://")
        and len(parts) > 2
        and parts[2]
        and "@" not in parts[2]
    ):
        return paste_id
    template = _PASTE_URLS.get(source)
    if template and paste_id and all(char.isalnum() or char in "-_" for char in paste_id):
        return template.format(id=paste_id)
    return "https://haveibeenpwned.com/"


def _breach_hits(rows) -> list[Hit]:
    hits = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("Name") or "breach")
        classes = ", ".join(str(item) for item in (row.get("DataClasses") or [])[:8])
        description = clean_snippet(strip_tags(str(row.get("Description") or "")))
        snippet = description
        if classes:
            snippet = clean_snippet(f"{description} Data classes: {classes}")
        safe_name = "".join(char for char in name if char.isalnum())
        hits.append(
            Hit(
                title=clean_snippet(row.get("Title") or name, 180),
                url=f"https://haveibeenpwned.com/PwnedWebsites#{safe_name}",
                snippet=snippet,
                timestamp=str(row.get("BreachDate") or ""),
                source="haveibeenpwned.com",
            )
        )
    return hits
