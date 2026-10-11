"""Intelligence X search API. Metadata and links only; file bodies are not downloaded."""

import re
import time
from urllib.parse import urlsplit

import httpx

from paste_spotlight.config import env_value
from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.models import Hit, SearchQuery, Status
from paste_spotlight.providers.base import Provider, missing_key
from paste_spotlight.textutil import clean_snippet

_ALLOWED_INSTANCES = {"free.intelx.io", "2.intelx.io", "public.intelx.io"}
_ALLOWED_BUCKETS = {"pastes", "leaks.public", "leaks", "web.public", "dumpster", "whois"}
_ID_RE = re.compile(r"^[A-Za-z0-9-]{16,80}$")


class IntelX(Provider):
    id = "intelx"
    name = "Intelligence X"
    summary = (
        "Optional Search API for the pastes bucket and public leak metadata. "
        "A free intelx.io account uses free.intelx.io. This provider stores titles and links, not file bodies."
    )

    def configured(self) -> bool:
        return bool(env_value("INTELX_API_KEY"))

    @property
    def readiness(self) -> str:
        return "ready" if self.configured() else "needs_key"

    def search(self, query: SearchQuery, client: httpx.Client):
        missing = missing_key(
            self,
            "INTELX_API_KEY",
            "A free signed-up account includes about 50 selector searches a day on free.intelx.io. "
            "Offering IntelX inside a product sold to others requires their API license "
            "(listed at €7,000/year on the product page). Researcher access is listed at €2,500/year.",
        )
        if missing:
            return missing
        try:
            base = _base_url()
            buckets = _buckets()
        except UnsafeURL as exc:
            return self.finish(Status.ERROR, str(exc))

        headers = {"x-key": env_value("INTELX_API_KEY"), "Content-Type": "application/json"}
        body = {
            "term": query.text,
            "buckets": buckets,
            "lookuplevel": 0,
            "maxresults": 10,
            "timeout": 5,
            "datefrom": "",
            "dateto": "",
            "sort": 2,
            "media": 0,
            "terminate": [],
        }
        try:
            started = guarded_request(client, "POST", f"{base}/intelligent/search", headers=headers, json=body)
        except UnsafeURL:
            return self.finish(Status.ERROR, "The Intelligence X request was blocked by the outbound allow-list.")
        except httpx.HTTPError:
            return self.finish(Status.ERROR, "Intelligence X could not be reached.")

        if started.status_code == 401:
            return self.finish(Status.ERROR, "Intelligence X rejected the API key for this API host.")
        if started.status_code == 402:
            return self.finish(Status.BLOCKED, "Intelligence X reported no search credits left on this key.")
        if started.status_code != 200:
            return self.finish(Status.ERROR, f"Intelligence X returned HTTP {started.status_code}.")
        try:
            search_id = str(started.json().get("id") or "")
        except ValueError:
            return self.finish(Status.ERROR, "Intelligence X returned a response that was not JSON.")
        if not _ID_RE.fullmatch(search_id):
            return self.finish(Status.ERROR, "Intelligence X did not return a search id.")

        records: list[dict] = []
        for attempt in range(2):
            try:
                result = guarded_request(
                    client,
                    "GET",
                    f"{base}/intelligent/search/result",
                    params={"id": search_id, "limit": "10", "offset": "0"},
                    headers={"x-key": env_value("INTELX_API_KEY")},
                )
            except (UnsafeURL, httpx.HTTPError):
                return self.finish(Status.ERROR, "Intelligence X results could not be read.")
            if result.status_code != 200:
                return self.finish(Status.ERROR, f"Intelligence X results returned HTTP {result.status_code}.")
            try:
                payload = result.json()
            except ValueError:
                return self.finish(Status.ERROR, "Intelligence X results were not JSON.")
            records = [row for row in payload.get("records") or [] if isinstance(row, dict)]
            if records or attempt == 1:
                break
            time.sleep(1)

        _terminate(client, base, search_id)
        hits = []
        for row in records[:10]:
            system_id = str(row.get("systemid") or "")
            url = f"https://intelx.io/?did={system_id}" if _ID_RE.fullmatch(system_id) else "https://intelx.io/"
            hits.append(
                Hit(
                    title=clean_snippet(row.get("name") or row.get("bucket") or "Intelligence X record", 180),
                    url=url,
                    snippet=clean_snippet(f"Bucket: {row.get('bucket') or 'unknown'}."),
                    timestamp=str(row.get("date") or ""),
                    source="intelx.io",
                )
            )
        bucket_note = ", ".join(buckets)
        if not hits:
            return self.finish(Status.NO_RESULTS, f"Intelligence X returned no records in {bucket_note}.")
        return self.finish(Status.OK, f"Intelligence X returned {len(hits)} record(s) from {bucket_note}.", hits)


def _base_url() -> str:
    raw = env_value("INTELX_API_URL") or "https://free.intelx.io"
    parsed = urlsplit(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in _ALLOWED_INSTANCES or parsed.path not in {"", "/"}:
        raise UnsafeURL(
            "INTELX_API_URL must be https://free.intelx.io, https://2.intelx.io, or https://public.intelx.io."
        )
    if parsed.username or parsed.query:
        raise UnsafeURL("INTELX_API_URL must be a bare Intelligence X API host.")
    return f"https://{host}"


def _buckets() -> list[str]:
    raw = env_value("INTELX_BUCKETS") or "pastes,leaks.public"
    chosen = []
    for part in raw.split(","):
        name = part.strip()
        if name in _ALLOWED_BUCKETS and name not in chosen:
            chosen.append(name)
    if not chosen:
        raise UnsafeURL("INTELX_BUCKETS must list at least one of: " + ", ".join(sorted(_ALLOWED_BUCKETS)) + ".")
    return chosen


def _terminate(client, base: str, search_id: str) -> None:
    try:
        guarded_request(
            client,
            "GET",
            f"{base}/intelligent/search/terminate",
            params={"id": search_id},
            headers={"x-key": env_value("INTELX_API_KEY")},
        )
    except (UnsafeURL, httpx.HTTPError):
        return
