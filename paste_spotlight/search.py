"""Run the selected providers and keep the last result set for CSV export."""

import logging
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from paste_spotlight.models import ProviderResult, SearchQuery, Status
from paste_spotlight.providers import PROVIDERS, get_provider

log = logging.getLogger("paste_spotlight")


class ResultStore:
    def __init__(self, max_sessions: int = 100) -> None:
        self._lock = threading.Lock()
        self._items: OrderedDict[str, dict] = OrderedDict()
        self._max = max_sessions

    def put(self, session_id: str, payload: dict) -> None:
        with self._lock:
            self._items[session_id] = payload
            self._items.move_to_end(session_id)
            while len(self._items) > self._max:
                self._items.popitem(last=False)

    def get(self, session_id: str) -> dict | None:
        with self._lock:
            return self._items.get(session_id)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


STORE = ResultStore()


def run_search(query: SearchQuery, provider_ids: list[str], client: httpx.Client) -> list[ProviderResult]:
    selected = [provider for provider_id in provider_ids if (provider := get_provider(provider_id))]
    if not selected:
        return []
    results: dict[str, ProviderResult] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(_safe_search, provider, query, client): provider.id for provider in selected}
        for future in as_completed(futures):
            provider_id = futures[future]
            results[provider_id] = future.result()
    return [results[provider.id] for provider in PROVIDERS if provider.id in results]


def _safe_search(provider, query: SearchQuery, client: httpx.Client) -> ProviderResult:
    try:
        return provider.search(query, client)
    except Exception:
        log.exception("provider %s failed", provider.id)
        return ProviderResult(
            provider_id=provider.id,
            name=provider.name,
            status=Status.ERROR,
            message="This provider failed before it could finish. Nothing was returned.",
        )
