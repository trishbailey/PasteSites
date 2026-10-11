"""Run the selected providers and keep the last result set for CSV export.

The result store is in-process memory. A restart clears it. The free plan has no database.
"""

import contextvars
import logging
import threading
import time
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import httpx

from paste_spotlight.deadline import SEARCH_DEADLINE_SECONDS, clear_deadline, start_deadline
from paste_spotlight.models import ProviderResult, SearchQuery, Status
from paste_spotlight.providers import PROVIDERS, get_provider

log = logging.getLogger("paste_spotlight")

# Bound a crafted form before dedupe. The known provider list is the real cap.
_RAW_PROVIDER_LIMIT = 20


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


def normalize_provider_ids(provider_ids: list[str]) -> list[str]:
    known = {provider.id for provider in PROVIDERS}
    chosen: list[str] = []
    for item in list(provider_ids)[:_RAW_PROVIDER_LIMIT]:
        if not isinstance(item, str) or item not in known or item in chosen:
            continue
        chosen.append(item)
        if len(chosen) >= len(PROVIDERS):
            break
    return chosen


def run_search(query: SearchQuery, provider_ids: list[str], client: httpx.Client) -> list[ProviderResult]:
    selected = [provider for provider_id in normalize_provider_ids(provider_ids) if (provider := get_provider(provider_id))]
    if not selected:
        return []
    results: dict[str, ProviderResult] = {}
    token = start_deadline(SEARCH_DEADLINE_SECONDS)
    pool = ThreadPoolExecutor(max_workers=min(4, len(selected)))
    try:
        futures = {}
        for provider in selected:
            ctx = contextvars.copy_context()
            futures[pool.submit(ctx.run, _safe_search, provider, query, client)] = provider
        pending = set(futures)
        deadline_at = time.monotonic() + SEARCH_DEADLINE_SECONDS
        while pending:
            timeout = deadline_at - time.monotonic()
            if timeout <= 0:
                break
            done, pending = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                provider = futures[future]
                results[provider.id] = _result_or_error(provider, future)
        for future, provider in futures.items():
            if provider.id in results:
                continue
            future.cancel()
            results[provider.id] = ProviderResult(
                provider_id=provider.id,
                name=provider.name,
                status=Status.ERROR,
                message=(
                    "This provider timed out before it finished. "
                    "The search deadline passed, so this is an error, not a no-results finding."
                ),
            )
    finally:
        clear_deadline(token)
        pool.shutdown(wait=False, cancel_futures=True)
    return [results[provider.id] for provider in PROVIDERS if provider.id in results]


def _result_or_error(provider, future) -> ProviderResult:
    try:
        result = future.result()
    except Exception:
        log.error("provider %s failed", provider.id)
        return ProviderResult(
            provider_id=provider.id,
            name=provider.name,
            status=Status.ERROR,
            message="This provider failed before it could finish. Nothing was returned.",
        )
    if isinstance(result, ProviderResult):
        return result
    return ProviderResult(
        provider_id=provider.id,
        name=provider.name,
        status=Status.ERROR,
        message="This provider failed before it could finish. Nothing was returned.",
    )


def _safe_search(provider, query: SearchQuery, client: httpx.Client) -> ProviderResult:
    try:
        return provider.search(query, client)
    except Exception:
        log.error("provider %s failed", provider.id)
        return ProviderResult(
            provider_id=provider.id,
            name=provider.name,
            status=Status.ERROR,
            message="This provider failed before it could finish. Nothing was returned.",
        )
