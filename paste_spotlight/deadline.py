"""Search-wide deadline shared with providers that poll.

Providers read this module instead of importing the search runner, which would cycle.
"""

import contextvars
import time

SEARCH_DEADLINE_SECONDS = 25.0

_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar("search_deadline", default=None)


def start_deadline(seconds: float = SEARCH_DEADLINE_SECONDS):
    return _deadline.set(time.monotonic() + seconds)


def clear_deadline(token) -> None:
    _deadline.reset(token)


def seconds_left() -> float | None:
    deadline = _deadline.get()
    if deadline is None:
        return None
    return deadline - time.monotonic()
