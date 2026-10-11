"""Shared result types."""

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    OK = "ok"
    NO_RESULTS = "no_results"
    BLOCKED = "blocked"
    NEEDS_KEY = "needs_key"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class Hit:
    title: str
    url: str
    snippet: str
    timestamp: str = ""
    source: str = ""


@dataclass
class ProviderResult:
    provider_id: str
    name: str
    status: Status
    message: str
    hits: list[Hit] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "hits": [
                {
                    "title": hit.title,
                    "url": hit.url,
                    "snippet": hit.snippet,
                    "timestamp": hit.timestamp,
                    "source": hit.source,
                }
                for hit in self.hits
            ],
        }


@dataclass(frozen=True)
class SearchQuery:
    text: str
    kind: str
