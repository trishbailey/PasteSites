#!/usr/bin/env python3
"""Live provider smoke test.

Runs each provider once with a benign public query. API keys are optional.
The script prints status labels only. It does not print secret values.

Exit 0 when every provider returns a status. Exit 1 when a provider raises.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from paste_spotlight.http_guard import make_client
from paste_spotlight.models import SearchQuery
from paste_spotlight.providers import PROVIDERS
from paste_spotlight.validate import validate_query


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test Paste Site Spotlight providers.")
    parser.add_argument("--query", default="HelloWorldMessage", help="Benign public keyword or selector.")
    parser.add_argument("--kind", default="keyword", choices=["email", "domain", "username", "keyword"])
    args = parser.parse_args()
    query = validate_query(args.query, args.kind)
    failed = False
    print(f"query={query.text} kind={query.kind}")
    print(f"{'provider':<22} {'status':<12} {'hits':>4}  message")
    with make_client() as client:
        for provider in PROVIDERS:
            try:
                result = provider.search(query, client)
            except Exception as exc:
                failed = True
                print(f"{provider.id:<22} {'raised':<12} {0:>4}  {type(exc).__name__}")
                continue
            message = " ".join(result.message.split())
            print(f"{result.provider_id:<22} {result.status.value:<12} {len(result.hits):>4}  {message[:180]}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
