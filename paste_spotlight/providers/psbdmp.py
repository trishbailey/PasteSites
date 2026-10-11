"""psbdmp paste index. The historical host is gone; the old domain is now Weakpass."""

import httpx

from paste_spotlight.http_guard import UnsafeURL, guarded_request
from paste_spotlight.models import SearchQuery, Status
from paste_spotlight.providers.base import Provider

WS_HOME = "https://psbdmp.ws/"
CC_SPEC = "https://psbdmp.cc/openapi.json"


class Psbdmp(Provider):
    id = "psbdmp"
    name = "psbdmp paste index"
    summary = (
        "Reports whether the old Pastebin dump index is actually searchable. "
        "User queries are not sent to the hash-lookup site now living at psbdmp.cc."
    )
    readiness = "status_only"

    def search(self, query: SearchQuery, client: httpx.Client):
        del query
        ws_note = _probe_ws(client)
        cc_note = _probe_cc(client)
        return self.finish(
            Status.BLOCKED,
            f"{ws_note} {cc_note} No paste query was sent.",
        )


def _probe_ws(client: httpx.Client) -> str:
    try:
        response = guarded_request(client, "GET", WS_HOME)
    except UnsafeURL:
        return "psbdmp.ws was not requested because it failed the outbound allow-list."
    except httpx.HTTPError as exc:
        name = type(exc).__name__
        if "Connect" in name or "Timeout" in name:
            return "psbdmp.ws has no working address (the historical paste API host does not resolve)."
        return f"psbdmp.ws could not be reached ({name})."
    return f"psbdmp.ws responded with HTTP {response.status_code}, but the documented v3 paste API was not used."


def _probe_cc(client: httpx.Client) -> str:
    try:
        response = guarded_request(client, "GET", CC_SPEC, headers={"Accept": "application/json"})
    except (UnsafeURL, httpx.HTTPError):
        return "psbdmp.cc could not be checked."
    sample = response.text[:800]
    if response.status_code == 200 and "Weakpass" in sample:
        return (
            "psbdmp.cc is online as Weakpass, a hash and wordlist API, not a paste search. "
            "That API was not called."
        )
    return f"psbdmp.cc returned HTTP {response.status_code} and not the old paste-search API."
