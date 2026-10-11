"""Provider registry."""

from paste_spotlight.providers.base import Provider
from paste_spotlight.providers.brave_dorks import BraveDorks
from paste_spotlight.providers.github_code import GitHubCode
from paste_spotlight.providers.github_gist import GitHubGist
from paste_spotlight.providers.github_public import GitHubPublic
from paste_spotlight.providers.google_cse import GoogleCse
from paste_spotlight.providers.hibp import Hibp
from paste_spotlight.providers.intelx import IntelX
from paste_spotlight.providers.pastebin_scrape import PastebinScrape
from paste_spotlight.providers.psbdmp import Psbdmp

PROVIDERS: list[Provider] = [
    GitHubPublic(),
    GitHubCode(),
    GitHubGist(),
    BraveDorks(),
    GoogleCse(),
    Hibp(),
    IntelX(),
    PastebinScrape(),
    Psbdmp(),
]

BY_ID = {provider.id: provider for provider in PROVIDERS}


def get_provider(provider_id: str) -> Provider | None:
    return BY_ID.get(provider_id)
