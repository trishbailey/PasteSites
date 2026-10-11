"""Paste hosts covered by search-engine dorks.

These are public paste and code-bin hostnames. Search engines are asked
about them. This app does not scrape the sites themselves.
"""

DORK_SITES = (
    "pastebin.com",
    "paste.ee",
    "justpaste.it",
    "rentry.co",
    "dpaste.com",
    "dpaste.org",
    "controlc.com",
    "ideone.com",
    "bpa.st",
    "nekobin.com",
    "gist.github.com",
    "hastebin.com",
    "ghostbin.com",
    "katb.in",
    "cl1p.net",
    "paste.org.ru",
    "defuse.ca",
    "termbin.com",
    "write.as",
    "privatebin.net",
)


def dork_query(text: str) -> str:
    phrase = " ".join(text.replace('"', " ").replace("(", " ").replace(")", " ").split())
    sites = " OR ".join(f"site:{site}" for site in DORK_SITES)
    return f'"{phrase}" ({sites})'
