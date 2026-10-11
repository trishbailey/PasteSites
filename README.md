# Paste Site Spotlight

Search public paste hosts and optional breach indexes for an email, domain, username, or keyword. Each provider returns its own status: **ok**, **no results**, **blocked**, **needs key**, or **error**. A provider that cannot run says so. It does not disappear into an empty page.

This replaces SelectorScope, which only called Google Programmable Search and reported a blank result set whenever that call was missing, refused, or empty.

Informational use. The app queries public APIs and search indexes you configure. It does not bypass access controls, and it does not fetch URLs typed into the search box.

[Beacon Intelligence](https://beaconintelligencegroup.com/)

## Why the old search returned nothing

Checked 11 October 2026 from this environment. The old `app.py` had a single network function, `search_google_cse()`, aimed at `https://www.googleapis.com/customsearch/v1`. It ran only when both `GOOGLE_CSE_API_KEY` and `GOOGLE_CSE_ID` were set (Streamlit secrets, or typed into the sidebar). This repo has neither. A live call with no key returned:

`HTTP 403 — Method doesn't allow unregistered callers (callers without established identity).`

With keys, the old app sent **one query per site** (43 sites, so 43 of the 100 free daily queries). Google's JSON body uses `items` for hits. An HTTP 200 with no `items` was treated as success and rendered as "No results found", with no per-site status. Dead hosts, Cloudflare challenges, and indexes that do not contain the site all looked the same.

A known public paste was online the same day: [pastebin.com/cxiuQk6P](https://pastebin.com/cxiuQk6P) ("Hello world" in Python, contains `HelloWorldMessage`). `https://pastebin.com/raw/cxiuQk6P` returned HTTP 200 and that source. Pastebin's own `/search` returned Cloudflare "Just a moment..." (HTTP 403). The old app never requested that paste. It would have found it only if Programmable Search had already indexed it.

GitHub's commit search, which the old app also did not call, returned `total_count: 41` for `HelloWorldMessage` with no token.

### Original sources

The "method" column is the same for every row, because the app never contacted the host. The HTTP column is what a direct request showed.

| Source | Direct request | Why a search still came back empty |
| --- | --- | --- |
| pastebin.com | Home HTTP 200. `/search` HTTP 403 Cloudflare challenge. Scraping API `scrape.pastebin.com/api_scraping.php` HTTP 403, body says the IP does not have access. `robots.txt` disallows `/raw/` and `/api/`. | No keyless keyword search. Scraping API is a recent-paste feed for one whitelisted PRO IP. PRO was sold out, with no public price. |
| justpaste.it | HTTP 200 | No public search API used by the old app. Covered now by dork providers. |
| paste.ee | HTTP 200 | Same. Create-paste API is not a search. |
| gist.github.com | HTTP 200. Website search renders gist snippets, including a hit for `HelloWorldMessage`. | `github.com/robots.txt` for `User-agent: *` disallows `/gist/` and `/search`. Code search API without a token: HTTP 401 `Requires authentication`. This app does not scrape gist HTML. |
| rentry.co | HTTP 200. `robots.txt` disallows raw/export paths. | No public search API. |
| dpaste.org | HTTP 200. `dpaste.com` (not in the old list) also HTTP 200. | No public search API. |
| ideone.com | HTTP 200 | No public search API used here. |
| bpa.st | HTTP 200 | No public search API used here. |
| nekobin.com | HTTP 200 | No public search API used here. |
| cl1p.net | HTTP 200 | No public search API used here. |
| write.as | HTTP 200 | Publishing site, no paste search API. |
| defuse.ca/pastebin.htm | HTTP 200 | Page is up. No search API. |
| termbin.com | HTTP 200 | Netcat paste bin. No search index. |
| hastebin.com | HTTP 403 Cloudflare "Attention Required" | Direct scrape is blocked. A haste fork at `haste.zneix.eu` answered HTTP 200 and sends `noindex`. |
| controlc.com | HTTP 403 Cloudflare "Just a moment..." | Direct scrape is blocked. |
| katb.in | HTTP 403 Cloudflare "Just a moment..." | Direct scrape is blocked. |
| ghostbin.me | TLS certificate verify failed. Insecure retry: connection closed. `ghostbin.com` and `ghostbin.co` returned Cloudflare HTTP 403. | Host in the old list is not a working search target. |
| 0bin.net | HTTP 404 from nginx | Site is gone. Zero-knowledge encryption means the server could not search paste bodies anyway. |
| paste.org.ru | HTTPS failed the TLS handshake. HTTP 200. | The old app only asked Google, over HTTPS `site:` queries. |
| textbin.net | HTTPS connection closed. HTTP 502. | Unusable as a search target. |
| cryptpad.fr | HTTP 200 | Pads are end-to-end encrypted. There is no server-side content search. |
| doxbin.com | HTTP 403 Cloudflare | Not a general paste index. Not queried by this app. |
| t.me, discord.com, keybase.io | HTTP 200 | Chat and profile hosts, not paste indexes. Dropped. |
| reddit.com | HTTP 403 to this client | Dropped. Reddit's API is separate and not a paste index. |
| archived.moe | HTTP 403 Cloudflare | Dropped. |
| desuarchive.org | HTTP 200 | Imageboard archive, not a paste index. Dropped. |
| breachforums.st | DNS: no such host | Dead, and not a paste index. Dropped. |
| xss.is | HTTP 200 login page | Not a paste index. Dropped. |
| irclog.org | DNS: no such host | Dead. Dropped. |
| kiwifarms.net | HTTP 203 browser check, redirected to kiwifarms.st | Not a paste index. Dropped. |
| github.com | HTTP 200. Commit search HTTP 200 (`HelloWorldMessage`, 41 commits). Repository search HTTP 200. Code search HTTP 401 without a token. | The old app never called the GitHub API. |
| gitlab.com, bitbucket.org | HTTP 200 | Code hosts. GitHub's official API is the code provider here. |
| stackoverflow.com | HTTP 403 Cloudflare to this client | Not a paste index. Dropped. |
| documenter.postman.com | HTTP 200 | Not a paste index. Dropped. |
| docs.google.com, drive.google.com, trello.com, scribd.com | HTTP 200 | Document hosts. Dropped from this paste tool. |
| archive.org | HTTP 200. CDX API returned HTTP 503 "Temporarily Offline" during the check. | Not used as a content search. |
| chatgpt.com/share | HTTP 403 Cloudflare | Not a paste index. Dropped. |

`psbdmp.ws` (not in the old list, but the usual paste-dump index) has **no DNS**. `psbdmp.cc` is up and identifies its API as **Weakpass**, a hash and wordlist service. This app does not call that API.

## Providers

| Provider | Live check on 11 Oct 2026 | What it needs |
| --- | --- | --- |
| GitHub commits and repositories | **Working.** `HelloWorldMessage` returned commits (`total_count` 41) and repository hits with no token. | Nothing. A `GITHUB_TOKEN` raises the rate limit. Matches commit messages and repository metadata, not file bodies. |
| GitHub code search | **Needs key.** Unauthenticated call returned HTTP 401 `Requires authentication`. | Free GitHub personal access token. About 10 code searches a minute. Does not index gists. |
| GitHub Gist | **Blocked on purpose.** `robots.txt` disallows `/gist/` and `/search`. | No scrape. Indexed gist pages come from the Brave or Google dork, which includes `site:gist.github.com`. |
| Brave Search dorks | **Needs key.** Call without a token returned HTTP 422, missing `X-Subscription-Token`. | Brave Search API key. One request covers the paste-host list. |
| Google Programmable Search | **Needs key.** Call without a key returned HTTP 403. | `GOOGLE_CSE_API_KEY` and `GOOGLE_CSE_ID`. One request, not one per site. The engine must search the whole web. |
| Have I Been Pwned | **Needs key.** Paste and breach calls returned HTTP 401 `missing hibp-api-key`. | Paid API key. Email queries only. Returns breach and paste metadata, not dump files. |
| Intelligence X | **Needs key.** `free.intelx.io` and `public.intelx.io` returned HTTP 401 with no key. | Free account key for your own lookups. Results are titles and links. File bodies are not downloaded. |
| Pastebin scraping API | **Blocked without a whitelist.** `scrape.pastebin.com` returned HTTP 403 "YOUR IP DOES NOT HAVE ACCESS". | `PASTEBIN_SCRAPING_ENABLED=true` on a whitelisted PRO IP. Recent pastes only. |
| psbdmp | **Blocked.** `psbdmp.ws` does not resolve. `psbdmp.cc` is Weakpass. | Nothing to configure. The status is reported on every search. The user query is not sent. |

Dork hosts: pastebin.com, paste.ee, justpaste.it, rentry.co, dpaste.com, dpaste.org, controlc.com, ideone.com, bpa.st, nekobin.com, gist.github.com, hastebin.com, ghostbin.com, katb.in, cl1p.net, paste.org.ru, defuse.ca, termbin.com, write.as, privatebin.net.

### Keys that add the most coverage

1. **Brave Search API** — broadest paste-host coverage in one query. Monthly credit is about $5, which covers about 1,000 Search requests; further Search requests are about $5 per 1,000. A card is required for the credit, and Brave asks for attribution (the result text includes "Web results by Brave Search API").
2. **GitHub token** — free. This is the provider that searches public file contents. Code search is about 10 requests a minute.
3. **Intelligence X free key** — historical paste bucket. A signed-up free account is about 50 selector searches a day on `free.intelx.io`. Their product page lists Researcher at €2,500/year and the API license (required to embed IntelX in a product offered to others) at €7,000/year. Use a free key for your own lookups.
4. **Have I Been Pwned** — email breach and paste metadata. Core 1 is $4.39 per month billed annually ($52.68/year) at 10 requests a minute. Higher Core, Pro, and High RPM plans cost more.
5. **Google Programmable Search** — overlaps Brave. 100 queries a day free, then about $5 per 1,000, with a daily paid cap. Useful as a second index.
6. **Pastebin scraping API** — weakest lookup. It sees recent public pastes, not history, and needs one stable whitelisted IP. PRO was sold out when checked. Render's free web services do not keep a stable outbound IP, so leave this off in production unless you terminate traffic on a host you can whitelist.

## Run locally

Python 3.11 or 3.12.

```bash
pip install -r requirements.txt
export APP_ACCESS_PASSWORD='choose-a-long-password'
uvicorn paste_spotlight.app:app --host 0.0.0.0 --port 8000
```

Open `http://127.0.0.1:8000`. There is no default password. If `APP_ACCESS_PASSWORD` is unset, the process still starts (so a platform health check can pass) and the sign-in page explains that searches are closed.

Optional keys can live in a `.env` file you do not commit. See `.env.example`. Load them into the environment yourself (`set -a; source .env; set +a`) or with the process manager. The app reads the process environment. It does not open `.env` automatically.

## Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
python scripts/live_smoke.py
python scripts/live_smoke.py --query analyst@example.com --kind email
```

`pytest` mocks every provider. `scripts/live_smoke.py` makes a few real requests, prints status and hit counts, and does not print secret values. Exit 0 means every provider returned a status. Exit 1 means one raised.

## Deploy on Render

`render.yaml` defines one free-plan web service named `paste-site-spotlight`. It listens on `0.0.0.0:$PORT`, health-checks `GET /health`, and auto-deploys from `main`.

1. Merge this project to `main` (the service branch in the Blueprint).
2. Open `https://dashboard.render.com/blueprint/new?repo=<your-https-repo-url>` and apply the Blueprint.
3. When prompted, set `APP_ACCESS_PASSWORD`. Set `SESSION_SECRET` as well if you want session cookies to survive a password change. Leave API keys blank until you have them.
4. Confirm the service is live and `https://<service>.onrender.com/health` returns `{"status":"ok"}`.
5. Sign in and run a search. Providers without keys show **needs key**. GitHub's public search can return hits immediately. psbdmp and Gist show **blocked** with the reason.

Free web services spin down after a period of inactivity. The in-memory search limit resets when the process restarts. That limit is what protects provider quotas: default 8 searches per session per hour and 12 per IP per hour.

`/health`, `/login`, `/robots.txt`, and `/static` are reachable without the password so Render can health-check the service and the sign-in page can load its stylesheet. Every other route checks the session cookie.

## Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `APP_ACCESS_PASSWORD` | Yes, for sign-in | Password for every page except health, login, robots, and static files. No default. |
| `SESSION_SECRET` | No | Signs the session cookie. If empty, the app derives a key from the access password. |
| `SEARCHES_PER_HOUR` | No | Per-session search cap. Default 8. Range 1–60. |
| `IP_SEARCHES_PER_HOUR` | No | Per-IP search cap. Default 12. Range 1–120. |
| `LOGIN_ATTEMPTS_PER_HOUR` | No | Per-IP sign-in attempts. Default 10. |
| `BRAVE_SEARCH_API_KEY` | No | Enables Brave paste-host dorks. |
| `GOOGLE_CSE_API_KEY` | No | Enables Google Programmable Search. Both Google variables are required together. |
| `GOOGLE_CSE_ID` | No | Programmable Search engine ID. Turn on "search the entire web". |
| `GITHUB_TOKEN` | No | Enables code search and raises the limit on commit and repository search. |
| `HIBP_API_KEY` | No | Enables HIBP breach and paste lookups for email queries. |
| `INTELX_API_KEY` | No | Enables Intelligence X. |
| `INTELX_API_URL` | No | `https://free.intelx.io` (default), `https://2.intelx.io`, or `https://public.intelx.io`. Other hosts are rejected. |
| `INTELX_BUCKETS` | No | Comma-separated subset of `pastes`, `leaks.public`, `leaks`, `web.public`, `dumpster`, `whois`. Default `pastes,leaks.public`. |
| `PASTEBIN_SCRAPING_ENABLED` | No | `true` attempts the official recent-paste feed. Leave false on Render free. |
| `PASTEBIN_SCRAPING_LIMIT` | No | Recent pastes to list, 1–50. Default 25. At most 5 bodies are read. |
| `PASTEBIN_SCRAPE_DELAY` | No | Seconds between Pastebin body reads. Default 1, matching Pastebin's guidance. |

Do not commit `.env` or put secret values in `render.yaml`. Keys in the Blueprint are `sync: false`, so Render asks for them in the dashboard.

## Limits and safety

- Searches are capped per session and per IP.
- Sign-in attempts are capped per IP.
- Query text is validated. URLs are rejected. The server never requests a URL supplied by the user.
- Outbound calls use an HTTPS host allow-list and do not follow redirects. `trust_env` is off, so a proxy variable cannot retarget a provider.
- Pastebin body reads use keys returned by Pastebin and the fixed host `scrape.pastebin.com`.
- Intelligence X file-read endpoints are not called.
- CSV cells that start with `=`, `+`, `-`, or `@` are prefixed so a spreadsheet does not treat them as formulas.
- Unexpected errors return a short message. Stack traces are not sent to the browser.
