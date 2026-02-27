# SelectorScope — OSINT Dorking Tool

Multi-site Google dork search for selectors (emails, usernames, phones, password hashes) across 43 paste sites, chat platforms, code repos, and document sharing sites.

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Get a [Google Custom Search API Key](https://developers.google.com/custom-search/v1/introduction) and create a [Programmable Search Engine](https://programmablesearchengine.google.com/) with "Search the entire web" enabled.

3. Run locally:
   ```
   streamlit run app.py
   ```

4. Enter your API Key and CSE ID in the sidebar when the app loads.

## Features

- **43 target sites** across 5 categories: paste sites, chat/forums, code repos, document sharing, AI chat leaks
- **Auto-detection** of selector type (email, username, phone, hash)
- **Selective site targeting** — check/uncheck individual sites or entire categories
- **Triage engine** — 4-factor scoring: site reputation, context keywords, selector proximity, freshness
- **Severity ratings** — HIGH (red), MEDIUM (amber), LOW (green)
- **Context tagging** — Credential Dump, Data Breach, Doxx/PII, Stealer Logs, Account Access, Reference
- **Flag results** for focused export
- **Export** as CSV or JSON (all results or flagged only)
- **Copy dork queries** for manual Google searching
- **Report view** with sortable data table

## API Quota

Google CSE free tier: 100 queries/day. Each site uses 1 query. The sidebar tracks usage per session.
