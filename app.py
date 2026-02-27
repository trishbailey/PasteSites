import streamlit as st
import requests
import re
import json
import csv
import io
import time
import pandas as pd
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="SelectorScope — OSINT Dorking Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# Custom CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
    /* Global */
    .block-container { padding-top: 1rem; max-width: 1200px; }
    
    /* Header */
    .app-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 0.5rem 0 1rem 0;
        border-bottom: 2px solid #e5e7eb;
        margin-bottom: 1.5rem;
    }
    .app-header-icon {
        background: #2563eb;
        color: white;
        width: 40px;
        height: 40px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 20px;
        flex-shrink: 0;
    }
    .app-header-text h1 {
        margin: 0;
        font-size: 1.5rem;
        font-weight: 700;
        color: #111827;
    }
    .app-header-text p {
        margin: 0;
        font-size: 0.85rem;
        color: #6b7280;
    }
    
    /* Result cards */
    .result-card {
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        background: white;
        border-left: 4px solid #d1d5db;
        transition: box-shadow 0.15s;
    }
    .result-card:hover {
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    .result-card.high { border-left-color: #ef4444; }
    .result-card.medium { border-left-color: #f59e0b; }
    .result-card.low { border-left-color: #22c55e; }
    
    .severity-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.03em;
    }
    .severity-high { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .severity-medium { background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }
    .severity-low { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
    
    .tag-pill {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 10px;
        font-size: 0.7rem;
        font-weight: 600;
        margin-right: 4px;
        margin-bottom: 4px;
    }
    .tag-domain { background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }
    .tag-category { background: #f5f3ff; color: #7c3aed; border: 1px solid #ddd6fe; }
    .tag-context { background: #fefce8; color: #a16207; border: 1px solid #fef08a; }
    
    .snippet-text {
        font-size: 0.85rem;
        color: #4b5563;
        line-height: 1.5;
        margin: 8px 0;
    }
    .highlight-selector {
        background: #fef08a;
        padding: 1px 3px;
        border-radius: 2px;
        font-weight: 600;
    }
    
    .result-title a {
        font-size: 0.95rem;
        font-weight: 600;
        color: #1e40af;
        text-decoration: none;
    }
    .result-title a:hover { text-decoration: underline; }
    
    /* Summary bar */
    .summary-bar {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 16px;
        display: flex;
        gap: 24px;
        align-items: center;
        flex-wrap: wrap;
    }
    .summary-stat {
        text-align: center;
    }
    .summary-stat .num {
        font-size: 1.5rem;
        font-weight: 700;
        color: #111827;
    }
    .summary-stat .label {
        font-size: 0.75rem;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* Sidebar refinements */
    [data-testid="stSidebar"] { background: #f9fafb; }
    
    /* Footer */
    .footer-text {
        text-align: center;
        font-size: 0.75rem;
        color: #9ca3af;
        padding: 2rem 0 1rem 0;
        border-top: 1px solid #e5e7eb;
        margin-top: 2rem;
    }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Site Database
# ─────────────────────────────────────────────
SITE_CATEGORIES = {
    "Paste Sites": {
        "sites": [
            "pastebin.com", "justpaste.it", "doxbin.com", "paste.ee",
            "gist.github.com", "rentry.co", "ghostbin.me", "dpaste.org",
            "hastebin.com", "controlc.com", "cl1p.net", "0bin.net",
            "ideone.com", "katb.in", "bpa.st", "nekobin.com",
            "paste.org.ru", "cryptpad.fr", "textbin.net", "termbin.com",
            "write.as", "defuse.ca/pastebin.htm"
        ],
        "icon": "📋"
    },
    "Chat & Forums": {
        "sites": [
            "t.me", "discord.com", "reddit.com", "archived.moe",
            "desuarchive.org", "breachforums.st", "xss.is",
            "keybase.io", "irclog.org", "kiwifarms.net"
        ],
        "icon": "💬"
    },
    "Code & Config": {
        "sites": [
            "github.com", "gitlab.com", "bitbucket.org",
            "stackoverflow.com", "documenter.postman.com"
        ],
        "icon": "💻"
    },
    "Documents & Files": {
        "sites": [
            "docs.google.com", "drive.google.com", "trello.com",
            "scribd.com", "archive.org"
        ],
        "icon": "📄"
    },
    "AI Chat Leaks": {
        "sites": ["chatgpt.com/share"],
        "icon": "🤖"
    }
}

# Site reputation scores (0-30)
SITE_REPUTATION = {
    "doxbin.com": 30,
    "pastebin.com": 25, "paste.ee": 25, "justpaste.it": 25,
    "breachforums.st": 25, "xss.is": 25, "kiwifarms.net": 25,
    "t.me": 20, "discord.com": 20,
    "gist.github.com": 15, "github.com": 15,
    "reddit.com": 15, "archived.moe": 15, "desuarchive.org": 15,
    "docs.google.com": 15, "drive.google.com": 15, "trello.com": 15,
    "chatgpt.com/share": 15,
    "stackoverflow.com": 10, "scribd.com": 10, "archive.org": 10,
}
DEFAULT_REPUTATION = 20

# Context keyword scoring
CONTEXT_KEYWORDS = {
    "credential_dump": {
        "words": ["password", "passwd", "combo", "combolist", "email:pass", "user:pass", "email:password"],
        "points": 15,
        "label": "Credential Dump"
    },
    "data_breach": {
        "words": ["leak", "leaked", "dump", "dumped", "breach", "breached", "database", "db dump", "sql"],
        "points": 12,
        "label": "Data Breach"
    },
    "doxx_pii": {
        "words": ["dox", "doxx", "doxxed", "ssn", "social security", "fullz", "cc", "cvv", "bin"],
        "points": 15,
        "label": "Doxx / PII"
    },
    "stealer_logs": {
        "words": ["stealer", "stealer log", "redline", "raccoon", "vidar", "log"],
        "points": 15,
        "label": "Stealer Logs"
    },
    "account_access": {
        "words": ["credential", "cred", "login", "account"],
        "points": 10,
        "label": "Account Access"
    },
    "contact_info": {
        "words": ["phone", "number", "address", "dob"],
        "points": 5,
        "label": "Contact Info"
    }
}


# ─────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────
def detect_selector_type(selector: str) -> tuple[str, str]:
    """Detect the type of selector entered. Returns (type_name, emoji)."""
    selector = selector.strip()
    if "@" in selector and "." in selector:
        return "Email", "📧"
    if re.match(r'^[\+]?[\d\s\-\(\)\.]{7,15}$', selector):
        return "Phone", "📱"
    if re.match(r'^[a-fA-F0-9]{32,}$', selector):
        return "Password/Hash", "🔑"
    return "Username", "👤"


def build_dork_query(site: str, selector: str) -> str:
    """Build a Google dork query for a specific site and selector."""
    return f'site:{site} "{selector}"'


def search_google_cse(query: str, api_key: str, cse_id: str) -> dict:
    """Execute a single Google Custom Search API query."""
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": cse_id,
        "q": query,
        "num": 10
    }
    try:
        response = requests.get(url, params=params, timeout=15)
        if response.status_code == 200:
            return {"success": True, "data": response.json(), "query": query}
        elif response.status_code == 429:
            return {"success": False, "error": "Rate limited", "query": query}
        else:
            return {"success": False, "error": f"HTTP {response.status_code}", "query": query}
    except requests.RequestException as e:
        return {"success": False, "error": str(e), "query": query}


def extract_date_from_result(item: dict) -> str | None:
    """Try to extract a date from a Google search result."""
    # Check metatags
    if "pagemap" in item:
        metatags = item.get("pagemap", {}).get("metatags", [{}])
        if metatags:
            for key in ["date", "article:published_time", "og:updated_time", "datePublished"]:
                if key in metatags[0]:
                    return metatags[0][key][:10]
    # Check snippet for date patterns
    snippet = item.get("snippet", "")
    date_match = re.search(r'(\w{3}\s+\d{1,2},\s+\d{4})', snippet)
    if date_match:
        return date_match.group(1)
    date_match = re.search(r'(\d{4}-\d{2}-\d{2})', snippet)
    if date_match:
        return date_match.group(1)
    return None


def compute_freshness_score(date_str: str | None) -> int:
    """Score freshness: 0-15 points."""
    if not date_str:
        return 0
    try:
        # Try multiple date formats
        for fmt in ["%Y-%m-%d", "%b %d, %Y", "%B %d, %Y"]:
            try:
                dt = datetime.strptime(date_str[:10], fmt)
                break
            except ValueError:
                continue
        else:
            return 0
        
        days_ago = (datetime.now() - dt).days
        if days_ago <= 7:
            return 15
        elif days_ago <= 30:
            return 10
        elif days_ago <= 90:
            return 5
        return 0
    except Exception:
        return 0


def compute_triage_score(item: dict, site: str, selector: str) -> dict:
    """Compute full triage score for a search result."""
    title = item.get("title", "").lower()
    snippet = item.get("snippet", "").lower()
    combined = f"{title} {snippet}"
    
    # 1. Site reputation (0-30)
    reputation_score = SITE_REPUTATION.get(site, DEFAULT_REPUTATION)
    
    # 2. Context keywords (0-40, capped)
    context_score = 0
    matched_contexts = []
    for ctx_key, ctx_info in CONTEXT_KEYWORDS.items():
        for word in ctx_info["words"]:
            if word in combined:
                context_score += ctx_info["points"]
                if ctx_info["label"] not in matched_contexts:
                    matched_contexts.append(ctx_info["label"])
                break  # Only count each category once
    context_score = min(context_score, 40)
    
    # 3. Selector proximity (0-15)
    proximity_score = 0
    selector_lower = selector.lower()
    if selector_lower in combined:
        proximity_score += 10
    # Check for colon/pipe patterns near selector
    if re.search(rf'{re.escape(selector_lower)}\s*[:\|]', combined) or \
       re.search(rf'[:\|]\s*{re.escape(selector_lower)}', combined):
        proximity_score += 5
    proximity_score = min(proximity_score, 15)
    
    # 4. Freshness (0-15)
    date_str = extract_date_from_result(item)
    freshness_score = compute_freshness_score(date_str)
    
    # Total
    total_score = reputation_score + context_score + proximity_score + freshness_score
    total_score = min(total_score, 100)
    
    # Severity
    if total_score >= 60:
        severity = "HIGH"
    elif total_score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    # Default context if none matched
    if not matched_contexts:
        matched_contexts = ["Reference"]
    
    return {
        "score": total_score,
        "severity": severity,
        "reputation_score": reputation_score,
        "context_score": context_score,
        "proximity_score": proximity_score,
        "freshness_score": freshness_score,
        "context_tags": matched_contexts,
        "date": date_str
    }


def get_category_for_site(site: str) -> str:
    """Get the category name for a given site."""
    for cat_name, cat_info in SITE_CATEGORIES.items():
        if site in cat_info["sites"]:
            return cat_name
    return "Other"


def highlight_selector_in_snippet(snippet: str, selector: str) -> str:
    """Highlight the selector within the snippet text."""
    if not snippet or not selector:
        return snippet
    pattern = re.compile(re.escape(selector), re.IGNORECASE)
    return pattern.sub(f'<span class="highlight-selector">{selector}</span>', snippet)


def results_to_dataframe(results: list) -> pd.DataFrame:
    """Convert results to a pandas DataFrame for export."""
    rows = []
    for r in results:
        rows.append({
            "Severity": r["severity"],
            "Score": r["score"],
            "Title": r["title"],
            "URL": r["url"],
            "Site": r["site"],
            "Category": r["category"],
            "Context Tags": ", ".join(r["context_tags"]),
            "Snippet": r["snippet"],
            "Date": r.get("date", ""),
        })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────
# API Credentials: Secrets first, manual fallback
# ─────────────────────────────────────────────
def get_api_credentials() -> tuple[str, str]:
    """Load API key and CSE ID from Streamlit secrets if available."""
    api_key = ""
    cse_id = ""
    try:
        api_key = st.secrets["GOOGLE_CSE_API_KEY"]
        cse_id = st.secrets["GOOGLE_CSE_ID"]
    except (KeyError, FileNotFoundError):
        pass
    return api_key, cse_id

SECRETS_API_KEY, SECRETS_CSE_ID = get_api_credentials()
USING_SECRETS = bool(SECRETS_API_KEY and SECRETS_CSE_ID)


# ─────────────────────────────────────────────
# Session State Initialization
# ─────────────────────────────────────────────
if "results" not in st.session_state:
    st.session_state.results = []
if "queries_used" not in st.session_state:
    st.session_state.queries_used = 0
if "flagged" not in st.session_state:
    st.session_state.flagged = set()
if "search_complete" not in st.session_state:
    st.session_state.search_complete = False
if "selected_sites" not in st.session_state:
    # Default: all sites selected
    all_sites = []
    for cat_info in SITE_CATEGORIES.values():
        all_sites.extend(cat_info["sites"])
    st.session_state.selected_sites = set(all_sites)


# ─────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────
st.markdown("""
<div class="app-header">
    <div class="app-header-icon">🔍</div>
    <div class="app-header-text">
        <h1>SelectorScope</h1>
        <p>Multi-site Google dork search for selectors</p>
    </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Sidebar: Configuration & Site Selection
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ API Configuration")
    
    if USING_SECRETS:
        # Credentials loaded from Streamlit secrets — no manual entry needed
        api_key = SECRETS_API_KEY
        cse_id = SECRETS_CSE_ID
        st.success("API configured via secrets")
        st.caption("Credentials are managed by the app owner.")
    else:
        # Fallback: manual entry (for local dev or if secrets aren't set)
        st.caption("No secrets found — enter credentials manually.")
        api_key = st.text_input(
            "Google CSE API Key",
            type="password",
            help="Your credentials stay in this session only and are never stored."
        )
        cse_id = st.text_input(
            "Custom Search Engine ID",
            help="Found in your Programmable Search Engine settings."
        )
        
        if api_key and cse_id:
            st.success("API configured")
        else:
            st.warning("Enter API credentials to search")
    
    st.markdown("---")
    
    # Quota tracker
    remaining = max(0, 100 - st.session_state.queries_used)
    st.markdown(f"**Queries used today:** {st.session_state.queries_used}")
    st.progress(min(st.session_state.queries_used / 100, 1.0))
    st.caption(f"~{remaining} queries remaining (estimated)")
    
    st.markdown("---")
    
    # Site selection
    st.markdown("### 🎯 Target Sites")
    
    total_all = sum(len(c["sites"]) for c in SITE_CATEGORIES.values())
    total_selected = len(st.session_state.selected_sites)
    st.caption(f"{total_selected} of {total_all} sites selected — ~{total_selected} queries per search")
    
    for cat_name, cat_info in SITE_CATEGORIES.items():
        with st.expander(f"{cat_info['icon']} {cat_name} ({len(cat_info['sites'])})", expanded=False):
            # Select/Deselect all for category
            cat_sites = set(cat_info["sites"])
            all_selected = cat_sites.issubset(st.session_state.selected_sites)
            
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button(f"Select All", key=f"sel_{cat_name}"):
                    st.session_state.selected_sites.update(cat_sites)
                    st.rerun()
            with col_b:
                if st.button(f"Deselect All", key=f"desel_{cat_name}"):
                    st.session_state.selected_sites -= cat_sites
                    st.rerun()
            
            for site in cat_info["sites"]:
                checked = st.checkbox(
                    site,
                    value=(site in st.session_state.selected_sites),
                    key=f"chk_{site}"
                )
                if checked:
                    st.session_state.selected_sites.add(site)
                else:
                    st.session_state.selected_sites.discard(site)


# ─────────────────────────────────────────────
# Main Area: Search
# ─────────────────────────────────────────────
col_search, col_badge = st.columns([5, 1])

with col_search:
    selector = st.text_input(
        "Enter selector",
        placeholder="email, username, phone, password hash...",
        label_visibility="collapsed"
    )

with col_badge:
    if selector:
        stype, semoji = detect_selector_type(selector)
        st.markdown(f"<div style='padding-top:5px'>{semoji} <strong>{stype}</strong></div>", unsafe_allow_html=True)

# Search controls
col_btn1, col_btn2, col_btn3, col_info = st.columns([1, 1, 1, 3])

with col_btn1:
    search_clicked = st.button("🔍 Search", type="primary", use_container_width=True)

with col_btn2:
    if st.button("🗑️ Clear", use_container_width=True):
        st.session_state.results = []
        st.session_state.flagged = set()
        st.session_state.search_complete = False
        st.rerun()

with col_btn3:
    copy_dorks = st.button("📋 Copy Dorks", use_container_width=True)

with col_info:
    selected_count = len(st.session_state.selected_sites)
    if selector:
        st.caption(f"Will send {selected_count} queries for \"{selector}\"")

# Copy dork queries to clipboard
if copy_dorks and selector:
    dork_lines = []
    for site in sorted(st.session_state.selected_sites):
        dork_lines.append(build_dork_query(site, selector))
    dork_text = "\n".join(dork_lines)
    st.code(dork_text, language="text")
    st.info("Copy the queries above. Each line is a ready-to-paste Google search.")


# ─────────────────────────────────────────────
# Search Execution
# ─────────────────────────────────────────────
if search_clicked:
    if not api_key or not cse_id:
        st.error("Please configure your API key and CSE ID in the sidebar.")
    elif not selector:
        st.error("Please enter a selector to search.")
    elif not st.session_state.selected_sites:
        st.error("Please select at least one target site.")
    else:
        st.session_state.results = []
        st.session_state.flagged = set()
        st.session_state.search_complete = False
        
        selected = sorted(st.session_state.selected_sites)
        total = len(selected)
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        all_results = []
        errors = []
        completed = 0
        
        # Throttled parallel execution (5 concurrent)
        def search_site(site):
            query = build_dork_query(site, selector)
            return site, search_google_cse(query, api_key, cse_id)
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(search_site, site): site for site in selected}
            
            for future in as_completed(futures):
                completed += 1
                site = futures[future]
                progress_bar.progress(completed / total)
                status_text.text(f"Searching... {completed}/{total} sites queried")
                
                try:
                    site, result = future.result()
                    st.session_state.queries_used += 1
                    
                    if result["success"]:
                        items = result["data"].get("items", [])
                        for item in items:
                            triage = compute_triage_score(item, site, selector)
                            all_results.append({
                                "title": item.get("title", "No title"),
                                "url": item.get("link", ""),
                                "snippet": item.get("snippet", ""),
                                "site": site,
                                "category": get_category_for_site(site),
                                "score": triage["score"],
                                "severity": triage["severity"],
                                "context_tags": triage["context_tags"],
                                "date": triage["date"],
                                "reputation_score": triage["reputation_score"],
                                "context_score": triage["context_score"],
                                "proximity_score": triage["proximity_score"],
                                "freshness_score": triage["freshness_score"],
                            })
                    else:
                        errors.append(f"{site}: {result['error']}")
                except Exception as e:
                    errors.append(f"{site}: {str(e)}")
                
                # Small delay to be respectful
                time.sleep(0.1)
        
        # Sort by score descending
        all_results.sort(key=lambda x: x["score"], reverse=True)
        
        st.session_state.results = all_results
        st.session_state.search_complete = True
        
        progress_bar.empty()
        status_text.empty()
        
        if errors:
            with st.expander(f"⚠️ {len(errors)} site(s) had errors", expanded=False):
                for err in errors:
                    st.text(err)
        
        st.rerun()


# ─────────────────────────────────────────────
# Results Display
# ─────────────────────────────────────────────
if st.session_state.search_complete and st.session_state.results:
    results = st.session_state.results
    
    # Summary bar
    high_count = sum(1 for r in results if r["severity"] == "HIGH")
    med_count = sum(1 for r in results if r["severity"] == "MEDIUM")
    low_count = sum(1 for r in results if r["severity"] == "LOW")
    sites_hit = len(set(r["site"] for r in results))
    
    st.markdown(f"""
    <div class="summary-bar">
        <div class="summary-stat">
            <div class="num">{len(results)}</div>
            <div class="label">Total Results</div>
        </div>
        <div class="summary-stat">
            <div class="num" style="color: #ef4444;">🔴 {high_count}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-stat">
            <div class="num" style="color: #f59e0b;">🟡 {med_count}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-stat">
            <div class="num" style="color: #22c55e;">🟢 {low_count}</div>
            <div class="label">Low</div>
        </div>
        <div class="summary-stat">
            <div class="num">{sites_hit}</div>
            <div class="label">Sites with Hits</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    
    with col_f1:
        severity_filter = st.selectbox(
            "Filter by severity",
            ["All", "HIGH", "MEDIUM", "LOW"],
            index=0
        )
    
    with col_f2:
        category_options = ["All"] + list(SITE_CATEGORIES.keys())
        category_filter = st.selectbox(
            "Filter by category",
            category_options,
            index=0
        )
    
    with col_f3:
        sort_option = st.selectbox(
            "Sort by",
            ["Threat Score", "Site", "Date"],
            index=0
        )
    
    # Apply filters
    filtered = results.copy()
    if severity_filter != "All":
        filtered = [r for r in filtered if r["severity"] == severity_filter]
    if category_filter != "All":
        filtered = [r for r in filtered if r["category"] == category_filter]
    
    # Apply sort
    if sort_option == "Site":
        filtered.sort(key=lambda x: x["site"])
    elif sort_option == "Date":
        filtered.sort(key=lambda x: x.get("date") or "", reverse=True)
    # Default: already sorted by score
    
    st.caption(f"Showing {len(filtered)} of {len(results)} results")
    
    # Result cards
    for i, r in enumerate(filtered):
        severity_class = r["severity"].lower()
        badge_class = f"severity-{severity_class}"
        
        # Highlight selector in snippet
        highlighted_snippet = highlight_selector_in_snippet(r["snippet"], selector) if selector else r["snippet"]
        
        # Context tags HTML
        tags_html = ""
        tags_html += f'<span class="tag-pill tag-domain">{r["site"]}</span>'
        tags_html += f'<span class="tag-pill tag-category">{r["category"]}</span>'
        for tag in r["context_tags"]:
            tags_html += f'<span class="tag-pill tag-context">{tag}</span>'
        
        # Date display
        date_html = f'<span style="font-size:0.75rem; color:#9ca3af;">Indexed: {r["date"]}</span>' if r.get("date") else ""
        
        # Score breakdown tooltip
        score_detail = f'Rep: {r["reputation_score"]} | Ctx: {r["context_score"]} | Prox: {r["proximity_score"]} | Fresh: {r["freshness_score"]}'
        
        card_html = f"""
        <div class="result-card {severity_class}">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:6px;">
                <div>
                    <span class="severity-badge {badge_class}" title="{score_detail}">{r["severity"]} ({r["score"]})</span>
                    {tags_html}
                </div>
                {date_html}
            </div>
            <div class="result-title">
                <a href="{r["url"]}" target="_blank" rel="noopener noreferrer">{r["title"][:100]}</a>
            </div>
            <div class="snippet-text">{highlighted_snippet}</div>
        </div>
        """
        st.markdown(card_html, unsafe_allow_html=True)
        
        # Flag button (using Streamlit native button for interactivity)
        result_key = r["url"]
        col_open, col_flag, col_space = st.columns([1, 1, 6])
        with col_open:
            st.link_button("Open ↗", r["url"], use_container_width=True)
        with col_flag:
            is_flagged = result_key in st.session_state.flagged
            flag_label = "★ Flagged" if is_flagged else "☆ Flag"
            if st.button(flag_label, key=f"flag_{i}_{result_key[:30]}"):
                if is_flagged:
                    st.session_state.flagged.discard(result_key)
                else:
                    st.session_state.flagged.add(result_key)
                st.rerun()
    
    # ─────────────────────────────────────────
    # Export Section
    # ─────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📦 Export Results")
    
    flagged_count = len(st.session_state.flagged)
    
    col_e1, col_e2, col_e3, col_e4 = st.columns(4)
    
    with col_e1:
        # Export All as CSV
        df_all = results_to_dataframe(results)
        csv_all = df_all.to_csv(index=False)
        st.download_button(
            f"⬇ Export All CSV ({len(results)})",
            data=csv_all,
            file_name=f"selectorscope_{selector}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    
    with col_e2:
        # Export All as JSON
        json_all = json.dumps(results, indent=2, default=str)
        st.download_button(
            f"⬇ Export All JSON ({len(results)})",
            data=json_all,
            file_name=f"selectorscope_{selector}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col_e3:
        # Export Flagged as CSV
        if flagged_count > 0:
            flagged_results = [r for r in results if r["url"] in st.session_state.flagged]
            df_flagged = results_to_dataframe(flagged_results)
            csv_flagged = df_flagged.to_csv(index=False)
            st.download_button(
                f"⬇ Flagged CSV ({flagged_count})",
                data=csv_flagged,
                file_name=f"selectorscope_flagged_{selector}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        else:
            st.button("⬇ Flagged CSV (0)", disabled=True, use_container_width=True)
    
    with col_e4:
        # Export Flagged as JSON
        if flagged_count > 0:
            flagged_results = [r for r in results if r["url"] in st.session_state.flagged]
            json_flagged = json.dumps(flagged_results, indent=2, default=str)
            st.download_button(
                f"⬇ Flagged JSON ({flagged_count})",
                data=json_flagged,
                file_name=f"selectorscope_flagged_{selector}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        else:
            st.button("⬇ Flagged JSON (0)", disabled=True, use_container_width=True)
    
    # ─────────────────────────────────────────
    # Report View
    # ─────────────────────────────────────────
    with st.expander("📊 Generate Report View"):
        st.markdown(f"## OSINT Selector Search Report")
        st.markdown(f"**Selector:** `{selector}`")
        st.markdown(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        st.markdown(f"**Sites Queried:** {selected_count}")
        st.markdown(f"**Total Results:** {len(results)}")
        st.markdown(f"**Breakdown:** 🔴 {high_count} High | 🟡 {med_count} Medium | 🟢 {low_count} Low")
        st.markdown("---")
        
        # Results table
        df_report = results_to_dataframe(results)
        st.dataframe(
            df_report,
            use_container_width=True,
            hide_index=True,
            column_config={
                "URL": st.column_config.LinkColumn("URL"),
                "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100),
            }
        )
        
        st.caption("Use Ctrl+P / Cmd+P to print this report view.")


elif st.session_state.search_complete and not st.session_state.results:
    st.info("No results found for this selector across the selected sites.")

elif not st.session_state.search_complete:
    # Landing state
    st.markdown("""
    <div style="text-align: center; padding: 3rem 1rem; color: #9ca3af;">
        <p style="font-size: 3rem; margin-bottom: 0.5rem;">🔍</p>
        <p style="font-size: 1.1rem; font-weight: 500; color: #6b7280;">Enter a selector and hit Search</p>
        <p style="font-size: 0.85rem;">Supports emails, usernames, phone numbers, and password hashes</p>
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────
st.markdown("""
<div class="footer-text">
    Results sourced via Google Custom Search API. This tool does not store any data beyond the current session.
</div>
""", unsafe_allow_html=True)
