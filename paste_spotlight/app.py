"""Paste Site Spotlight web application."""

import csv
import hmac
import io
import logging
import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from starlette.exceptions import HTTPException as StarletteHTTPException

from paste_spotlight import __version__
from paste_spotlight.auth import (
    COOKIE_NAME,
    CSRF_COOKIE,
    SESSION_TTL,
    issue_session,
    new_csrf_token,
    password_configured,
    password_matches,
    read_session,
    safe_next,
)
from paste_spotlight.config import (
    ip_searches_per_hour,
    login_attempts_per_hour,
    searches_per_hour,
)
from paste_spotlight.http_guard import make_client
from paste_spotlight.providers import PROVIDERS
from paste_spotlight.ratelimit import RateLimiter, client_ip
from paste_spotlight.search import STORE, run_search
from paste_spotlight.validate import ValidationError, validate_query

log = logging.getLogger("paste_spotlight")
PACKAGE = Path(__file__).resolve().parent

app = FastAPI(title="Paste Site Spotlight", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(PACKAGE / "static")), name="static")
templates = Jinja2Templates(directory=str(PACKAGE / "templates"))
LIMITER = RateLimiter()


def _highlight(text: str, query: str):
    safe = str(escape(text or ""))
    needle = str(escape(query or ""))
    if not needle:
        return Markup(safe)
    pattern = re.compile(re.escape(needle), re.IGNORECASE)
    return Markup(pattern.sub(lambda match: f"<mark>{match.group(0)}</mark>", safe))


templates.env.filters["highlight"] = _highlight


def _secure(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return proto == "https"


def _session(request: Request) -> dict | None:
    if not password_configured():
        return None
    return read_session(request.cookies.get(COOKIE_NAME))


def _csrf_ok(expected: str, supplied: str) -> bool:
    if not expected or not supplied:
        return False
    return hmac.compare_digest(expected, supplied)


def _provider_rows(selected: set[str] | None = None) -> list[dict]:
    rows = []
    for provider in PROVIDERS:
        readiness = provider.readiness
        rows.append(
            {
                "id": provider.id,
                "name": provider.name,
                "summary": provider.summary,
                "readiness": readiness,
                "checked": provider.id in selected if selected is not None else readiness in {"ready", "status_only", "needs_key"},
            }
        )
    return rows


def _render(request: Request, name: str, context: dict, status_code: int = 200):
    payload = {"request": request, "app_name": "Paste Site Spotlight", "version": __version__, **context}
    return templates.TemplateResponse(request, name, payload, status_code=status_code)


def _csv_safe(value: str) -> str:
    text = value or ""
    if text[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        return "'" + text
    return text


def _csv_body(payload: dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["provider", "status", "provider_message", "title", "url", "source", "timestamp", "snippet", "query", "query_type"]
    )
    for provider in payload.get("results") or []:
        hits = provider.get("hits") or [None]
        for hit in hits:
            hit = hit or {}
            writer.writerow(
                [
                    _csv_safe(provider.get("name") or ""),
                    _csv_safe(provider.get("status") or ""),
                    _csv_safe(provider.get("message") or ""),
                    _csv_safe(hit.get("title") or ""),
                    _csv_safe(hit.get("url") or ""),
                    _csv_safe(hit.get("source") or ""),
                    _csv_safe(hit.get("timestamp") or ""),
                    _csv_safe(hit.get("snippet") or ""),
                    _csv_safe(payload.get("query") or ""),
                    _csv_safe(payload.get("kind") or ""),
                ]
            )
    return buffer.getvalue()


class SecurityHeaders:
    """Add response headers without BaseHTTPMiddleware, which re-raises route errors."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"content-security-policy",
                            b"default-src 'self'; style-src 'self'; img-src 'self'; "
                            b"base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
                        ),
                        (b"cache-control", b"no-store"),
                    ]
                )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


app.add_middleware(SecurityHeaders)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return _render(
            request,
            "error.html",
            {"message": "That page does not exist.", "status_code": 404},
            status_code=404,
        )
    return _render(
        request,
        "error.html",
        {"message": "That request could not be completed.", "status_code": exc.status_code},
        status_code=exc.status_code,
    )


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error")
    return _render(
        request,
        "error.html",
        {"message": "Something went wrong. The details were not shown.", "status_code": 500},
        status_code=500,
    )


@app.get("/health")
def health():
    return JSONResponse({"status": "ok"})


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", media_type="text/plain")


@app.get("/login")
def login_form(request: Request, next: str = "/"):
    if _session(request):
        return RedirectResponse("/", status_code=303)
    token = request.cookies.get(CSRF_COOKIE) or new_csrf_token()
    response = _render(
        request,
        "login.html",
        {
            "csrf": token,
            "next": safe_next(next),
            "configured": password_configured(),
            "error": "",
        },
    )
    response.set_cookie(
        CSRF_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=_secure(request),
        max_age=3600,
        path="/",
    )
    return response


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    token = str(form.get("csrf") or "")
    cookie_token = request.cookies.get(CSRF_COOKIE) or ""
    destination = safe_next(str(form.get("next") or "/"))
    ip_key = "login:" + client_ip(request)
    if not LIMITER.allow(ip_key, login_attempts_per_hour()):
        return _render(
            request,
            "login.html",
            {
                "csrf": cookie_token,
                "next": destination,
                "configured": password_configured(),
                "error": "Too many sign-in attempts. Wait about an hour and try again.",
            },
            status_code=429,
        )
    if not _csrf_ok(cookie_token, token):
        return _render(
            request,
            "error.html",
            {"message": "The sign-in form expired. Refresh the page and try again.", "status_code": 400},
            status_code=400,
        )
    if not password_configured():
        return _render(
            request,
            "login.html",
            {
                "csrf": cookie_token,
                "next": destination,
                "configured": False,
                "error": "APP_ACCESS_PASSWORD is not set, so sign-in is disabled.",
            },
            status_code=503,
        )
    if not password_matches(str(form.get("password") or "")):
        return _render(
            request,
            "login.html",
            {
                "csrf": cookie_token,
                "next": destination,
                "configured": True,
                "error": "That password is not correct.",
            },
            status_code=401,
        )
    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        issue_session(),
        httponly=True,
        samesite="lax",
        secure=_secure(request),
        max_age=SESSION_TTL,
        path="/",
    )
    return response


@app.post("/logout")
async def logout(request: Request):
    session = _session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    if not _csrf_ok(session.get("csrf") or "", str(form.get("csrf") or "")):
        return _render(
            request,
            "error.html",
            {"message": "The sign-out form expired. Refresh the page and try again.", "status_code": 400},
            status_code=400,
        )
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@app.get("/")
def home(request: Request):
    session = _session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    limit = searches_per_hour()
    remaining = LIMITER.remaining("search:" + session["sid"], limit)
    return _render(
        request,
        "search.html",
        {
            "csrf": session["csrf"],
            "providers": _provider_rows(),
            "query": "",
            "kind": "email",
            "error": "",
            "results": None,
            "remaining": remaining,
            "limit": limit,
        },
    )


@app.post("/search")
async def search(request: Request):
    session = _session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    if not _csrf_ok(session.get("csrf") or "", str(form.get("csrf") or "")):
        return _render(
            request,
            "error.html",
            {"message": "The search form expired. Refresh the page and try again.", "status_code": 400},
            status_code=400,
        )
    kind = str(form.get("kind") or "keyword")
    text = str(form.get("q") or "")
    selected = [item for item in form.getlist("providers") if item in {provider.id for provider in PROVIDERS}]
    limit = searches_per_hour()
    base = {
        "csrf": session["csrf"],
        "providers": _provider_rows(set(selected)),
        "query": text,
        "kind": kind,
        "results": None,
        "remaining": LIMITER.remaining("search:" + session["sid"], limit),
        "limit": limit,
    }
    if not selected:
        base["error"] = "Choose at least one provider."
        return _render(request, "search.html", base, status_code=400)
    try:
        query = validate_query(text, kind)
    except ValidationError as exc:
        base["error"] = str(exc)
        return _render(request, "search.html", base, status_code=400)

    session_key = "search:" + session["sid"]
    ip_key = "search-ip:" + client_ip(request)
    if LIMITER.remaining(session_key, limit) == 0 or LIMITER.remaining(ip_key, ip_searches_per_hour()) == 0:
        base["error"] = "Hourly search limit reached. This cap protects API quotas. Try again later."
        base["remaining"] = 0
        return _render(request, "search.html", base, status_code=429)
    LIMITER.allow(session_key, limit)
    LIMITER.allow(ip_key, ip_searches_per_hour())

    with make_client() as client:
        results = run_search(query, selected, client)
    payload = {
        "query": query.text,
        "kind": query.kind,
        "results": [item.as_dict() for item in results],
    }
    STORE.put(session["sid"], payload)
    base.update(
        {
            "error": "",
            "query": query.text,
            "kind": query.kind,
            "results": payload["results"],
            "remaining": LIMITER.remaining(session_key, limit),
            "hit_count": sum(len(item.hits) for item in results),
        }
    )
    return _render(request, "search.html", base)


@app.post("/export.csv")
async def export_csv(request: Request):
    session = _session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    if not _csrf_ok(session.get("csrf") or "", str(form.get("csrf") or "")):
        return _render(
            request,
            "error.html",
            {"message": "The export form expired. Refresh the page and try again.", "status_code": 400},
            status_code=400,
        )
    payload = STORE.get(session["sid"])
    if not payload:
        return _render(
            request,
            "error.html",
            {"message": "There is no search to export yet. Run a search first.", "status_code": 404},
            status_code=404,
        )
    body = _csv_body(payload)
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="paste-site-spotlight.csv"'},
    )
