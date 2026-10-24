"""Request-level plumbing shared by all routes.

Covers session resolution, cookie handling, CSRF double-submit tokens,
one-shot flash messages, safe redirect validation and HTML rendering.
"""

from __future__ import annotations

import base64
import binascii
import io
import secrets
import sqlite3
import urllib.parse
from collections.abc import Iterator

import qrcode
import qrcode.image.svg
from fastapi import Request
from fastapi.responses import HTMLResponse
from starlette.datastructures import URL

from craftpass import db
from craftpass.config import Settings
from craftpass.tokens import TokenError, TokenService

_FLASH_COOKIE = "craftpass_flash"
_FLASH_MAX_AGE = 30  # seconds — just long enough for one redirect hop
_CSRF_MIN_LEN = 16


# --------------------------------------------------------------------------
# Session resolution
# --------------------------------------------------------------------------
def session_payload(request: Request) -> dict | None:
    """Decode the session cookie without touching the database."""
    settings: Settings = request.app.state.settings
    tokens: TokenService = request.app.state.tokens
    raw = request.cookies.get(settings.session_cookie_name)
    if not raw:
        return None
    try:
        return tokens.decode_session(raw)
    except TokenError:
        return None


def current_session_user(request: Request, conn: sqlite3.Connection) -> sqlite3.Row | None:
    """Return the logged-in, active user row, or None.

    Combines JWT verification with a fresh database lookup: a disabled or
    deleted user is treated as signed out even while an old cookie persists.
    Group claims are re-read from the DB as well, so membership changes
    apply without waiting for the cookie to expire.
    """
    payload = session_payload(request)
    if payload is None:
        return None
    user = db.user_by_id(conn, int(payload["sub"]))
    if user is None or not user["is_active"]:
        return None
    return user


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    """FastAPI dependency yielding one connection per request."""
    conn = db.connect(request.app.state.settings)
    try:
        yield conn
    finally:
        conn.close()


def set_session_cookie(response, token: str, settings: Settings) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        domain=settings.cookie_domain,
        max_age=settings.session_ttl_seconds,
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response, settings: Settings) -> None:
    response.delete_cookie(settings.session_cookie_name, domain=settings.cookie_domain, path="/")


# --------------------------------------------------------------------------
# CSRF (double-submit cookie)
# --------------------------------------------------------------------------
def csrf_token(request) -> str:
    """Existing CSRF cookie value, or a freshly minted one.

    The fresh value is stashed on the request scope; `render()` copies it
    onto the response so the browser stores the same token the form carried.
    """
    settings: Settings = request.app.state.settings
    existing = request.cookies.get(settings.csrf_cookie_name)
    if existing and len(existing) >= _CSRF_MIN_LEN:
        return existing
    token = secrets.token_urlsafe(24)
    request.scope["craftpass_pending_csrf"] = token
    return token


def csrf_ok(request, submitted: str | None) -> bool:
    """Validate a double-submit pair in constant time."""
    settings: Settings = request.app.state.settings
    stored = request.cookies.get(settings.csrf_cookie_name, "")
    if not stored or not submitted:
        return False
    return secrets.compare_digest(stored, submitted)


# --------------------------------------------------------------------------
# Flash messages (one redirect hop)
# --------------------------------------------------------------------------
def flash(response, message: str, kind: str = "info") -> None:
    payload = urllib.parse.quote(f"{kind}|{message}")
    response.set_cookie(_FLASH_COOKIE, payload, max_age=_FLASH_MAX_AGE, httponly=True, path="/")


def _pop_flash(request):
    raw = request.cookies.get(_FLASH_COOKIE)
    if not raw:
        return None
    try:
        kind, _, message = urllib.parse.unquote(raw).partition("|")
        return {"kind": kind or "info", "message": message}
    except (binascii.Error, ValueError):  # pragma: no cover - defensive
        return None


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def render(
    request: Request, name: str, context: dict | None = None, *, status_code: int = 200
) -> HTMLResponse:
    """Render a template with the shared context (CSRF + flash + settings)."""
    settings: Settings = request.app.state.settings
    token = csrf_token(request)
    ctx = {
        "request": request,
        "settings": settings,
        "brand": "CraftPass",
        "csrf_token": token,
        "current_user": None,
        "flash": _pop_flash(request),
    }
    ctx.update(context or {})

    templates = request.app.state.templates
    response = templates.TemplateResponse(request, name, ctx, status_code=status_code)
    if "craftpass_pending_csrf" in request.scope:
        response.set_cookie(
            settings.csrf_cookie_name,
            request.scope["craftpass_pending_csrf"],
            max_age=3600 * 12,
            secure=settings.secure_cookies,
            httponly=True,
            samesite="lax",
            path="/",
        )
    if request.cookies.get(_FLASH_COOKIE):
        response.delete_cookie(_FLASH_COOKIE, path="/")
    return response


# --------------------------------------------------------------------------
# Redirect safety
# --------------------------------------------------------------------------
def safe_redirect(value: str | None, settings: Settings) -> str | None:
    """Validate a user-supplied redirect target.

    Accepts absolute URLs whose host equals the parent domain or one of its
    subdomains, plus site-relative paths (``/account``). Rejects everything
    else — cross-origin targets, scheme-less hosts, userinfo, fragments.
    """
    if not value:
        return None
    if value.startswith("/") and not value.startswith("//"):
        return value
    # Fragments are a browser concept; drop them before parsing.
    value = value.split("#", 1)[0]
    try:
        url = URL(value)
    except ValueError:
        return None
    if url.scheme not in ("https", "http"):
        return None
    if url.username or url.password:
        return None
    host = (url.hostname or "").lower().rstrip(".")
    if not host:
        return None
    suffix = settings.cookie_suffix
    http_ok = url.scheme == "https" or not settings.secure_cookies
    host_ok = host == suffix or host.endswith(f".{suffix}")
    if http_ok and host_ok:
        return str(url)
    return None


def original_url(request, fallback_domain: str | None = None, https: bool = True) -> str:
    """Best-effort reconstruction of the URL the user originally requested.

    Used by /verify to bounce unauthenticated users to the login page and
    send them right back where they were afterwards. Trust order:
    X-Forwarded-Host (set by Caddy to the *public* host), then the app's
    registered domain. The raw Host header is deliberately ignored — behind
    forward_auth it is the auth upstream's container hostname.
    """
    forwarded_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    forwarded_uri = request.headers.get("x-forwarded-uri", "").strip()

    host = forwarded_host or fallback_domain
    if not host:
        return "/"
    proto = forwarded_proto or ("https" if https else "http")
    path = forwarded_uri or "/"
    return f"{proto}://{host}{path}"


def login_redirect_url(request, settings: Settings, fallback_domain: str | None = None) -> str:
    target = original_url(request, fallback_domain)
    quoted = urllib.parse.quote(target, safe="")
    return f"{settings.issuer}/login?rd={quoted}"


# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------
def client_ip(request) -> str:
    if request.client is None:  # test transports
        return "127.0.0.1"
    return request.client.host


def totp_qr_svg(uri: str) -> str:
    """Render an otpauth:// provisioning URI as an inline SVG data URI."""
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=12)
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/svg+xml;base64,{encoded}"
