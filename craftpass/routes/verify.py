"""Caddy forward-auth verification endpoint.

Contract with Caddy's ``forward_auth`` directive:

* ``200`` + ``X-Auth-User`` / ``X-Auth-Groups`` — request allowed; the headers
  are copied onto the proxied request (``copy_headers``).
* ``302`` to the login page — no valid session; the browser authenticates at
  ``auth.labcraft.me`` and is returned to the URL it originally requested.
* ``403`` HTML — signed in, but not a member of the app's required group.
* ``404`` HTML — unknown app slug (Caddyfile/config mismatch).
"""

from __future__ import annotations

from sqlite3 import Connection

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse

from craftpass import db
from craftpass.config import Settings
from craftpass.web import (
    current_session_user,
    get_conn,
    login_redirect_url,
    render,
)

router = APIRouter()


def _decide(request: Request, conn: Connection, slug: str):
    settings: Settings = request.app.state.settings

    app = db.app_by_slug(conn, slug) if slug else None
    if app is None:
        detail = (
            f"No app is registered for slug {slug!r}. Check the Caddyfile "
            "import argument against the Apps table in /admin."
            if slug
            else "The verify endpoint needs an app slug: /verify/<slug>."
        )
        return render(
            request,
            "errors/error.html",
            {"status": 404, "detail": detail},
            status_code=404,
        )

    user = current_session_user(request, conn)
    if user is None:
        # No (or stale) session cookie: bounce through the login page and
        # come straight back. The original URL is reconstructed from the
        # proxy headers when available, otherwise the app's registered
        # domain is used as a safe fallback.
        return RedirectResponse(
            login_redirect_url(request, settings, app["domain"]), status_code=302
        )

    groups = db.group_names(conn, user["id"])
    required = app["required_group"]
    if not (user["is_admin"] or required is None or required in groups):
        return render(
            request,
            "errors/403.html",
            {
                "app_name": app["display_name"],
                "app_slug": slug,
                "current_user": user,
                "back_url": settings.default_redirect_url,
            },
            status_code=403,
        )

    return JSONResponse(
        {"app": slug, "user": user["username"], "groups": groups},
        headers={
            "X-Auth-User": user["username"],
            "X-Auth-Groups": ", ".join(groups),
        },
    )


@router.get("/verify/{slug}")
def verify_path(slug: str, request: Request, conn: Connection = Depends(get_conn)):
    return _decide(request, conn, slug)


@router.get("/verify")
def verify_query(request: Request, conn: Connection = Depends(get_conn), app: str = ""):
    return _decide(request, conn, app)
