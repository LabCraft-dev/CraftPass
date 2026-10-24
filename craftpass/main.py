"""Application factory and module-level `app` for uvicorn."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from craftpass import db
from craftpass.config import Settings, get_settings
from craftpass.ratelimit import SlidingWindowLimiter
from craftpass.routes import admin, oidc, portal, verify
from craftpass.security import PasswordService, TotpService
from craftpass.tokens import TokenService
from craftpass.web import render

BASE_DIR = Path(__file__).resolve().parent
_LOG = logging.getLogger("craftpass")

_CSP = (
    "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

HTTP_NOT_FOUND = 404


@asynccontextmanager
async def _lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    db.init_db(settings)
    app.state.tokens.load_or_create()
    _LOG.info("CraftPass ready — issuer %s, database %s", settings.issuer, settings.db_path)
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    app = FastAPI(
        title="CraftPass",
        version="0.1.0",
        lifespan=_lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.tokens = TokenService(settings)
    app.state.passwords = PasswordService(settings)
    app.state.totp = TotpService()
    app.state.limiter = SlidingWindowLimiter(
        settings.login_max_attempts, settings.login_window_seconds
    )
    app.state.templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

    # -- security headers ---------------------------------------------------
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Content-Security-Policy", _CSP)
        if not request.url.path.startswith("/static"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # -- error rendering ----------------------------------------------------
    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith(("/oauth", "/verify")):
            return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)
        if exc.status_code == HTTP_NOT_FOUND:
            return render(request, "errors/404.html", status_code=HTTP_NOT_FOUND)
        return render(
            request,
            "errors/error.html",
            {"status": exc.status_code, "detail": exc.detail},
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):
        _LOG.exception("unhandled error on %s", request.url.path)
        if request.url.path.startswith(("/oauth", "/verify")):
            return JSONResponse({"error": "server_error"}, status_code=500)
        return render(request, "errors/500.html", status_code=500)

    # -- wiring ---------------------------------------------------------------
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    app.include_router(portal.router)
    app.include_router(verify.router)
    app.include_router(admin.router)
    app.include_router(oidc.router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"ok": True}

    return app


app = create_app()
