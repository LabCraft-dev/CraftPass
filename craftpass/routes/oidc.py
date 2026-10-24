"""Minimal OpenID Connect provider (authorization-code flow).

Supports PKCE (S256 only) alongside HTTP Basic or form client authentication,
per the plugin requirements of Jellyfin's OIDC client. Endpoint set:

* ``/.well-known/openid-configuration`` — discovery document
* ``/oauth/authorize``                 — requires a session cookie
* ``/oauth/token``                     — back-channel; JSON errors per RFC 6749
* ``/oauth/userinfo``                  — Bearer access tokens
* ``/oauth/jwks.json``                 — RSA public key for local verification
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import time
import urllib.parse
from sqlite3 import Connection

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse

from craftpass import db
from craftpass.tokens import TokenError
from craftpass.web import client_ip, get_conn, render, session_payload

router = APIRouter()


def _secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _redirect_with_params(base: str, params: dict) -> str:
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{urllib.parse.urlencode(params)}"


# --------------------------------------------------------------------------
# Discovery & keys
# --------------------------------------------------------------------------
@router.get("/.well-known/openid-configuration")
def discovery(request: Request):
    issuer = request.app.state.settings.issuer
    return JSONResponse(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "userinfo_endpoint": f"{issuer}/oauth/userinfo",
            "jwks_uri": f"{issuer}/oauth/jwks.json",
            "scopes_supported": ["openid", "profile", "email"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": [
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "nonce",
                "name",
                "preferred_username",
                "groups",
                "email",
                "email_verified",
            ],
        },
        headers={"Cache-Control": "public, max-age=600"},
    )


@router.get("/oauth/jwks.json")
def jwks(request: Request):
    return JSONResponse(
        request.app.state.tokens.jwks(),
        headers={"Cache-Control": "public, max-age=3600"},
    )


# --------------------------------------------------------------------------
# Authorization endpoint
# --------------------------------------------------------------------------
@router.get("/oauth/authorize")
def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "openid profile",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    conn: Connection = Depends(get_conn),
):
    settings = request.app.state.settings
    ip = client_ip(request)

    app = db.app_by_client_id(conn, client_id.strip())
    if app is None or app["auth_mode"] != "oidc":
        return render(
            request,
            "errors/error.html",
            {
                "status": 400,
                "detail": f"{client_id!r} is not a registered OIDC client. "
                "Register it in /admin/apps first.",
            },
            status_code=400,
        )

    try:
        allowed_uris = json.loads(app["oidc_redirect_uris"] or "[]")
    except json.JSONDecodeError:
        allowed_uris = []
    if redirect_uri not in allowed_uris:
        # Never redirect on a bad redirect_uri — that would be an open redirect.
        return render(
            request,
            "errors/error.html",
            {
                "status": 400,
                "detail": "redirect_uri is not registered for this client. "
                "Add it to the client's redirect URIs in /admin/apps.",
            },
            status_code=400,
        )

    def error_redirect(error: str) -> RedirectResponse:
        params: dict = {"error": error}
        if state is not None:
            params["state"] = state
        return RedirectResponse(_redirect_with_params(redirect_uri, params), status_code=302)

    if response_type != "code":
        return error_redirect("unsupported_response_type")
    if code_challenge and code_challenge_method != "S256":
        return error_redirect("invalid_request")  # 'plain' is not offered

    payload = session_payload(request)
    user = None
    if payload is not None:
        candidate = db.user_by_id(conn, int(payload["sub"]))
        if candidate is not None and candidate["is_active"]:
            user = candidate
    if user is None:
        here = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        return RedirectResponse(
            f"{settings.issuer}/login?rd={urllib.parse.quote(settings.issuer + here, safe='')}",
            status_code=302,
        )

    groups = db.group_names(conn, user["id"])
    required = app["required_group"]
    if not (user["is_admin"] or required is None or required in groups):
        db.audit_log(
            conn,
            user["username"],
            "oidc.denied",
            f"client={client_id}",
            ip,
            cap=settings.audit_max_rows,
        )
        conn.commit()
        return error_redirect("access_denied")

    raw_code = secrets.token_urlsafe(32)
    db.store_code(
        conn,
        {
            "code_hash": _sha256_hex(raw_code),
            "client_id": app["oidc_client_id"],
            "user_id": user["id"],
            "redirect_uri": redirect_uri,
            "scope": scope or "openid profile",
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method if code_challenge else None,
            "nonce": nonce,
            "auth_time": int(payload.get("iat", 0)),
            "expires_at": time.time() + settings.auth_code_ttl,
        },
    )
    db.audit_log(
        conn,
        user["username"],
        "oidc.code.issued",
        f"client={client_id}",
        ip,
        cap=settings.audit_max_rows,
    )
    conn.commit()

    params: dict = {"code": raw_code, "iss": settings.issuer}
    if state is not None:
        params["state"] = state
    return RedirectResponse(_redirect_with_params(redirect_uri, params), status_code=302)


# --------------------------------------------------------------------------
# Token endpoint
# --------------------------------------------------------------------------
@router.post("/oauth/token")
async def token(request: Request, conn: Connection = Depends(get_conn)):
    settings = request.app.state.settings
    ip = client_ip(request)
    form = await request.form()

    grant_type = str(form.get("grant_type", ""))
    code = str(form.get("code", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    code_verifier = str(form.get("code_verifier", ""))

    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode()
            client_id, _, client_secret = decoded.partition(":")
        except (binascii.Error, UnicodeDecodeError):
            client_id, client_secret = "", ""
    else:
        client_id = str(form.get("client_id", ""))
        client_secret = str(form.get("client_secret", ""))

    app = db.app_by_client_id(conn, client_id.strip()) if client_id else None
    stored_hash = (app["oidc_client_secret_hash"] if app else None) or ""
    supplied_hash = _secret_hash(client_secret) if client_secret else ""
    client_ok = bool(
        app
        and app["auth_mode"] == "oidc"
        and stored_hash
        and secrets.compare_digest(stored_hash, supplied_hash)
    )
    if not client_ok:
        request.app.state.limiter.record(f"oauth-client:{ip}")
        db.audit_log(
            conn,
            (client_id or "<none>")[:32],
            "oauth.client_rejected",
            "bad credentials",
            ip,
            cap=settings.audit_max_rows,
        )
        conn.commit()
        return JSONResponse(
            {"error": "invalid_client"},
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="craftpass", charset="UTF-8"'},
        )

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if not code or not redirect_uri:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    row = db.consume_code(conn, _sha256_hex(code), time.time())
    if row is None or row["client_id"] != client_id or row["redirect_uri"] != redirect_uri:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    if row["code_challenge"] and not (
        code_verifier and secrets.compare_digest(_s256(code_verifier), row["code_challenge"])
    ):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    user = db.user_by_id(conn, row["user_id"])
    if user is None or not user["is_active"]:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    tokens = request.app.state.tokens
    groups = db.group_names(conn, user["id"])
    id_token = tokens.issue_id_token(
        user, groups, client_id, nonce=row["nonce"], auth_time=row["auth_time"]
    )
    access_token = tokens.issue_access_token(user, groups, client_id, row["scope"])

    db.purge_expired_codes(conn, time.time())
    db.audit_log(
        conn,
        user["username"],
        "oauth.token.issued",
        f"client={client_id}",
        ip,
        cap=settings.audit_max_rows,
    )
    conn.commit()

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl,
            "id_token": id_token,
            "scope": row["scope"],
        }
    )


# --------------------------------------------------------------------------
# Userinfo
# --------------------------------------------------------------------------
@router.get("/oauth/userinfo")
def userinfo(request: Request, conn: Connection = Depends(get_conn)):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return JSONResponse(
            {"error": "invalid_token"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = request.app.state.tokens.decode_any(auth[7:].strip())
    except TokenError:
        return JSONResponse(
            {"error": "invalid_token"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    scope = payload.get("scope", "")
    if "openid" not in scope and "profile" not in scope:
        return JSONResponse(
            {"error": "insufficient_scope"},
            status_code=403,
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.user_by_id(conn, int(payload["sub"]))
    if user is None or not user["is_active"]:
        return JSONResponse(
            {"error": "invalid_token"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims: dict = {
        "sub": str(user["id"]),
        "preferred_username": user["username"],
        "name": user["display_name"] or user["username"],
        "groups": db.group_names(conn, user["id"]),
        "email_verified": False,
    }
    if user["email"]:
        claims["email"] = user["email"]
    return JSONResponse(claims)
