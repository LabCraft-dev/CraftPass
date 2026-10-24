"""Login portal: setup wizard, login/logout, self-service account and 2FA."""

from __future__ import annotations

import re
import urllib.parse
from sqlite3 import Connection

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from craftpass import db
from craftpass.config import Settings
from craftpass.security import password_problem, username_problem
from craftpass.web import (
    clear_session_cookie,
    client_ip,
    csrf_ok,
    current_session_user,
    flash,
    get_conn,
    render,
    safe_redirect,
    set_session_cookie,
    totp_qr_svg,
)

router = APIRouter()

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

LOGIN_ERROR = "Invalid username, password or 2FA code."


def _portal_url(request: Request, path: str) -> str:
    return f"{request.app.state.settings.issuer}{path}"


def _login_url(request: Request, rd: str | None) -> str:
    settings: Settings = request.app.state.settings
    quoted = urllib.parse.quote(rd, safe="") if rd else ""
    suffix = f"?rd={quoted}" if quoted else ""
    return f"{settings.issuer}/login{suffix}"


def _after_login(request: Request, rd: str | None) -> str:
    settings: Settings = request.app.state.settings
    return safe_redirect(rd, settings) or settings.default_redirect_url


# --------------------------------------------------------------------------
# Root
# --------------------------------------------------------------------------
@router.get("/")
def root(request: Request, conn: Connection = Depends(get_conn)):
    user = current_session_user(request, conn)
    if user is None:
        return RedirectResponse(_login_url(request, None), status_code=302)
    if user["is_admin"]:
        return RedirectResponse(_portal_url(request, "/admin"), status_code=302)
    return RedirectResponse(request.app.state.settings.default_redirect_url, status_code=302)


# --------------------------------------------------------------------------
# First-boot setup wizard
# --------------------------------------------------------------------------
def _setup_open(conn: Connection) -> bool:
    return not db.admin_exists(conn)


@router.get("/setup")
def setup_form(
    request: Request,
    token: str | None = None,
    conn: Connection = Depends(get_conn),
):
    settings: Settings = request.app.state.settings
    if not _setup_open(conn):
        response = RedirectResponse(_login_url(request, None), status_code=302)
        flash(response, "CraftPass is already initialized.", "info")
        return response
    if settings.setup_token and token != settings.setup_token:
        return render(
            request,
            "setup.html",
            {"needs_token": True, "provided_token": token, "form": {}},
            status_code=403 if token else 200,
        )
    return render(request, "setup.html", {"needs_token": bool(settings.setup_token), "form": {}})


@router.post("/setup")
def setup_submit(
    request: Request,
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    password: str = Form(...),
    confirm: str = Form(...),
    token: str = Form(""),
    csrf: str = Form(""),
    conn: Connection = Depends(get_conn),
):
    settings: Settings = request.app.state.settings
    limiter = request.app.state.limiter
    ip = client_ip(request)

    if not csrf_ok(request, csrf):
        return render(
            request,
            "setup.html",
            {
                "needs_token": bool(settings.setup_token),
                "form": {},
                "error": "The form has expired. Please try again.",
            },
            status_code=400,
        )

    if not _setup_open(conn):
        return RedirectResponse(_login_url(request, None), status_code=303)
    if settings.setup_token and token != settings.setup_token:
        return render(
            request,
            "setup.html",
            {"needs_token": True, "form": {}, "error": "Invalid setup token."},
            status_code=403,
        )
    if limiter.blocked(f"setup:{ip}"):
        return render(
            request,
            "setup.html",
            {
                "needs_token": bool(settings.setup_token),
                "form": {},
                "error": "Too many attempts. Try again later.",
            },
            status_code=429,
        )

    username = username.strip().lower()
    display_name = display_name.strip()
    email = email.strip()
    errors: list[str] = []

    if problem := username_problem(username):
        errors.append(f"Username: {problem}.")
    if problem := password_problem(password):
        errors.append(f"Password: {problem}.")
    if password != confirm:
        errors.append("Passwords do not match.")
    if email and not _EMAIL_RE.fullmatch(email):
        errors.append("Email: does not look like an email address.")

    if errors:
        limiter.record(f"setup:{ip}")
        return render(
            request,
            "setup.html",
            {
                "needs_token": bool(settings.setup_token),
                "error": " ".join(errors),
                "form": {"username": username, "display_name": display_name, "email": email},
            },
            status_code=400,
        )

    passwords = request.app.state.passwords
    conn.execute(
        """
        INSERT INTO users (username, display_name, email, password_hash, is_admin, is_active)
        VALUES (?, ?, ?, ?, 1, 1)
        """,
        (username, display_name, email, passwords.hash(password)),
    )
    db.audit_log(
        conn,
        username,
        "setup.completed",
        f"administrator {username} created",
        ip,
        cap=settings.audit_max_rows,
    )
    conn.commit()

    response = RedirectResponse(_login_url(request, None), status_code=303)
    flash(response, "Administrator created. Sign in to continue.", "success")
    return response


# --------------------------------------------------------------------------
# Login / logout
# --------------------------------------------------------------------------
@router.get("/login")
def login_form(
    request: Request,
    rd: str | None = None,
    conn: Connection = Depends(get_conn),
):
    user = current_session_user(request, conn)
    if user is not None:
        return RedirectResponse(_after_login(request, rd), status_code=302)
    return render(
        request,
        "login.html",
        {
            "rd": rd or "",
            "needs_setup": not db.admin_exists(conn),
            "setup_url": _portal_url(request, "/setup"),
        },
    )


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(""),
    rd: str = Form(""),
    csrf: str = Form(""),
    conn: Connection = Depends(get_conn),
):
    settings: Settings = request.app.state.settings
    passwords = request.app.state.passwords
    totp = request.app.state.totp
    limiter = request.app.state.limiter
    ip = client_ip(request)
    actor = (username or "")[:32].strip() or "<anonymous>"

    context = {"rd": rd or "", "needs_setup": False}

    def fail(status: int, message: str, detail: str = "") -> object:
        limiter.record(f"ip:{ip}")
        limiter.record(f"user:{username.lower()[:32]}")
        db.audit_log(
            conn, actor, "login.failed", detail or message, ip, cap=settings.audit_max_rows
        )
        conn.commit()
        return render(request, "login.html", {**context, "error": message}, status_code=status)

    if not csrf_ok(request, csrf):
        return fail(400, "The form has expired. Please try again.", "csrf rejected")

    if limiter.blocked(f"ip:{ip}") or limiter.blocked(f"user:{username.lower()[:32]}"):
        db.audit_log(conn, actor, "login.blocked", "rate limit", ip, cap=settings.audit_max_rows)
        conn.commit()
        return render(
            request,
            "login.html",
            {**context, "error": "Too many failed attempts. Try again in a few minutes."},
            status_code=429,
        )

    user = db.user_by_username(conn, username.strip())
    if user is None:
        passwords.equalize_timing(password)
        return fail(401, LOGIN_ERROR, "unknown user")

    if not user["is_active"]:
        passwords.equalize_timing(password)
        return fail(401, LOGIN_ERROR, "disabled user")

    if not passwords.verify(user["password_hash"], password):
        return fail(401, LOGIN_ERROR, "bad password")

    if user["totp_enabled"] and user["totp_secret"]:
        step = totp.verify(user["totp_secret"], totp_code, user["totp_last_step"])
        if step is None:
            return fail(401, LOGIN_ERROR, "bad or missing totp code")
        conn.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))

    if passwords.needs_rehash(user["password_hash"]):
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (passwords.hash(password), user["id"]),
        )

    db.touch_last_login(conn, user["id"])
    db.audit_log(conn, user["username"], "login.success", "", ip, cap=settings.audit_max_rows)
    conn.commit()

    token = request.app.state.tokens.issue_session(user, db.group_names(conn, user["id"]))
    response = RedirectResponse(_after_login(request, rd), status_code=303)
    set_session_cookie(response, token, settings)
    return response


@router.api_route("/logout", methods=["GET", "POST"])
def logout(request: Request, conn: Connection = Depends(get_conn)):
    settings: Settings = request.app.state.settings
    user = current_session_user(request, conn)
    if user is not None:
        db.audit_log(
            conn, user["username"], "logout", "", client_ip(request), cap=settings.audit_max_rows
        )
        conn.commit()
    response = RedirectResponse(_login_url(request, None), status_code=303)
    clear_session_cookie(response, settings)
    flash(response, "Signed out.", "info")
    return response


# --------------------------------------------------------------------------
# Self-service account
# --------------------------------------------------------------------------
@router.get("/account")
def account(request: Request, conn: Connection = Depends(get_conn)):
    user = current_session_user(request, conn)
    if user is None:
        return RedirectResponse(_login_url(request, "/account"), status_code=302)
    pending_totp = bool(user["totp_secret"]) and not user["totp_enabled"]
    return render(
        request,
        "account.html",
        {
            "current_user": user,
            "pending_totp": pending_totp,
            "qr_svg": totp_qr_svg(
                request.app.state.totp.provisioning_uri(
                    user["totp_secret"], user["email"] or user["username"]
                )
            )
            if pending_totp
            else "",
            "secret_spaced": " ".join(
                user["totp_secret"][i : i + 4] for i in range(0, len(user["totp_secret"] or ""), 4)
            )
            if pending_totp
            else "",
        },
    )


@router.post("/account/profile")
def account_profile(
    request: Request,
    display_name: str = Form(""),
    email: str = Form(""),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    settings: Settings = request.app.state.settings
    user = current_session_user(request, conn)
    if user is None:
        return RedirectResponse(_login_url(request, "/account"), status_code=302)
    if not csrf_ok(request, csrf):
        return render(
            request,
            "account.html",
            {"current_user": user, "error": "Form expired."},
            status_code=400,
        )

    email = email.strip()
    display_name = display_name.strip()
    if email and not _EMAIL_RE.fullmatch(email):
        response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
        flash(response, "That email address does not look valid.", "error")
        return response

    conn.execute(
        "UPDATE users SET display_name = ?, email = ?, updated_at = ? WHERE id = ?",
        (display_name, email, db.utc_now_iso(), user["id"]),
    )
    db.audit_log(
        conn,
        user["username"],
        "account.profile_updated",
        "",
        client_ip(request),
        cap=settings.audit_max_rows,
    )
    conn.commit()
    response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
    flash(response, "Profile updated.", "success")
    return response


@router.post("/account/password")
def account_password(
    request: Request,
    current: str = Form(...),
    new: str = Form(...),
    confirm: str = Form(""),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    settings: Settings = request.app.state.settings
    passwords = request.app.state.passwords
    user = current_session_user(request, conn)
    if user is None:
        return RedirectResponse(_login_url(request, "/account"), status_code=302)
    if not csrf_ok(request, csrf):
        return render(
            request,
            "account.html",
            {"current_user": user, "error": "Form expired."},
            status_code=400,
        )

    problems: list[str] = []
    if not passwords.verify(user["password_hash"], current):
        problems.append("Current password is incorrect.")
    if problem := password_problem(new):
        problems.append(f"New password: {problem}.")
    if new != confirm:
        problems.append("New passwords do not match.")
    if problems:
        response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
        flash(response, " ".join(problems), "error")
        return response

    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (passwords.hash(new), user["id"]),
    )
    db.audit_log(
        conn,
        user["username"],
        "account.password_changed",
        "",
        client_ip(request),
        cap=settings.audit_max_rows,
    )
    conn.commit()
    response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
    flash(response, "Password changed.", "success")
    return response


@router.post("/account/totp/start")
def totp_start(
    request: Request,
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    user = current_session_user(request, conn)
    if user is None:
        return RedirectResponse(_login_url(request, "/account"), status_code=302)
    if not csrf_ok(request, csrf):
        return render(
            request,
            "account.html",
            {"current_user": user, "error": "Form expired."},
            status_code=400,
        )
    if user["totp_enabled"]:
        response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
        flash(response, "2FA is already enabled.", "error")
        return response

    secret = request.app.state.totp.new_secret()
    conn.execute(
        "UPDATE users SET totp_secret = ?, totp_enabled = 0, totp_last_step = 0 WHERE id = ?",
        (secret, user["id"]),
    )
    db.audit_log(
        conn,
        user["username"],
        "totp.enrollment_started",
        "",
        client_ip(request),
        cap=request.app.state.settings.audit_max_rows,
    )
    conn.commit()
    response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
    flash(response, "Scan the QR code, then confirm with a code from your app.", "info")
    return response


@router.post("/account/totp/confirm")
def totp_confirm(
    request: Request,
    code: str = Form(...),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    user = current_session_user(request, conn)
    if user is None:
        return RedirectResponse(_login_url(request, "/account"), status_code=302)
    if not csrf_ok(request, csrf):
        return render(
            request,
            "account.html",
            {"current_user": user, "error": "Form expired."},
            status_code=400,
        )
    if user["totp_enabled"] or not user["totp_secret"]:
        response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
        flash(response, "Start 2FA enrollment first.", "error")
        return response

    step = request.app.state.totp.verify(user["totp_secret"], code, user["totp_last_step"])
    if step is None:
        response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
        flash(
            response,
            "That code was not accepted. Check the clock on your phone and try again.",
            "error",
        )
        return response

    conn.execute(
        "UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?",
        (step, user["id"]),
    )
    db.audit_log(
        conn,
        user["username"],
        "totp.enabled",
        "",
        client_ip(request),
        cap=request.app.state.settings.audit_max_rows,
    )
    conn.commit()
    response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
    flash(response, "Two-factor authentication enabled.", "success")
    return response


@router.post("/account/totp/disable")
def totp_disable(
    request: Request,
    password: str = Form(...),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    user = current_session_user(request, conn)
    if user is None:
        return RedirectResponse(_login_url(request, "/account"), status_code=302)
    if not csrf_ok(request, csrf):
        return render(
            request,
            "account.html",
            {"current_user": user, "error": "Form expired."},
            status_code=400,
        )
    if not request.app.state.passwords.verify(user["password_hash"], password):
        response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
        flash(response, "Password incorrect.", "error")
        return response

    conn.execute(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = 0 WHERE id = ?",
        (user["id"],),
    )
    db.audit_log(
        conn,
        user["username"],
        "totp.disabled",
        "",
        client_ip(request),
        cap=request.app.state.settings.audit_max_rows,
    )
    conn.commit()
    response = RedirectResponse(_portal_url(request, "/account"), status_code=303)
    flash(response, "Two-factor authentication disabled.", "info")
    return response
