"""Admin console: users, groups, apps, OIDC clients and the audit log.

Every mutating action is a CSRF-checked POST followed by a redirect (PRG),
and writes an audit event before committing.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import urllib.parse
from sqlite3 import Connection, IntegrityError

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from craftpass import __version__, db
from craftpass.config import Settings
from craftpass.routes.portal import _EMAIL_RE
from craftpass.security import password_problem, username_problem
from craftpass.web import (
    client_ip,
    csrf_ok,
    current_session_user,
    flash,
    get_conn,
    render,
)

router = APIRouter(prefix="/admin")

# Random material sizes
_SECRET_BYTES = 32
_PASSWORD_BYTES = 12
_GROUP_NAME_MAX = 32


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# --------------------------------------------------------------------------
# Guards & small helpers
# --------------------------------------------------------------------------
def _require_admin(request: Request, conn: Connection):
    """Return (user, None) on success, or (None, error_response)."""
    settings: Settings = request.app.state.settings
    user = current_session_user(request, conn)
    if user is None:
        return None, RedirectResponse(
            f"{settings.issuer}/login?rd={urllib.parse.quote('/admin')}", status_code=302
        )
    if not user["is_admin"]:
        return None, render(
            request,
            "errors/403.html",
            {
                "app_name": "the admin console",
                "current_user": user,
                "back_url": settings.default_redirect_url,
            },
            status_code=403,
        )
    return user, None


def _back(request: Request, path: str) -> str:
    return f"{request.app.state.settings.issuer}{path}"


def _audit(conn: Connection, request: Request, actor: str, action: str, detail: str = "") -> None:
    db.audit_log(
        conn,
        actor,
        action,
        detail,
        client_ip(request),
        cap=request.app.state.settings.audit_max_rows,
    )


def _generated_password() -> str:
    return secrets.token_urlsafe(_PASSWORD_BYTES)


def _hash_secret(value: str) -> str:
    return _sha256(value)


def _bad(csrf: str, request: Request, user) -> object:
    return render(
        request,
        "errors/error.html",
        {
            "status": 400,
            "detail": "The form has expired. Go back and try again.",
            "current_user": user,
        },
        status_code=400,
    )


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------
@router.get("")
def overview(request: Request, conn: Connection = Depends(get_conn)):
    user, err = _require_admin(request, conn)
    if err:
        return err
    counters = conn.execute(
        """
        SELECT
          (SELECT COUNT(*) FROM users) AS users,
          (SELECT COUNT(*) FROM users WHERE is_admin = 1) AS admins,
          (SELECT COUNT(*) FROM users WHERE totp_enabled = 1) AS totp_users,
          (SELECT COUNT(*) FROM groups) AS groups,
          (SELECT COUNT(*) FROM apps) AS apps,
          (SELECT COUNT(*) FROM apps WHERE auth_mode = 'oidc') AS oidc_clients
        """
    ).fetchone()
    return render(
        request,
        "admin/overview.html",
        {
            "current_user": user,
            "stats": counters,
            "recent": db.recent_audit(conn, limit=8),
            "version": __version__,
        },
    )


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------
@router.get("/users")
def users_list(request: Request, conn: Connection = Depends(get_conn)):
    user, err = _require_admin(request, conn)
    if err:
        return err
    return render(
        request,
        "admin/users.html",
        {"current_user": user, "users": db.users_with_groups(conn)},
    )


@router.get("/users/new")
def user_new(request: Request, conn: Connection = Depends(get_conn)):
    user, err = _require_admin(request, conn)
    if err:
        return err
    return render(
        request,
        "admin/user_new.html",
        {"current_user": user, "groups": db.all_groups(conn), "form": {}, "errors": []},
    )


@router.post("/users")
def user_create(
    request: Request,
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    password_mode: str = Form("custom"),
    password: str = Form(""),
    confirm: str = Form(""),
    group_ids: list[int] = Form([]),
    is_admin: bool = Form(False),
    is_active: bool = Form(True),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)

    username = username.strip().lower()
    display_name = display_name.strip()
    email = email.strip()
    errors: list[str] = []

    if problem := username_problem(username):
        errors.append(f"Username: {problem}.")
    if email and not _EMAIL_RE.fullmatch(email):
        errors.append("Email: does not look like an email address.")

    if password_mode == "generate":  # noqa: S105 - a form mode name, not a secret
        password = _generated_password()
        generated = True
    else:
        generated = False
        if problem := password_problem(password):
            errors.append(f"Password: {problem}.")
        if password != confirm:
            errors.append("Passwords do not match.")

    if errors:
        return render(
            request,
            "admin/user_new.html",
            {
                "current_user": admin,
                "groups": db.all_groups(conn),
                "form": {
                    "username": username,
                    "display_name": display_name,
                    "email": email,
                    "is_admin": is_admin,
                    "is_active": is_active,
                },
                "errors": errors,
            },
            status_code=400,
        )

    try:
        cur = conn.execute(
            """
            INSERT INTO users (username, display_name, email, password_hash,
                               is_admin, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                display_name,
                email,
                request.app.state.passwords.hash(password),
                int(is_admin),
                int(is_active),
            ),
        )
        user_id = cur.lastrowid
        db.set_user_groups(conn, user_id, group_ids)
        _audit(conn, request, admin["username"], "user.created", username)
        conn.commit()
    except IntegrityError:
        conn.rollback()
        return render(
            request,
            "admin/user_new.html",
            {
                "current_user": admin,
                "groups": db.all_groups(conn),
                "form": {"username": username},
                "errors": [f"Username {username!r} is taken."],
            },
            status_code=400,
        )

    response = RedirectResponse(_back(request, f"/admin/users/{user_id}"), status_code=303)
    if generated:
        flash(response, f"Password for {username} (shown once): {password}", "success")
    else:
        flash(response, f"User {username} created.", "success")
    return response


@router.get("/users/{user_id}")
def user_detail(request: Request, user_id: int, conn: Connection = Depends(get_conn)):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    target = db.user_by_id(conn, user_id)
    if target is None:
        return render(request, "errors/404.html", status_code=404)
    all_groups = db.all_groups(conn)
    member_ids = {
        row["group_id"]
        for row in conn.execute(
            "SELECT group_id FROM user_groups WHERE user_id = ?", (user_id,)
        ).fetchall()
    }
    target_groups = [row["name"] for row in all_groups if row["id"] in member_ids]
    return render(
        request,
        "admin/user_detail.html",
        {
            "current_user": admin,
            "target": target,
            "all_groups": all_groups,
            "member_ids": member_ids,
            "target_groups": target_groups,
            "is_self": target["id"] == admin["id"],
        },
    )


@router.post("/users/{user_id}/password")
def user_password(
    request: Request,
    user_id: int,
    password_mode: str = Form("custom"),
    password: str = Form(""),
    confirm: str = Form(""),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)
    target = db.user_by_id(conn, user_id)
    if target is None:
        return render(request, "errors/404.html", status_code=404)

    if password_mode == "generate":  # noqa: S105 - a form mode name, not a secret
        password = _generated_password()
        generated = True
    else:
        generated = False
        if problem := password_problem(password):
            response = RedirectResponse(_back(request, f"/admin/users/{user_id}"), 303)
            flash(response, f"Password: {problem}.", "error")
            return response
        if password != confirm:
            response = RedirectResponse(_back(request, f"/admin/users/{user_id}"), 303)
            flash(response, "Passwords do not match.", "error")
            return response

    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (request.app.state.passwords.hash(password), user_id),
    )
    _audit(conn, request, admin["username"], "user.password_reset", target["username"])
    conn.commit()
    response = RedirectResponse(_back(request, f"/admin/users/{user_id}"), status_code=303)
    if generated:
        flash(
            response, f"New password for {target['username']} (shown once): {password}", "success"
        )
    else:
        flash(response, f"Password reset for {target['username']}.", "success")
    return response


@router.post("/users/{user_id}/groups")
def user_groups(
    request: Request,
    user_id: int,
    group_ids: list[int] = Form([]),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)
    target = db.user_by_id(conn, user_id)
    if target is None:
        return render(request, "errors/404.html", status_code=404)

    db.set_user_groups(conn, user_id, group_ids)
    _audit(conn, request, admin["username"], "user.groups_changed", target["username"])
    conn.commit()
    response = RedirectResponse(_back(request, f"/admin/users/{user_id}"), status_code=303)
    flash(response, f"Groups updated for {target['username']}.", "success")
    return response


@router.post("/users/{user_id}/flags")
def user_flags(
    request: Request,
    user_id: int,
    is_admin_flag: bool = Form(False),
    is_active_flag: bool = Form(False),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)
    target = db.user_by_id(conn, user_id)
    if target is None:
        return render(request, "errors/404.html", status_code=404)

    is_self = target["id"] == admin["id"]
    admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]

    if is_self and not is_active_flag:
        response = RedirectResponse(_back(request, f"/admin/users/{user_id}"), 303)
        flash(response, "You cannot deactivate your own account.", "error")
        return response
    if target["is_admin"] and not is_admin_flag and admin_count <= 1:
        response = RedirectResponse(_back(request, f"/admin/users/{user_id}"), 303)
        flash(response, "Refusing to demote the only administrator.", "error")
        return response

    conn.execute(
        "UPDATE users SET is_admin = ?, is_active = ? WHERE id = ?",
        (int(is_admin_flag), int(is_active_flag), user_id),
    )
    _audit(
        conn,
        request,
        admin["username"],
        "user.flags_changed",
        f"{target['username']} admin={int(is_admin_flag)} active={int(is_active_flag)}",
    )
    conn.commit()
    response = RedirectResponse(_back(request, f"/admin/users/{user_id}"), status_code=303)
    flash(response, f"Flags updated for {target['username']}.", "success")
    return response


@router.post("/users/{user_id}/totp-reset")
def user_totp_reset(
    request: Request,
    user_id: int,
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)
    target = db.user_by_id(conn, user_id)
    if target is None:
        return render(request, "errors/404.html", status_code=404)

    conn.execute(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = 0 WHERE id = ?",
        (user_id,),
    )
    _audit(conn, request, admin["username"], "totp.admin_reset", target["username"])
    conn.commit()
    response = RedirectResponse(_back(request, f"/admin/users/{user_id}"), status_code=303)
    flash(
        response,
        f"2FA cleared for {target['username']}; they can enroll again from /account.",
        "info",
    )
    return response


@router.post("/users/{user_id}/delete")
def user_delete(
    request: Request,
    user_id: int,
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)
    target = db.user_by_id(conn, user_id)
    if target is None:
        return render(request, "errors/404.html", status_code=404)
    if target["id"] == admin["id"]:
        response = RedirectResponse(_back(request, "/admin/users"), 303)
        flash(response, "You cannot delete your own account.", "error")
        return response

    username = target["username"]
    conn.execute("DELETE FROM user_groups WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    _audit(conn, request, admin["username"], "user.deleted", username)
    conn.commit()
    response = RedirectResponse(_back(request, "/admin/users"), status_code=303)
    flash(response, f"User {username} deleted.", "info")
    return response


# --------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------
@router.get("/groups")
def groups_list(request: Request, conn: Connection = Depends(get_conn)):
    user, err = _require_admin(request, conn)
    if err:
        return err
    groups = db.groups_with_counts(conn)
    usage = {g["name"]: db.group_in_use(conn, g["name"]) for g in groups}
    return render(
        request,
        "admin/groups.html",
        {"current_user": user, "groups": groups, "usage": usage, "errors": []},
    )


@router.post("/groups")
def group_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)

    name = name.strip().lower()
    if (
        not name
        or len(name) > _GROUP_NAME_MAX
        or not name.replace("_", "").replace("-", "").isalnum()
    ):
        response = RedirectResponse(_back(request, "/admin/groups"), 303)
        flash(response, "Group names: 1-32 characters, letters/digits/dash/underscore.", "error")
        return response
    try:
        conn.execute(
            "INSERT INTO groups (name, description) VALUES (?, ?)", (name, description.strip())
        )
        _audit(conn, request, admin["username"], "group.created", name)
        conn.commit()
    except IntegrityError:
        conn.rollback()
        response = RedirectResponse(_back(request, "/admin/groups"), 303)
        flash(response, f"Group {name!r} already exists.", "error")
        return response
    response = RedirectResponse(_back(request, "/admin/groups"), status_code=303)
    flash(response, f"Group {name} created.", "success")
    return response


@router.get("/groups/{group_id}")
def group_detail(request: Request, group_id: int, conn: Connection = Depends(get_conn)):
    user, err = _require_admin(request, conn)
    if err:
        return err
    group = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if group is None:
        return render(request, "errors/404.html", status_code=404)
    return render(
        request,
        "admin/group_detail.html",
        {
            "current_user": user,
            "group": group,
            "members": db.group_members(conn, group_id),
            "used_by": db.group_in_use(conn, group["name"]),
        },
    )


@router.post("/groups/{group_id}/update")
def group_update(
    request: Request,
    group_id: int,
    description: str = Form(""),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)
    group = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if group is None:
        return render(request, "errors/404.html", status_code=404)

    conn.execute(
        "UPDATE groups SET description = ? WHERE id = ?",
        (description.strip(), group_id),
    )
    _audit(conn, request, admin["username"], "group.updated", group["name"])
    conn.commit()
    response = RedirectResponse(_back(request, f"/admin/groups/{group_id}"), status_code=303)
    flash(response, "Group updated. (Names are fixed; create a new group to rename.)", "success")
    return response


@router.post("/groups/{group_id}/delete")
def group_delete(
    request: Request,
    group_id: int,
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)
    group = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if group is None:
        return render(request, "errors/404.html", status_code=404)

    used_by = db.group_in_use(conn, group["name"])
    if used_by:
        response = RedirectResponse(_back(request, "/admin/groups"), 303)
        flash(response, f"Group {group['name']!r} is required by: {', '.join(used_by)}.", "error")
        return response

    conn.execute("DELETE FROM user_groups WHERE group_id = ?", (group_id,))
    conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    _audit(conn, request, admin["username"], "group.deleted", group["name"])
    conn.commit()
    response = RedirectResponse(_back(request, "/admin/groups"), status_code=303)
    flash(response, f"Group {group['name']} deleted.", "info")
    return response


# --------------------------------------------------------------------------
# Apps & OIDC clients
# --------------------------------------------------------------------------
@router.get("/apps")
def apps_list(request: Request, conn: Connection = Depends(get_conn)):
    user, err = _require_admin(request, conn)
    if err:
        return err
    return render(
        request,
        "admin/apps.html",
        {"current_user": user, "apps": db.all_apps(conn)},
    )


@router.get("/apps/{slug}")
def app_detail(request: Request, slug: str, conn: Connection = Depends(get_conn)):
    user, err = _require_admin(request, conn)
    if err:
        return err
    app = db.app_by_slug(conn, slug)
    if app is None:
        return render(request, "errors/404.html", status_code=404)

    redirect_uris = "\n".join(json.loads(app["oidc_redirect_uris"] or "[]"))
    return render(
        request,
        "admin/app_detail.html",
        {
            "current_user": user,
            "app": app,
            "groups": db.all_groups(conn),
            "redirect_uris_text": redirect_uris,
            "secret_set": bool(app["oidc_client_secret_hash"]),
        },
    )


@router.post("/apps/{slug}")
def app_update(
    request: Request,
    slug: str,
    display_name: str = Form(...),
    domain: str = Form(""),
    required_group: str = Form(""),
    auth_mode: str = Form("forward_auth"),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)
    app = db.app_by_slug(conn, slug)
    if app is None:
        return render(request, "errors/404.html", status_code=404)

    if auth_mode not in ("forward_auth", "oidc"):
        response = RedirectResponse(_back(request, f"/admin/apps/{slug}"), 303)
        flash(response, "auth_mode must be forward_auth or oidc.", "error")
        return response
    domain = domain.strip().lower().rstrip(".")
    if domain and not domain.replace(".", "").replace("-", "").isalnum():
        response = RedirectResponse(_back(request, f"/admin/apps/{slug}"), 303)
        flash(response, "Domain does not look like a hostname.", "error")
        return response
    group = required_group.strip() or None
    if group and db.group_by_name(conn, group) is None:
        response = RedirectResponse(_back(request, f"/admin/apps/{slug}"), 303)
        flash(response, f"No group named {group!r} exists.", "error")
        return response

    conn.execute(
        """
        UPDATE apps SET display_name = ?, domain = ?, required_group = ?, auth_mode = ?,
                        updated_at = ?
        WHERE slug = ?
        """,
        (display_name.strip(), domain, group, auth_mode, db.utc_now_iso(), slug),
    )
    _audit(conn, request, admin["username"], "app.updated", slug)
    conn.commit()
    response = RedirectResponse(_back(request, f"/admin/apps/{slug}"), status_code=303)
    flash(response, "App updated.", "success")
    return response


@router.post("/apps/{slug}/oidc")
def app_oidc(
    request: Request,
    slug: str,
    client_id: str = Form(""),
    redirect_uris: str = Form(""),
    regenerate_secret: bool = Form(False),
    csrf: str = Form(...),
    conn: Connection = Depends(get_conn),
):
    admin, err = _require_admin(request, conn)
    if err:
        return err
    if not csrf_ok(request, csrf):
        return _bad(csrf, request, admin)
    app = db.app_by_slug(conn, slug)
    if app is None:
        return render(request, "errors/404.html", status_code=404)

    client_id = client_id.strip().lower()
    uris = [line.strip() for line in redirect_uris.splitlines() if line.strip()]
    bad_uris = [
        u for u in uris if not (u.startswith("https://") and urllib.parse.urlsplit(u).netloc)
    ]
    if bad_uris:
        response = RedirectResponse(_back(request, f"/admin/apps/{slug}"), 303)
        flash(response, "Redirect URIs must be full https:// URLs.", "error")
        return response
    if client_id and db.app_by_client_id(conn, client_id) not in (None, app):
        response = RedirectResponse(_back(request, f"/admin/apps/{slug}"), 303)
        flash(response, f"Client ID {client_id!r} is already used by another app.", "error")
        return response

    new_secret = None
    if regenerate_secret or not app["oidc_client_secret_hash"]:
        new_secret = secrets.token_urlsafe(_SECRET_BYTES)

    conn.execute(
        """
        UPDATE apps SET oidc_client_id = ?, oidc_redirect_uris = ?,
                        oidc_client_secret_hash = COALESCE(?, oidc_client_secret_hash),
                        updated_at = ?
        WHERE slug = ?
        """,
        (
            client_id or None,
            json.dumps(uris),
            _hash_secret(new_secret) if new_secret else None,
            db.utc_now_iso(),
            slug,
        ),
    )
    _audit(
        conn,
        request,
        admin["username"],
        "app.oidc_updated" if not new_secret else "app.secret_regenerated",
        slug,
    )
    conn.commit()
    response = RedirectResponse(_back(request, f"/admin/apps/{slug}"), status_code=303)
    if new_secret:
        flash(
            response,
            f"New client secret for {client_id or slug} (shown once, copy now): {new_secret}",
            "success",
        )
    else:
        flash(response, "OIDC client settings saved.", "success")
    return response


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------
@router.get("/audit")
def audit_list(
    request: Request,
    q: str = "",
    conn: Connection = Depends(get_conn),
):
    user, err = _require_admin(request, conn)
    if err:
        return err
    return render(
        request,
        "admin/audit.html",
        {
            "current_user": user,
            "events": db.recent_audit(conn, limit=200, prefix=q.strip() or None),
            "q": q.strip(),
        },
    )
