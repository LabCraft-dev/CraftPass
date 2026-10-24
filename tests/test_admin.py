"""Admin console authorization and CRUD actions."""

from __future__ import annotations

from conftest import flash_of, group_id, make_user


def test_admin_guard_redirects_anonymous(client):
    r = client.get("/admin", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith("https://auth.labcraft.me/login?rd=")


def test_admin_guard_denies_non_admin(admin_client, settings):
    pw = make_user(admin_client, "pleb")
    admin_client.get("/logout")
    from conftest import login_as

    login_as(admin_client, "pleb", pw)
    r = admin_client.get("/admin")
    assert r.status_code == 403
    r = admin_client.get("/admin/users")
    assert r.status_code == 403
    # Mutating endpoints are guarded too.
    csrf = admin_client.cookies["craftpass_csrf"]
    r = admin_client.post(
        "/admin/groups", data={"name": "sneaky", "csrf": csrf}, follow_redirects=False
    )
    assert r.status_code == 403


def test_overview_shows_stats(admin_client):
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "Recent activity" in r.text
    assert "login.success" in r.text  # the fixture login is audited


def test_user_crud_flow(admin_client, settings):
    csrf = admin_client.cookies["craftpass_csrf"]

    # Create with a manual password.
    r = admin_client.post(
        "/admin/users",
        data={
            "username": "crud",
            "display_name": "Crud User",
            "email": "crud@labcraft.me",
            "password": "manualpassword1",
            "confirm": "manualpassword1",
            "csrf": csrf,
            "group_ids": [str(group_id(settings, "media"))],
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "User crud created" in flash_of(r)

    # Duplicate username is rejected.
    r = admin_client.post(
        "/admin/users",
        data={
            "username": "crud",
            "password": "manualpassword1",
            "confirm": "manualpassword1",
            "csrf": csrf,
        },
    )
    assert r.status_code == 400
    assert "taken" in r.text

    # Weak password is rejected with a re-render.
    r = admin_client.post(
        "/admin/users",
        data={"username": "weak", "password": "short", "confirm": "short", "csrf": csrf},
    )
    assert r.status_code == 400

    from craftpass import db

    conn = db.connect(settings)
    crud = db.user_by_username(conn, "crud")
    assert crud is not None and "media" in db.group_names(conn, crud["id"])
    conn.close()

    # Reset password via generate.
    r = admin_client.post(
        f"/admin/users/{crud['id']}/password",
        data={"password_mode": "generate", "csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "shown once" in flash_of(r)

    # Remove from groups.
    r = admin_client.post(
        f"/admin/users/{crud['id']}/groups", data={"csrf": csrf}, follow_redirects=False
    )
    assert r.status_code == 303
    conn = db.connect(settings)
    assert db.group_names(conn, crud["id"]) == []
    conn.close()

    # Delete.
    r = admin_client.post(
        f"/admin/users/{crud['id']}/delete", data={"csrf": csrf}, follow_redirects=False
    )
    assert r.status_code == 303
    conn = db.connect(settings)
    assert db.user_by_username(conn, "crud") is None
    conn.close()


def test_admin_cannot_deactivate_self(admin_client, settings):
    from craftpass import db

    conn = db.connect(settings)
    admin = db.user_by_username(conn, "admin")
    conn.close()
    csrf = admin_client.cookies["craftpass_csrf"]

    r = admin_client.post(
        f"/admin/users/{admin['id']}/flags", data={"csrf": csrf}, follow_redirects=False
    )
    assert r.status_code == 303
    assert "cannot deactivate your own account" in flash_of(r)

    conn = db.connect(settings)
    still_active = db.user_by_id(conn, admin["id"])["is_active"]
    conn.close()
    assert still_active == 1


def test_group_crud_and_usage_guard(admin_client, settings):
    csrf = admin_client.cookies["craftpass_csrf"]

    r = admin_client.post(
        "/admin/groups",
        data={"name": "testers", "description": "temporary", "csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303

    from craftpass import db

    conn = db.connect(settings)
    group = db.group_by_name(conn, "testers")
    assert group is not None
    gid = group["id"]
    conn.close()

    # Usage guard: point an app at it, then try to delete.
    r = admin_client.post(
        "/admin/apps/qbit",
        data={
            "display_name": "qBittorrent",
            "domain": "qbit.stream.labcraft.me",
            "required_group": "testers",
            "auth_mode": "forward_auth",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    r = admin_client.post(
        f"/admin/groups/{gid}/delete", data={"csrf": csrf}, follow_redirects=False
    )
    assert r.status_code == 303
    assert "required by" in flash_of(r)

    # Release the app, delete the group.
    r = admin_client.post(
        "/admin/apps/qbit",
        data={
            "display_name": "qBittorrent",
            "domain": "qbit.stream.labcraft.me",
            "required_group": "downloads",
            "auth_mode": "forward_auth",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    r = admin_client.post(
        f"/admin/groups/{gid}/delete", data={"csrf": csrf}, follow_redirects=False
    )
    assert r.status_code == 303
    conn = db.connect(settings)
    assert db.group_by_name(conn, "testers") is None
    conn.close()


def test_app_update_validation(admin_client):
    csrf = admin_client.cookies["craftpass_csrf"]

    r = admin_client.post(
        "/admin/apps/sonarr",
        data={
            "display_name": "Sonarr",
            "domain": "sonarr.stream.labcraft.me",
            "required_group": "does-not-exist",
            "auth_mode": "forward_auth",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "No group named" in flash_of(r)

    r = admin_client.post(
        "/admin/apps/sonarr",
        data={
            "display_name": "Sonarr",
            "domain": "sonarr.stream.labcraft.me",
            "required_group": "",
            "auth_mode": "weird",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "auth_mode" in flash_of(r)


def test_oidc_client_secret_shown_once(admin_client, settings):
    from conftest import secret_from_flash

    csrf = admin_client.cookies["craftpass_csrf"]
    r = admin_client.post(
        "/admin/apps/jellyfin/oidc",
        data={
            "client_id": "jellyfin",
            "redirect_uris": "https://jellyfin.stream.labcraft.me/sso/OIDC/Callback/craftpass",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    secret = secret_from_flash(r)
    assert len(secret) >= 32

    # The stored value is the SHA-256 of the secret — never the plaintext.
    import hashlib

    from craftpass import db

    conn = db.connect(settings)
    app = db.app_by_slug(conn, "jellyfin")
    conn.close()
    assert app["oidc_client_secret_hash"] == hashlib.sha256(secret.encode()).hexdigest()
    assert secret not in app["oidc_redirect_uris"]


def test_audit_page_and_filter(admin_client):
    r = admin_client.get("/admin/audit")
    assert r.status_code == 200
    assert "login.success" in r.text

    r = admin_client.get("/admin/audit", params={"q": "login."})
    assert r.status_code == 200
    assert "login.success" in r.text
    assert "setup.completed" not in r.text

    r = admin_client.get("/admin/audit", params={"q": "nothing.matches"})
    assert "No events match" in r.text


def test_admin_actions_audited(admin_client, settings):
    make_user(admin_client, "audited")
    csrf = admin_client.cookies["craftpass_csrf"]
    admin_client.post(
        "/admin/apps/dash",
        data={
            "display_name": "Prismarr",
            "domain": "dash.stream.labcraft.me",
            "required_group": "",
            "auth_mode": "forward_auth",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    r = admin_client.get("/admin/audit", params={"q": "app."})
    assert "app.updated" in r.text
    r = admin_client.get("/admin/audit", params={"q": "user."})
    assert "user.created" in r.text
