"""Caddy forward-auth contract (/verify)."""

from __future__ import annotations

import urllib.parse

from conftest import group_id, login_as, make_user


def test_verify_without_session_redirects_to_login(client):
    r = client.get("/verify/seerr", follow_redirects=False)
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.startswith("https://auth.labcraft.me/login?rd=")
    # No proxy headers present: the app's registered domain is the fallback.
    rd = urllib.parse.unquote(location.split("rd=", 1)[1])
    assert rd == "https://seerr.stream.labcraft.me/"


def test_verify_uses_forwarded_headers_for_rd(client):
    r = client.get(
        "/verify/seerr",
        headers={
            "X-Forwarded-Host": "seerr.stream.labcraft.me",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Uri": "/movie/tt123?tab=cast",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    rd = urllib.parse.unquote(r.headers["location"].split("rd=", 1)[1])
    assert rd == "https://seerr.stream.labcraft.me/movie/tt123?tab=cast"


def test_verify_query_param_form(client):
    r = client.get("/verify?app=dash", follow_redirects=False)
    assert r.status_code == 302
    assert "rd=https%3A%2F%2Fdash.stream" in r.headers["location"]


def test_verify_admin_bypasses_groups(admin_client):
    r = admin_client.get("/verify/sonarr")
    assert r.status_code == 200
    assert r.headers["X-Auth-User"] == "admin"


def test_verify_unknown_slug_404(admin_client):
    r = admin_client.get("/verify/nope")
    assert r.status_code == 404
    assert "No app is registered" in r.text


def test_verify_requires_app_slug(admin_client):
    r = admin_client.get("/verify")
    assert r.status_code == 404


def test_verify_403_for_non_member(admin_client, settings):
    pw = make_user(admin_client, "nogroup")
    admin_client.get("/logout")
    login_as(admin_client, "nogroup", pw)

    r = admin_client.get("/verify/sonarr")
    assert r.status_code == 403
    assert "Access denied" in r.text
    assert "Sonarr" in r.text

    r = admin_client.get("/verify/dash")
    assert r.status_code == 403


def test_verify_group_member_allowed(admin_client, settings):
    media = group_id(settings, "media")
    pw = make_user(admin_client, "member", group_ids=[media])
    admin_client.get("/logout")
    login_as(admin_client, "member", pw)

    r = admin_client.get("/verify/dash")
    assert r.status_code == 200
    assert r.headers["X-Auth-User"] == "member"
    assert "media" in r.headers["X-Auth-Groups"]

    # arr_admin-gated app still denies them.
    r = admin_client.get("/verify/sonarr")
    assert r.status_code == 403


def test_verify_group_change_applies_without_new_login(admin_client, settings):
    """Group edits take effect on the next /verify, cookie notwithstanding."""
    pw = make_user(admin_client, "mover", group_ids=[group_id(settings, "downloads")])
    admin_client.get("/logout")
    login_as(admin_client, "mover", pw)
    assert admin_client.get("/verify/qbit").status_code == 200
    assert admin_client.get("/verify/dash").status_code == 403

    # Admin moves them into media, out of downloads — behind their back.
    from craftpass import db

    conn = db.connect(settings)
    mover = db.user_by_username(conn, "mover")
    db.set_user_groups(conn, mover["id"], [group_id(settings, "media")])
    conn.commit()
    conn.close()

    assert admin_client.get("/verify/dash").status_code == 200
    assert admin_client.get("/verify/qbit").status_code == 403


def test_verify_stale_jwt_treated_as_signed_out(admin_client, settings):
    pw = make_user(admin_client, "stale")
    admin_client.get("/logout")
    login_as(admin_client, "stale", pw)
    assert admin_client.get("/verify/dash").status_code == 403  # no groups yet

    # Disable them behind their back; their cookie is still in the jar.
    from craftpass import db

    conn = db.connect(settings)
    conn.execute("UPDATE users SET is_active = 0 WHERE username = 'stale'")
    conn.commit()
    conn.close()

    r = admin_client.get("/verify/dash", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith("https://auth.labcraft.me/login?rd=")
