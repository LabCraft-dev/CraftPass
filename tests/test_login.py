"""Login, rate limiting, TOTP lifecycle and logout."""

from __future__ import annotations

from conftest import ADMIN_PASSWORD

from craftpass import db


def _login(client, username, password, totp="", rd=""):
    csrf = client.cookies["craftpass_csrf"]
    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "totp_code": totp,
            "rd": rd,
            "csrf": csrf,
        },
        follow_redirects=False,
    )


def _create_admin_via_wizard(client):
    client.get("/setup")
    csrf = client.cookies["craftpass_csrf"]
    r = client.post(
        "/setup",
        data={
            "username": "admin",
            "display_name": "",
            "password": ADMIN_PASSWORD,
            "confirm": ADMIN_PASSWORD,
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303


def test_login_cookie_attributes(client):
    _create_admin_via_wizard(client)
    r = _login(client, "admin", ADMIN_PASSWORD)
    assert r.status_code == 303
    raw = r.headers["set-cookie"]
    assert "craftpass_sso=" in raw
    assert "Domain=.labcraft.me" in raw
    assert "HttpOnly" in raw
    assert "samesite=lax" in raw.lower()
    assert "secure" in raw.lower()


def test_login_wrong_password_generic_error(admin_client):
    admin_client.get("/logout")
    r = _login(admin_client, "admin", "totallywrong99")
    assert r.status_code == 401
    assert "Invalid username, password or 2FA code" in r.text


def test_login_unknown_user_same_error(admin_client):
    admin_client.get("/logout")
    r = _login(admin_client, "ghost", "whatever12345")
    assert r.status_code == 401
    assert "Invalid username, password or 2FA code" in r.text


def test_rate_limit_kicks_in(client):
    _create_admin_via_wizard(client)
    for _ in range(5):
        r = _login(client, "admin", "badpassword1")
        assert r.status_code == 401
    r = _login(client, "admin", ADMIN_PASSWORD)
    assert r.status_code == 429
    assert "Too many failed attempts" in r.text


def test_open_redirect_validation(client):
    _create_admin_via_wizard(client)
    r = _login(client, "admin", ADMIN_PASSWORD, rd="https://evil.example.com/loot")
    assert r.status_code == 303
    assert r.headers["location"] == "https://dash.stream.labcraft.me"

    r = _login(client, "admin", ADMIN_PASSWORD, rd="https://ok.labcraft.me/account")
    assert r.headers["location"] == "https://ok.labcraft.me/account"

    r = _login(client, "admin", ADMIN_PASSWORD, rd="https://auth.labcraft.me/account")
    assert r.headers["location"] == "https://auth.labcraft.me/account"

    # Scheme-relative, script-ish and plain-http targets are refused.
    for bad in ("//evil.example.com", "javascript:alert(1)", "http://plain.labcraft.me/x"):
        r = _login(client, "admin", ADMIN_PASSWORD, rd=bad)
        assert r.headers["location"] == "https://dash.stream.labcraft.me", bad


def test_totp_full_lifecycle(admin_client, settings, monkeypatch):
    # Pin the TOTP clock so the test cannot straddle a 30-second step boundary.
    # Step 60_000_000 == unix 1_800_000_000. The service method is patched at
    # class level — patching the global time module would also skew httpx
    # cookie-expiry checks and silently drop the session cookie.
    frozen_at = 1_800_000_000
    from craftpass.security import TotpService

    monkeypatch.setattr(TotpService, "step_at", lambda self, now=None: 60_000_000)

    # 1. Enroll via the self-service page.
    csrf = admin_client.cookies["craftpass_csrf"]
    r = admin_client.post("/account/totp/start", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303

    conn = db.connect(settings)
    row = db.user_by_username(conn, "admin")
    assert row["totp_secret"] and not row["totp_enabled"]
    secret = row["totp_secret"]
    conn.close()

    # 2. Confirm with the current step's code — now enabled.
    import pyotp

    current_code = pyotp.TOTP(secret).at(frozen_at)
    r = admin_client.post(
        "/account/totp/confirm", data={"code": current_code, "csrf": csrf}, follow_redirects=False
    )
    assert r.status_code == 303
    from conftest import flash_of

    assert "enabled" in flash_of(r).lower(), flash_of(r)
    conn = db.connect(settings)
    assert db.user_by_username(conn, "admin")["totp_enabled"] == 1
    conn.close()

    # 3. Sign out; login without a code fails.
    admin_client.get("/logout")
    r = _login(admin_client, "admin", ADMIN_PASSWORD)
    assert r.status_code == 401

    # 4. The code from the NEXT step (still inside the ±1 window) succeeds.
    #    The current step's code was consumed by the confirm — replay
    #    protection deliberately rejects it in the same window.
    next_code = pyotp.TOTP(secret).at(frozen_at + 30)
    r = _login(admin_client, "admin", ADMIN_PASSWORD, totp=next_code)
    assert r.status_code == 303

    # 5. Immediate replay of the same code is rejected.
    admin_client.get("/logout")
    r = _login(admin_client, "admin", ADMIN_PASSWORD, totp=next_code)
    assert r.status_code == 401


def _now_code(secret: str) -> str:
    import pyotp

    return pyotp.TOTP(secret).now()


def test_totp_admin_reset_allows_password_login(admin_client, settings):
    csrf = admin_client.cookies["craftpass_csrf"]
    admin_client.post("/account/totp/start", data={"csrf": csrf})
    conn = db.connect(settings)
    admin = db.user_by_username(conn, "admin")
    code = _now_code(admin["totp_secret"])
    conn.close()
    admin_client.post("/account/totp/confirm", data={"code": code, "csrf": csrf})

    # Admin resets 2FA for the account.
    r = admin_client.post(
        f"/admin/users/{admin['id']}/totp-reset", data={"csrf": csrf}, follow_redirects=False
    )
    assert r.status_code == 303

    admin_client.get("/logout")
    r = _login(admin_client, "admin", ADMIN_PASSWORD)
    assert r.status_code == 303


def test_disabled_user_cannot_login(admin_client, settings):
    csrf = admin_client.cookies["craftpass_csrf"]
    r = admin_client.post(
        "/admin/users",
        data={
            "username": "victim",
            "display_name": "",
            "email": "",
            "password_mode": "generate",
            "password": "",
            "confirm": "",
            "csrf": csrf,
            "is_active": "on",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    conn = db.connect(settings)
    victim = db.user_by_username(conn, "victim")
    conn.close()

    # Send NO is_admin_flag / is_active_flag fields (unchecked boxes are absent).
    r = admin_client.post(
        f"/admin/users/{victim['id']}/flags", data={"csrf": csrf}, follow_redirects=False
    )
    assert r.status_code == 303

    r = _login(admin_client, "victim", "whatever123456")
    assert r.status_code == 401


def test_logout_clears_cookie(admin_client):
    r = admin_client.get("/logout", follow_redirects=False)
    assert r.status_code == 303
    raw = r.headers["set-cookie"]
    assert 'craftpass_sso=""' in raw
    r = admin_client.get("/account", follow_redirects=False)
    assert r.status_code == 302
