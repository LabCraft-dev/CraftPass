"""Shared fixtures: isolated settings/app/client per test."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from craftpass import db
from craftpass.config import Settings
from craftpass.main import create_app

BASE = "https://auth.labcraft.me"
ADMIN_PASSWORD = "correct horse batt9"


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        issuer_url=BASE,
        cookie_domain=".labcraft.me",
        default_redirect_url="https://dash.stream.labcraft.me",
        data_dir=tmp_path / "data",
        secure_cookies=True,
        session_ttl_days=1,
        setup_token="",
    )


@pytest.fixture()
def app(settings):
    return create_app(settings)


@pytest.fixture()
def client(app):
    with TestClient(app, base_url=BASE) as c:
        yield c


@pytest.fixture()
def admin_client(client):
    """A client that completed the setup wizard and is signed in as `admin`."""
    r = client.get("/setup")
    assert r.status_code == 200
    csrf = client.cookies["craftpass_csrf"]

    r = client.post(
        "/setup",
        data={
            "username": "admin",
            "display_name": "The Admin",
            "password": ADMIN_PASSWORD,
            "confirm": ADMIN_PASSWORD,
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    r = client.get("/login")
    csrf = client.cookies["craftpass_csrf"]
    r = client.post(
        "/login",
        data={"username": "admin", "password": ADMIN_PASSWORD, "csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert "craftpass_sso" in client.cookies
    return client


def flash_of(response) -> str:
    """Decode the one-hop flash cookie set on a redirect response."""
    raw = response.cookies.get("craftpass_flash", "")
    import urllib.parse

    return urllib.parse.unquote(raw)


SECRET_IN_FLASH = re.compile(r"shown once[^:]*:\s*([A-Za-z0-9_-]{20,})")


def secret_from_flash(response) -> str:
    m = SECRET_IN_FLASH.search(flash_of(response))
    assert m, f"no secret found in flash: {flash_of(response)!r}"
    return m.group(1)


GEN_PASSWORD = re.compile(r"\(shown once\):\s*([A-Za-z0-9_-]{16,})")


def created_password(redirect_response) -> str:
    """Extract the one-time generated password from a user-create redirect."""
    m = GEN_PASSWORD.search(flash_of(redirect_response))
    assert m, f"no generated password in flash: {flash_of(redirect_response)!r}"
    return m.group(1)


def make_user(admin_client, username, group_ids=()) -> str:
    """Create a user via the admin console; returns the generated password."""
    csrf = admin_client.cookies["craftpass_csrf"]
    data = {
        "username": username,
        "display_name": "",
        "email": "",
        "password_mode": "generate",
        "password": "",
        "confirm": "",
        "csrf": csrf,
    }
    if group_ids:
        data["group_ids"] = [str(g) for g in group_ids]
    r = admin_client.post("/admin/users", data=data, follow_redirects=False)
    assert r.status_code == 303, r.text
    return created_password(r)


def login_as(client, username, password, totp=""):
    """Full login round-trip; asserts success and returns the response."""
    client.get("/login")
    r = client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "totp_code": totp,
            "csrf": client.cookies["craftpass_csrf"],
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    return r


def group_id(settings, name) -> int:

    conn = db.connect(settings)
    row = conn.execute("SELECT id FROM groups WHERE name = ?", (name,)).fetchone()
    conn.close()
    assert row, f"group {name!r} not seeded"
    return row["id"]
