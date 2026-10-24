"""Setup wizard behaviour."""

from __future__ import annotations

from fastapi.testclient import TestClient

from craftpass.config import Settings
from craftpass.main import create_app


def test_setup_get_renders_while_unclaimed(client):
    r = client.get("/setup")
    assert r.status_code == 200
    assert "Create the first administrator" in r.text


def test_setup_creates_admin_then_closes(client):
    client.get("/setup")
    csrf = client.cookies["craftpass_csrf"]
    r = client.post(
        "/setup",
        data={
            "username": "founder",
            "password": "supersecret99",
            "confirm": "supersecret99",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303

    # The wizard is gone for good.
    r = client.get("/setup", follow_redirects=False)
    assert r.status_code == 302
    r = client.post(
        "/setup",
        data={
            "username": "hacker",
            "password": "whatever123",
            "confirm": "whatever123",
            "csrf": client.cookies["craftpass_csrf"],
        },
        follow_redirects=False,
    )
    assert r.status_code == 303

    # And the account actually signs in.
    r = client.post(
        "/login",
        data={
            "username": "founder",
            "password": "supersecret99",
            "csrf": client.cookies["craftpass_csrf"],
        },
        follow_redirects=False,
    )
    assert r.status_code == 303


def test_setup_rejects_weak_password(client):
    client.get("/setup")
    csrf = client.cookies["craftpass_csrf"]
    r = client.post(
        "/setup",
        data={"username": "founder", "password": "short1", "confirm": "short1", "csrf": csrf},
    )
    assert r.status_code == 400
    assert "at least 10 characters" in r.text

    # Nothing was created.
    r = client.get("/setup")
    assert r.status_code == 200


def test_setup_rejects_bad_username(client):
    client.get("/setup")
    csrf = client.cookies["craftpass_csrf"]
    r = client.post(
        "/setup",
        data={
            "username": "Nope!",
            "password": "supersecret99",
            "confirm": "supersecret99",
            "csrf": csrf,
        },
    )
    assert r.status_code == 400


def test_setup_token_gate(tmp_path):
    settings = Settings(
        issuer_url="https://auth.labcraft.me",
        cookie_domain=".labcraft.me",
        data_dir=tmp_path / "data",
        setup_token="letmein42",
    )
    with TestClient(create_app(settings), base_url="https://auth.labcraft.me") as c:
        r = c.get("/setup")
        assert r.status_code == 200
        assert "Setup token" in r.text

        csrf = c.cookies["craftpass_csrf"]
        r = c.post(
            "/setup",
            data={
                "username": "founder",
                "password": "supersecret99",
                "confirm": "supersecret99",
                "token": "wrong",
                "csrf": csrf,
            },
        )
        assert r.status_code == 403

        r = c.post(
            "/setup",
            data={
                "username": "founder",
                "password": "supersecret99",
                "confirm": "supersecret99",
                "token": "letmein42",
                "csrf": csrf,
            },
            follow_redirects=False,
        )
        assert r.status_code == 303


def test_csrf_missing_rejected(client):
    r = client.post(
        "/setup",
        data={"username": "founder", "password": "supersecret99", "confirm": "supersecret99"},
    )
    assert r.status_code == 400
    assert "expired" in r.text
