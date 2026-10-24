"""OIDC provider: discovery, authorize, token (PKCE + secret), userinfo, jwks."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.parse

from conftest import login_as, make_user, secret_from_flash

REDIRECT = "https://jellyfin.stream.labcraft.me/sso/OIDC/Callback/craftpass"


def _configure_jellyfin_client(admin_client) -> str:
    """Register the seeded jellyfin app as an OIDC client; returns the secret."""
    csrf = admin_client.cookies["craftpass_csrf"]
    r = admin_client.post(
        "/admin/apps/jellyfin/oidc",
        data={
            "client_id": "jellyfin",
            "redirect_uris": REDIRECT,
            "regenerate_secret": "true",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    return secret_from_flash(r)


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def _authorize(client, **overrides):
    params = {
        "client_id": "jellyfin",
        "redirect_uri": REDIRECT,
        "response_type": "code",
        "scope": "openid profile",
        "state": "st4te",
        "nonce": "n0nce",
    }
    params.update(overrides)
    return client.get("/oauth/authorize", params=params, follow_redirects=False)


def _code_from(location: str) -> str:
    assert location.startswith(REDIRECT), location
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    return query["code"][0]


# --------------------------------------------------------------------------
# Discovery & keys
# --------------------------------------------------------------------------
def test_discovery_document(client):
    r = client.get("/.well-known/openid-configuration")
    assert r.status_code == 200
    doc = r.json()
    assert doc["issuer"] == "https://auth.labcraft.me"
    assert doc["authorization_endpoint"].endswith("/oauth/authorize")
    assert doc["token_endpoint"].endswith("/oauth/token")
    assert doc["userinfo_endpoint"].endswith("/oauth/userinfo")
    assert doc["jwks_uri"].endswith("/oauth/jwks.json")
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["id_token_signing_alg_values_supported"] == ["RS256"]
    assert "client_secret_basic" in doc["token_endpoint_auth_methods_supported"]


def test_jwks_shape_and_kid_matches_id_token_header(client, admin_client):
    secret = _configure_jellyfin_client(admin_client)
    verifier, challenge = _pkce()
    r = _authorize(admin_client, code_challenge=challenge, code_challenge_method="S256")
    assert r.status_code == 302
    code = _code_from(r.headers["location"])

    r = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
        },
        auth=("jellyfin", secret),
    )
    assert r.status_code == 200
    id_token = r.json()["id_token"]

    jwks = client.get("/oauth/jwks.json").json()
    key = jwks["keys"][0]
    assert key["kty"] == "RSA" and key["alg"] == "RS256" and key["n"] and key["e"]

    # The id_token header kid matches the published key.
    header = id_token.split(".")[0]
    header += "=" * (-len(header) % 4)
    kid = json.loads(base64.urlsafe_b64decode(header))["kid"]
    assert kid == key["kid"]


# --------------------------------------------------------------------------
# Authorization
# --------------------------------------------------------------------------
def test_authorize_without_session_redirects_to_login(admin_client):
    admin_client.get("/logout")
    r = _authorize(admin_client)
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.startswith("https://auth.labcraft.me/login?rd=")
    rd = urllib.parse.unquote(location.split("rd=", 1)[1])
    assert rd.startswith("https://auth.labcraft.me/oauth/authorize?")
    assert "client_id=jellyfin" in rd


def test_authorize_rejects_unregistered_redirect_uri(admin_client):
    r = _authorize(admin_client, redirect_uri="https://attacker.example.com/cb")
    assert r.status_code == 400
    assert "not registered" in r.text


def test_authorize_rejects_plain_pkce(admin_client):
    r = _authorize(admin_client, code_challenge="abc", code_challenge_method="plain")
    assert r.status_code == 302
    assert "error=invalid_request" in r.headers["location"]


def test_authorize_denies_user_outside_group(admin_client, settings):
    _configure_jellyfin_client(admin_client)
    pw = make_user(admin_client, "outsider")  # no media group
    admin_client.get("/logout")
    login_as(admin_client, "outsider", pw)
    r = _authorize(admin_client)
    assert r.status_code == 302
    assert "error=access_denied" in r.headers["location"]


# --------------------------------------------------------------------------
# Token endpoint
# --------------------------------------------------------------------------
def test_token_happy_path_with_pkce(admin_client):
    secret = _configure_jellyfin_client(admin_client)
    verifier, challenge = _pkce()
    r = _authorize(
        admin_client, code_challenge=challenge, code_challenge_method="S256", nonce="n0nce"
    )
    assert r.status_code == 302
    location = r.headers["location"]
    assert "state=st4te" in location
    code = _code_from(location)

    r = admin_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
        },
        auth=("jellyfin", secret),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "openid profile"

    # Decode and verify the id_token with the service's own public key.
    tokens = admin_client.app.state.tokens
    # (audience is the client, so decode as access for shape; id_token via jwt)
    id_token = body["id_token"]
    claims = _decode_standalone(tokens, id_token)
    assert claims["iss"] == "https://auth.labcraft.me"
    assert claims["aud"] == "jellyfin"
    assert claims["preferred_username"] == "admin"
    assert claims["nonce"] == "n0nce"
    assert claims["auth_time"] > 0
    assert isinstance(claims["groups"], list)


def _decode_standalone(tokens, jwt_str):
    import jwt as pyjwt

    return pyjwt.decode(
        jwt_str,
        tokens._key.public_key(),
        algorithms=["RS256"],
        audience="jellyfin",
        issuer="https://auth.labcraft.me",
    )


def test_token_wrong_secret_401(admin_client):
    _configure_jellyfin_client(admin_client)
    verifier, challenge = _pkce()
    r = _authorize(admin_client, code_challenge=challenge, code_challenge_method="S256")
    code = _code_from(r.headers["location"])

    r = admin_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
        },
        auth=("jellyfin", "wrong-secret"),
    )
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_client"
    assert r.headers["www-authenticate"].startswith("Basic")


def test_token_form_auth_variant(admin_client):
    secret = _configure_jellyfin_client(admin_client)
    verifier, challenge = _pkce()
    r = _authorize(admin_client, code_challenge=challenge, code_challenge_method="S256")
    code = _code_from(r.headers["location"])

    r = admin_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
            "client_id": "jellyfin",
            "client_secret": secret,
        },
    )
    assert r.status_code == 200


def test_token_code_single_use(admin_client):
    secret = _configure_jellyfin_client(admin_client)
    verifier, challenge = _pkce()
    r = _authorize(admin_client, code_challenge=challenge, code_challenge_method="S256")
    code = _code_from(r.headers["location"])

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": verifier,
    }
    r = admin_client.post("/oauth/token", data=payload, auth=("jellyfin", secret))
    assert r.status_code == 200
    r = admin_client.post("/oauth/token", data=payload, auth=("jellyfin", secret))
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_redirect_uri_mismatch(admin_client):
    secret = _configure_jellyfin_client(admin_client)
    verifier, challenge = _pkce()
    r = _authorize(admin_client, code_challenge=challenge, code_challenge_method="S256")
    code = _code_from(r.headers["location"])

    r = admin_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://jellyfin.stream.labcraft.me/other",
            "code_verifier": verifier,
        },
        auth=("jellyfin", secret),
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_pkce_verifier_required_and_checked(admin_client):
    secret = _configure_jellyfin_client(admin_client)
    _, challenge = _pkce()
    r = _authorize(admin_client, code_challenge=challenge, code_challenge_method="S256")
    code = _code_from(r.headers["location"])

    # Missing verifier.
    r = admin_client.post(
        "/oauth/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT},
        auth=("jellyfin", secret),
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"

    # (code is consumed by the attempt above; run a fresh one for the wrong-verifier case)
    r = _authorize(admin_client, code_challenge=challenge, code_challenge_method="S256")
    code = _code_from(r.headers["location"])
    r = admin_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": "wrong-verifier-wrong-length",
        },
        auth=("jellyfin", secret),
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_unsupported_grant(admin_client):
    secret = _configure_jellyfin_client(admin_client)
    r = admin_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": "jellyfin", "client_secret": secret},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "unsupported_grant_type"


# --------------------------------------------------------------------------
# Userinfo
# --------------------------------------------------------------------------
def test_userinfo_with_access_token(admin_client):
    secret = _configure_jellyfin_client(admin_client)
    verifier, challenge = _pkce()
    r = _authorize(admin_client, code_challenge=challenge, code_challenge_method="S256")
    code = _code_from(r.headers["location"])
    r = admin_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
        },
        auth=("jellyfin", secret),
    )
    access_token = r.json()["access_token"]

    r = admin_client.get("/oauth/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert r.status_code == 200
    claims = r.json()
    assert claims["preferred_username"] == "admin"
    assert claims["sub"]
    assert isinstance(claims["groups"], list)

    # A garbage token is a 401, not a 500.
    r = admin_client.get("/oauth/userinfo", headers={"Authorization": "Bearer not.a.token"})
    assert r.status_code == 401
    r = admin_client.get("/oauth/userinfo")
    assert r.status_code == 401
