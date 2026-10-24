"""Unit tests for the web helpers (redirect safety, URL reconstruction)."""

from __future__ import annotations

import pytest

from craftpass.config import Settings
from craftpass.web import original_url, safe_redirect


@pytest.fixture()
def settings():
    return Settings(
        issuer_url="https://auth.labcraft.me",
        cookie_domain=".labcraft.me",
        default_redirect_url="https://dash.stream.labcraft.me",
        secure_cookies=True,
    )


class FakeHeaders(dict):
    def get(self, key, default=""):
        return super().get(key.lower(), default)


class FakeRequest:
    def __init__(self, headers):
        self.headers = FakeHeaders({k.lower(): v for k, v in headers.items()})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://dash.stream.labcraft.me", "https://dash.stream.labcraft.me"),
        ("https://deep.sub.labcraft.me/x/y?z=1", "https://deep.sub.labcraft.me/x/y?z=1"),
        ("https://labcraft.me", "https://labcraft.me"),
        ("https://ok.labcraft.me/#frag", "https://ok.labcraft.me/"),  # fragment dropped
        ("/account", "/account"),
        ("//evil.example.com", None),
        ("https://evil.example.com", None),
        ("https://labcraft.me.evil.com", None),
        ("http://plain.labcraft.me", None),  # http refused while secure_cookies
        ("javascript:alert(1)", None),
        ("https://user:pass@labcraft.me", None),
        ("", None),
        (None, None),
    ],
)
def test_safe_redirect_matrix(settings, value, expected):
    assert safe_redirect(value, settings) == expected


def test_safe_redirect_allows_http_when_insecure():
    settings = Settings(
        issuer_url="http://auth.local",
        cookie_domain=".local",
        default_redirect_url="http://dash.local",
        secure_cookies=False,
    )
    assert safe_redirect("http://app.local/x", settings) == "http://app.local/x"
    assert safe_redirect("https://app.local/x", settings) == "https://app.local/x"


def test_original_url_prefers_forwarded_headers():
    request = FakeRequest(
        {
            "X-Forwarded-Host": "seerr.stream.labcraft.me, something-else",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Uri": "/search?q=hi",
            "Host": "craftpass:8000",
        }
    )
    assert original_url(request) == "https://seerr.stream.labcraft.me/search?q=hi"


def test_original_url_falls_back_to_domain():
    request = FakeRequest({"Host": "craftpass:8000"})
    assert original_url(request, fallback_domain="seerr.stream.labcraft.me") == (
        "https://seerr.stream.labcraft.me/"
    )


def test_original_url_survives_missing_everything():
    request = FakeRequest({})
    assert original_url(request) == "/"
