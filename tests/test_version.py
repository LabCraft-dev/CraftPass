"""Version surface: the setuptools-scm-derived version must be visible.

Note: kept out of test_web.py on purpose — that module has a local
`settings` fixture (unit tests of the web helpers) which would shadow
the conftest fixture that points `data_dir` at a temp directory.
"""

from __future__ import annotations

import re


def test_healthz_reports_version(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    # setuptools-scm shapes: 1.2.3 | 0.0.1.dev11+g1a2b3c.d20261025 | 0.0.0
    assert re.fullmatch(r"\d+(\.\d+)*(\.dev\d+)?(\+[\w.]+)?", body["version"])


def test_dunder_version_present():
    from craftpass import __version__

    assert __version__
    assert __version__ != ""
