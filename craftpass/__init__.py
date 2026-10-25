"""CraftPass — self-hosted single sign-on for the LabCraft stack.

A single FastAPI service providing:

* a login portal served behind a Cloudflare Tunnel (``auth.labcraft.me``),
* a forward-auth verification endpoint consumed by Caddy (``/verify/<app>``),
* a minimal OpenID Connect provider for native-app clients such as Jellyfin.

The version is derived from git tags by setuptools-scm at build time and
read back via installed-package metadata (PEP 566 / importlib.metadata).
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("craftpass")
except PackageNotFoundError:  # running straight from a checkout
    __version__ = "0.0.0.dev0"
