"""CraftPass — self-hosted single sign-on for the LabCraft stack.

A single FastAPI service providing:

* a login portal served behind a Cloudflare Tunnel (``auth.labcraft.me``),
* a forward-auth verification endpoint consumed by Caddy (``/verify/<app>``),
* a minimal OpenID Connect provider for native-app clients such as Jellyfin.
"""

__version__ = "0.1.0"
