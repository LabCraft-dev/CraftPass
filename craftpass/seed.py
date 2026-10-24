"""First-boot seed data.

Rows are inserted with ``INSERT OR IGNORE`` keyed by their natural key
(group name / app slug), so re-running the seed never overwrites changes
made in the admin UI and never resurrects deleted rows.
"""

SEED_GROUPS: list[tuple[str, str]] = [
    ("media", "Friends and family — streaming and requests (Jellyfin, Seerr, Prismarr)"),
    ("arr_admin", "Automation managers — the *arr stack"),
    ("downloads", "Download managers — qBittorrent and Gopeed"),
]

SEED_APPS: list[dict] = [
    {
        "slug": "jellyfin",
        "display_name": "Jellyfin",
        "domain": "jellyfin.stream.labcraft.me",
        "required_group": "media",
        "auth_mode": "oidc",
        "oidc_client_id": "jellyfin",
        "oidc_redirect_uris": '["https://jellyfin.stream.labcraft.me/sso/OIDC/Callback/craftpass"]',
    },
    {
        "slug": "seerr",
        "display_name": "Seerr",
        "domain": "seerr.stream.labcraft.me",
        "required_group": "media",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
    {
        "slug": "sonarr",
        "display_name": "Sonarr",
        "domain": "sonarr.stream.labcraft.me",
        "required_group": "arr_admin",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
    {
        "slug": "radarr",
        "display_name": "Radarr",
        "domain": "radarr.stream.labcraft.me",
        "required_group": "arr_admin",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
    {
        "slug": "prowlarr",
        "display_name": "Prowlarr",
        "domain": "prowlarr.stream.labcraft.me",
        "required_group": "arr_admin",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
    {
        "slug": "bazarr",
        "display_name": "Bazarr",
        "domain": "bazarr.stream.labcraft.me",
        "required_group": "arr_admin",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
    {
        "slug": "suggestarr",
        "display_name": "Suggestarr",
        "domain": "suggestarr.stream.labcraft.me",
        "required_group": "arr_admin",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
    {
        "slug": "wizarr",
        "display_name": "Wizarr",
        "domain": "wizarr.stream.labcraft.me",
        "required_group": "arr_admin",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
    {
        "slug": "qbit",
        "display_name": "qBittorrent",
        "domain": "qbit.stream.labcraft.me",
        "required_group": "downloads",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
    {
        "slug": "download",
        "display_name": "Gopeed",
        "domain": "download.stream.labcraft.me",
        "required_group": "downloads",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
    {
        "slug": "dash",
        "display_name": "Prismarr",
        "domain": "dash.stream.labcraft.me",
        "required_group": "media",
        "auth_mode": "forward_auth",
        "oidc_client_id": None,
        "oidc_redirect_uris": "[]",
    },
]
