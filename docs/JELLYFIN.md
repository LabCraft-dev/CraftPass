# Jellyfin (OIDC)

Jellyfin is the one app that does **not** use `forward_auth`: native TV and
mobile clients talk to the server API directly with their own tokens, and a
proxy cookie check would break them. Instead Jellyfin authenticates users
against CraftPass as an OpenID Connect client.

## Plugin choice (researched 2026-10)

The plugin from the original plan, `9p4/jellyfin-plugin-sso`, was **archived
on 2026-05-12** and is read-only. The maintained successor is:

* **`aussierk/jellyfin-plugin-oidc`** — active (2026 releases), automated
  release pipeline, test suite, RBAC role mapping, PKCE support.

| Jellyfin | Plugin version | Notes |
| --- | --- | --- |
| 12.x (current stable) | 2.1.x | hardened rewrite, .NET 10 |
| 10.11.x | 1.0.7.0 | last 10.x line |
| ≤ 10.10 | — | upgrade Jellyfin first |

Check your version in the Dashboard (server section) or the container tag.
On 12.x you may need *Manage Plugins → Catalog* to refresh after adding the
repo.

## Install

1. Dashboard → **Plugins → Repositories → Add**:

   ```
   https://raw.githubusercontent.com/aussierk/jellyfin-plugin-oidc/main/manifest.json
   ```

2. Catalog → **SSO-OIDC Authentication** → Install → restart Jellyfin.

## Configure the plugin

Dashboard → Plugins → **SSO-OIDC Authentication** → add a provider:

| Field | Value |
| --- | --- |
| Provider ID | `craftpass` |
| Display Name | `CraftPass` |
| Issuer URL | `https://auth.labcraft.me` |
| Client ID | `jellyfin` |
| Client Secret | *(the value CraftPass shows once)* |
| Scopes | `openid profile` |
| Role Claim Path | `groups` |
| Username Claim | `preferred_username` |
| Display Name Claim | `name` |
| Server Base URL | `https://jellyfin.stream.labcraft.me` |
| Auto-create users | on (default) |
| Manage user policy / library access | on (default) |

Use **Test Connection** — it fetches the discovery document and pins the
endpoints.

## Configure CraftPass (the other half)

`/admin/apps/jellyfin`:

* **Client ID**: `jellyfin`
* **Redirect URIs** (must match the plugin's pattern — note the capital C):

  ```
  https://jellyfin.stream.labcraft.me/sso/OIDC/Callback/craftpass
  ```

* **Generate a new secret on save** — the secret is displayed once, in the
  flash message. Paste it into the plugin's Client Secret field.

## Role mapping (RBAC)

In the plugin, map the `groups` claim:

| Role name | Matches group | Grants |
| --- | --- | --- |
| `jellyfin-admin` | `media` + is-admin handled below | regular playback |
| `jellyfin-admins` | *(assign to admins in CraftPass)* | Administrator |

Practical setup: create a CraftPass group (say `jellyfin_admins`), put
yourself in it, and map `jellyfin_admins` → *Administrator* checked. Map
`media` → all libraries for friends and family.

Because CraftPass always sends `email_verified: false`, leave the plugin's
*Require a verified email* **off**; matching works via `sub` / username and
does not need email trust.

## Back-channel note

Jellyfin's server POSTs to `https://auth.labcraft.me/oauth/token` through
the Cloudflare edge. If you use Bot Fight Mode or managed challenges, add a
skip rule — see [CLOUDFLARE.md](CLOUDFLARE.md).

## Login button on the web UI

The plugin adds a branded button automatically (Button color/icon in its
settings). Native apps: the plugin supports Quick Connect bridging for
clients that can't open a browser.
