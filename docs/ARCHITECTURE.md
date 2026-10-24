# Architecture

CraftPass is a single FastAPI service wearing three hats:

| Hat | Consumer | Endpoint |
| --- | --- | --- |
| Login portal | Browsers, via Cloudflare Tunnel | `/setup`, `/login`, `/logout`, `/account`, `/2FA` flows |
| Forward-auth oracle | Caddy `forward_auth` | `/verify/<slug>` |
| OpenID Connect provider | Native apps (Jellyfin) | `/.well-known/openid-configuration`, `/oauth/*` |

## Topology

```
                    Cloudflare edge
                          │
        ┌─────────────────┴──────────────────┐
        │ orange (proxied)                  │ grey (DNS only)
        │                                    │
  auth.labcraft.me                *.stream.labcraft.me
        │                                    │
  cloudflared tunnel                     VM :443 (Caddy)
        │                                    │
  craftpass:8000  ── labcraft-net ──  caddy ─┬─ jellyfin:8096   (OIDC)
   (public portal)   (docker bridge)        ├─ seerr:5055      (forward_auth)
                                           ├─ sonarr:8989      (forward_auth)
                                           └─ …                (forward_auth)
```

`auth.labcraft.me` is the only public entry into CraftPass and it arrives
through the tunnel — never through Caddy. This matters: the login page must
be reachable without a session (chicken-and-egg), and it must not share a
TLS listener with the apps it gates.

## Sessions

* One cookie, `craftpass_sso`, scoped `Domain=.labcraft.me` — `HttpOnly`,
  `Secure`, `SameSite=Lax`, 30-day lifetime.
* Content: an RS256 JWT (`iss`, `sub`, `username`, `groups`, `is_admin`).
  Signed with a 2048-bit key generated on first boot and persisted under
  `/data/keys/rs256_private.pem` (mode 600). The `kid` is the first 16 hex
  chars of the SHA-256 of the public key's DER encoding.
* The JWT is **stateless** by design, but every authorization decision
  re-reads the database: `/verify` and `/oauth/authorize` resolve the user
  row and its *current* groups on each call. Disabling a user or changing
  group membership takes effect on the next request — no waiting for the
  cookie to expire, no server-side session table.

## Authorization model

1. Admin bypass — `is_admin` passes every check.
2. Group match — app has `required_group`; the user is a member → pass.
3. Otherwise 403 with a human-readable page and a link back to the dashboard.

Apps with no `required_group` admit any signed-in user.

## Passwords & 2FA

* Argon2id, OWASP Password Storage Cheat Sheet parameters (19 MiB, t=2, p=1),
  PHC-string storage, transparent re-hash on login when parameters drift.
* Unknown usernames run a dummy verification so timing matches real ones.
* TOTP (RFC 6238) via any authenticator app: QR + manual secret on the
  account page, ±1 step window, replay protection (`totp_last_step` never
  goes backwards; a code is single-use within its step).
* Login rate limiting: sliding window, per-IP **and** per-username, 5
  failures / 5 minutes by default; `429` while blocked.

## OIDC subset

Authorization-code flow, confidential clients, PKCE S256 (optional per
request, verified when present; `plain` refused). Codes are 32-byte random
values stored as SHA-256, single-use, 60-second TTL, bound to
`client_id + redirect_uri`. Secrets are stored as SHA-256 and shown to the
admin exactly once. `id_token` carries `sub` (stable user id),
`preferred_username`, `name`, `groups`, `email` when set (`email_verified`
is always `false` — CraftPass emails are admin-entered, not verified).

## Data

One SQLite file, `/data/craftpass.db`, WAL mode. Tables: `users`, `groups`,
`user_groups`, `apps`, `oauth_codes`, `audit_logs`. Migrations are applied
by `PRAGMA user_version` at startup. Seeds (3 groups, 11 apps) are inserted
with `INSERT OR IGNORE` keyed by name/slug — admin edits and deletions are
never reverted by a restart.

## Hardening summary

* CSP `default-src 'self'; script-src 'self'; img-src 'self' data:; …` — no
  CDN, no inline scripts/styles; the compiled Tailwind sheet and the QR data
  URI are the only external-ish assets.
* CSRF double-submit tokens on every state-changing form.
* Open-redirect validation on every `rd` parameter (parent domain or its
  subdomains only, fragments stripped, userinfo rejected).
* Security headers on every response; `Cache-Control: no-store` anywhere
  auth state is involved.
* No OpenAPI/docs endpoints in production; `/healthz` is the only probe.
