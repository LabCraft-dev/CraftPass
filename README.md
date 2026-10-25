# CraftPass

Self-hosted single sign-on for the LabCraft stack: one login for every
`*.labcraft.me` app, served by a single ~40 MB ARM64 container.

```
Browser ──▶ auth.labcraft.me (Cloudflare Tunnel)  ─▶ CraftPass login portal
Browser ──▶ sonarr.stream.labcraft.me (Caddy :443) ─▶ forward_auth ─▶ CraftPass /verify
Jellyfin ──▶ OIDC authorization-code + PKCE        ─▶ CraftPass /oauth/*
```

| Layer | Choice |
| --- | --- |
| Service | FastAPI + uvicorn, Python 3.13, ~40 MB image |
| Database | SQLite (WAL), one file under `/data` |
| Passwords | Argon2id — OWASP parameters (19 MiB, t=2, p=1) |
| Sessions | RS256 JWT cookie, `Domain=.labcraft.me`, 30 days |
| 2FA | RFC 6238 TOTP with QR enrollment + replay protection |
| Proxy auth | Caddy `forward_auth` → `/verify/<slug>` |
| Native apps | OpenID Connect provider (PKCE S256 + client secret) |
| UI | Server-rendered Jinja2 + compiled Tailwind, zero CDN/script deps |

## Features

* **One cookie, every subdomain** — sign in once at `auth.labcraft.me`; the
  cookie is honored on all `*.stream.labcraft.me` hosts (grey-cloud DNS) and
  future `*.labcraft.me` apps (orange).
* **Group-based access** — `media`, `arr_admin`, `downloads` out of the box;
  admins bypass everything. Group changes apply on the next request, no
  waiting for sessions to expire.
* **No double login** — apps sit behind the guard with their own auth off
  (`External` mode, subnet whitelists; per-app recipes in the docs).
* **Native-app SSO** — Jellyfin (TV/mobile clients) authenticates via OIDC
  instead of a proxy cookie.
* **One-time setup wizard** — first visit to `/setup` creates the admin,
  then the page closes forever. No default credentials ever exist.
* **Audit log** — every login, change and token issuance, filterable.
* **Hardened by default** — CSRF tokens, per-IP+per-user rate limiting,
  strict CSP (no inline scripts, no CDNs), open-redirect validation,
  Argon2 timing equalization, single-use OAuth codes.

## Quick start

```bash
cp .env.example .env         # set CF_TUNNEL_TOKEN
docker compose up -d --build
```

Open `https://auth.labcraft.me/setup`, create the administrator, sign in.
Full walk-through (DNS, tunnel, Caddyfile, per-app tuning):
**[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

## Documentation

| Document | Contents |
| --- | --- |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | topology, session model, OIDC subset, hardening |
| [DEPLOYMENT](docs/DEPLOYMENT.md) | DNS, tunnel, compose, first boot, per-app login tuning |
| [JELLYFIN](docs/JELLYFIN.md) | plugin choice + version matrix, provider config, role mapping |
| [CADDY](docs/CADDY.md) | guard snippets, redirect flow, API-key bypass, adding apps |
| [CLOUDFLARE](docs/CLOUDFLARE.md) | tunnel, WAF skip rule for the OIDC back-channel |
| [TROUBLESHOOTING](docs/TROUBLESHOOTING.md) | double logins, loops, lockouts, logs |

## Development

```bash
make install      # venv + editable install with dev tools
make test         # 66 tests: setup, login/TOTP, verify, OIDC, admin
make lint         # ruff check + format gate
make css          # recompile static/app.css (Tailwind CLI)
make dev          # uvicorn --reload on 127.0.0.1:8000
```

Local http testing needs `SECURE_COOKIES=false` (see `.env.example`) — the
cookie flags are the only difference from production behavior.

## Releases

CI builds multi-arch images (`linux/amd64` + `linux/arm64`) and publishes
them to Docker Hub once the `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` repo
secrets are set (Settings → Secrets and variables → Actions):

* every push to `main` → `<namespace>/craftpass:edge`
* pushing a tag → semver tags + `latest` (`v1.2.3` → `1.2.3`, `1.2`, `1`;
  while `0.x` the major-only tag is skipped)

```bash
git tag v0.1.0
git push origin v0.1.0
```

Until the secrets are configured the publish job skips itself; validation
jobs (lint, tests, Caddyfile, image builds) always run.

## Project layout

```
craftpass/
├── config.py        # pydantic-settings, env-driven
├── db.py            # sqlite: schema, migrations, queries, audit
├── security.py      # argon2, TOTP, credential policy
├── tokens.py        # RS256 keys, session/id/access JWTs, JWKS
├── ratelimit.py     # sliding-window limiter
├── web.py           # sessions, CSRF, flashes, redirects, rendering
├── main.py          # app factory, middleware, error pages
├── routes/          # portal · verify · admin · oidc
├── templates/       # Jinja2 (portal + admin console)
└── static/          # compiled Tailwind + admin.js
tests/               # pytest suite (66 tests)
deploy/Caddyfile     # drop-in for the existing stack
docs/                # the six guides above
```

## Security notes

* Secrets (`oidc_client_secret`) are stored as SHA-256 and shown exactly
  once, in the redirect flash.
* Emails are admin-entered and **not** verified — `email_verified` is always
  `false` in tokens. Don't enable email-based account linking upstream.
* `/data` holds the database and the RSA signing keys. Back it up; losing
  the keys logs everyone out (that is the intended behavior).
* The setup wizard is the only unauthenticated write surface. If the tunnel
  is live before first setup, set `SETUP_TOKEN` to require it.

## License

MIT — see [LICENSE](LICENSE).
