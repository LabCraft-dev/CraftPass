# Deployment

Two supported routes: merge into your existing LabCraft stack (recommended),
or run the reference compose file standalone. In both cases the order is:

DNS → tunnel → compose → first boot → Caddyfile.

## 1. Cloudflare

1. **DNS records** (existing stack, unchanged):

   | Record | Type | Proxy |
   | --- | --- | --- |
   | `*.stream.labcraft.me` | `A` → VM public IP | **grey** (DNS only) |
   | future `*.labcraft.me` apps | `A` → VM public IP | orange (proxied) |

2. **Tunnel**: Zero Trust → Networks → Tunnels → *Create tunnel*. Copy the
   token into `.env` as `CF_TUNNEL_TOKEN`, then add a single public hostname:

   * Subdomain `auth`, domain `labcraft.me`, service `HTTP://craftpass:8000`.

   The tunnel routes by container name, so `cloudflared` and `craftpass`
   must share a Docker network (step 3 makes sure they do).

## 2. Configuration

```bash
cp .env.example .env      # set CF_TUNNEL_TOKEN; the rest are pre-filled
```

| Variable | Default | Notes |
| --- | --- | --- |
| `ISSUER_URL` | `https://auth.labcraft.me` | must match the tunnel hostname |
| `COOKIE_DOMAIN` | `.labcraft.me` | leading dot = all subdomains |
| `DEFAULT_REDIRECT_URL` | `https://dash.stream.labcraft.me` | post-login landing |
| `SESSION_TTL_DAYS` | `30` | persistent login lifetime |
| `SETUP_TOKEN` | *(empty)* | extra gate on `/setup` while unclaimed |
| `SECURE_COOKIES` | `true` | `false` only for local http testing |

## 3. Compose — merge into the existing stack

Add these two services to the compose file that already runs Caddy, Jellyfin,
the *arr stack, qBittorrent and friends (they must share one network):

```yaml
services:
  craftpass:
    build: ./CraftPass           # path to this repo on the VM
    container_name: craftpass
    restart: unless-stopped
    environment:
      ISSUER_URL: https://auth.labcraft.me
      COOKIE_DOMAIN: .labcraft.me
      DEFAULT_REDIRECT_URL: https://dash.stream.labcraft.me
      SESSION_TTL_DAYS: "30"
    volumes:
      - ./data/auth:/data
    # no ports: — Caddy and cloudflared reach it over the internal network

  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared
    restart: unless-stopped
    command: tunnel --no-autoupdate run --token ${CF_TUNNEL_TOKEN}
```

`./data/auth` must be writable by uid 1000 (the container runs non-root):

```bash
mkdir -p data/auth && chown 1000:1000 data/auth
```

## 4. First boot

1. `docker compose up -d --build`
2. Visit `https://auth.labcraft.me/setup` — the one-time wizard creates the
   first administrator, then the page closes forever (`303` to `/login`).
3. Sign in, then enable 2FA from **My account**.

The database seeds itself on first start: groups `media`, `arr_admin`,
`downloads` and the 11 apps from the Caddyfile. Seeds never overwrite
changes made in `/admin`.

## 5. Caddy

Replace the vhosts in your `caddy/Caddyfile` with the contents of
[`deploy/Caddyfile`](../deploy/Caddyfile) (keep your global block — the file
already carries it). Then:

```bash
docker exec caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker exec caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
```

## 6. Per-app login tuning (kills the double login)

With forward_auth in front, switch the apps' own auth off — otherwise you
log in twice:

* **Sonarr / Radarr / Prowlarr** — the UI hides the option, so set it via
  environment variables (also the reliable path across app updates):

  ```yaml
  environment:
    - SONARR__AUTH__METHOD=External
    - SONARR__SERVER__ALLOWEDHOSTS=sonarr.stream.labcraft.me,sonarr
  ```
  `RADARR__` / `PROWLARR__` equivalents for the others. `External` means
  "the proxy authenticates" — the app then does no login check of its own,
  which is only safe because Caddy enforces `sso_guard` and the app port is
  never published.
* **qBittorrent** — Web UI settings: tick *Bypass authentication for clients
  in whitelisted IP subnets* and add the Docker network's subnet (find it
  with `docker network inspect <stack>_default | grep Subnet`, typically
  `172.x.0.0/16`). qBittorrent then skips its own prompt when the request
  comes from Caddy.
* **Seerr / Prismarr / Wizarr** — leave their internal auth as you like;
  the guard sits in front regardless. Wizarr's invite paths (`/j/*`,
  `/join*`, `/static/*`, `/setup*`) are deliberately public.
* **Jellyfin** — different mechanism entirely, see
  [JELLYFIN.md](JELLYFIN.md).

## Updating

```bash
git pull
docker compose build craftpass
docker compose up -d craftpass
```

Schema migrations run automatically at startup; seeds are idempotent. Take a
copy of `data/auth/` (it contains the database *and* the signing keys) before
major upgrades — losing the keys invalidates every session and id_token at
once.
