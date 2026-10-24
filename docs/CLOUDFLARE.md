# Cloudflare

CraftPass uses exactly two Cloudflare features: ordinary DNS records and one
Tunnel. No Worker, no Access policy — the authentication is CraftPass' own.

## DNS layout

| Record | Type | Target | Proxy |
| --- | --- | --- | --- |
| `*.stream.labcraft.me` | `A` | VM public IP | **grey** — DNS only |
| future `*.labcraft.me` | `A` | VM public IP | orange — proxied |
| `auth.labcraft.me` | *(none)* | tunnel | via cloudflared |

The `*.stream` hosts are grey so browser traffic goes straight to Caddy on
the VM (ZeroSSL certificates). `auth.labcraft.me` resolves to the tunnel and
never touches the VM's public IP.

## Tunnel (Zero Trust → Networks → Tunnels)

* Create tunnel → copy token → `.env` as `CF_TUNNEL_TOKEN`.
* Public hostname: `auth.labcraft.me` → `HTTP://craftpass:8000`.
* `cloudflared` and `craftpass` must share a Docker network; the tunnel
  routes by container name.

## WAF / Bot rules — the OIDC back-channel

Jellyfin's *server* POSTs to `https://auth.labcraft.me/oauth/token`
(server-to-server, no browser signals). If you have Bot Fight Mode
(free plan) or Managed Challenge rules enabled, that call can get
challenged and fail with a 403 from Cloudflare — the plugin then reports
token-endpoint errors.

Options, in order of preference:

1. **Skip rule** (Pro+ / wherever Custom Rules' *Skip* action is available):

   Expression: `(http.host eq "auth.labcraft.me" and starts_with(http.request.uri.path, "/oauth/"))`
   Action: *Skip* — Super Bot Fight Mode, Managed Challenge.

   Add a second one for `/.well-known/` if you use challenges broadly.

2. **Free plan**: keep Bot Fight Mode **off** for the zone, or simply don't
   create challenge rules that match `auth.labcraft.me` — the default
   state passes the token POST through fine.

`/oauth/token` has its own defenses (client secret required, per-IP
limiter, single-use codes), so skipping edge challenges there does not
expose anything guessable.

## Caching

Never cache `auth.labcraft.me` (Cache Rule: bypass for that hostname) —
Cloudflare doesn't cache POSTs or dynamic content by default, but an eager
page-rule setup can surprise you. CraftPass also sends `Cache-Control:
no-store` on every auth-sensitive response.
