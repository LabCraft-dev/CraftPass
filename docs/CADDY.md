# Caddy

The full drop-in Caddyfile lives at [`deploy/Caddyfile`](../deploy/Caddyfile).
This page explains the moving parts so you can extend it.

## The guard snippets

```
(sso_guard) {
	forward_auth craftpass:8000 {
		uri /verify/{args[0]}
		copy_headers X-Auth-User X-Auth-Groups
	}
}
```

`import sso_guard sonarr` expands the snippet with `{args[0]}` = `sonarr`.
Caddy then, for every request to that vhost:

1. Forwards the request's headers (cookies included) to
   `craftpass:8000/verify/sonarr`.
2. CraftPass answers:
   * **200** — allowed. Caddy copies `X-Auth-User` / `X-Auth-Groups` onto
     the request going upstream (handy if an app ever wants the identity).
   * **302** to `https://auth.labcraft.me/login?rd=<original-url>` — Caddy
     passes the redirect to the browser untouched. The user logs in, the
     cookie is set on `.labcraft.me`, and they land back on the exact URL
     they originally requested.
   * **403** — signed in, but not in the app's group. A readable page with
     a link back to the dashboard.

The `rd` fallback: CraftPass reconstructs the original URL from the proxy
headers Caddy sets (`X-Forwarded-Host` / `X-Forwarded-Proto` /
`X-Forwarded-Uri`); if those are absent it falls back to the app's
registered domain from the `/admin/apps` table.

## Version notes

* `{args[0]}` — Caddy 2.9+ spelling; on 2.5–2.8 write `{args.0}`.
* `copy_headers` lives **inside** `forward_auth` — not at vhost level.
* Validate before every reload:

  ```bash
  docker exec caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
  docker exec caddy caddy reload  --config /etc/caddy/Caddyfile --adapter caddyfile
  ```

## The API-key bypass variant

```
(sso_guard_arr) {
	@browser_requests {
		not header X-Api-Key *
		not query apikey=*
	}
	forward_auth @browser_requests craftpass:8000 { … }
}
```

Used for Sonarr/Radarr/Prowlarr/Bazarr so mobile clients (nzb360, LunaSea)
that authenticate with an `X-Api-Key` header or `?apikey=` parameter go
straight through — the *arr app validates the key itself on those API
calls. The key is doing the authentication; the cookie is irrelevant there.

## Wizarr's selective guard

```
@wizarr_admin {
	not path /j/* /join* /static/* /setup*
}
forward_auth @wizarr_admin craftpass:8000 { … }
```

Invite links must stay reachable for guests who have no account yet; only
the management UI is behind the guard.

## Adding a future app

1. Add the row in `/admin/apps` (slug = the Caddyfile argument, group,
   domain).
2. Add the vhost:

   ```
   newapp.stream.labcraft.me {
   	import sso_guard newapp
   	reverse_proxy newapp:1234
   }
   ```

3. `caddy reload`. Done — no CraftPass restart needed.
