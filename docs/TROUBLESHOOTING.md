# Troubleshooting

Ordered by how often each one actually bites.

## “I log in but the app asks for its own password again”

The guard is working; the app's internal auth is still on. Turn it off per
app — see the *Per-app login tuning* section of
[DEPLOYMENT.md](DEPLOYMENT.md) (`SONARR__AUTH__METHOD=External`, qBittorrent
subnet whitelist, …).

## Redirect loop between the app and the login page

* The cookie is set for `Domain=.labcraft.me` — check the browser's dev
  tools actually store it on that domain (third-party cookie blockers do
  not affect it: it is a first-party cookie on every subdomain).
* If `SECURE_COOKIES` was left `false` in production, browsers store it but
  may drop it over https transitions oddly — keep it `true` in production.
* Clock skew: container clocks off by minutes break nothing except TOTP —
  but hours of skew invalidates JWTs. Check `docker exec craftpass date -u`.

## 403 from Cloudflare on the Jellyfin token exchange

Jellyfin's server can't POST to `/oauth/token` because a bot rule
challenged it. See [CLOUDFLARE.md](CLOUDFLARE.md) — add the skip rule or
disable Bot Fight Mode.

## `craftpass` container dies on start: permission denied

`/data` is not writable by uid 1000:

```bash
chown 1000:1000 data/auth   # on the host, at the compose file's level
```

## /verify answers 404 “No app is registered”

The Caddyfile slug and the `/admin/apps` row disagree. `import sso_guard
sonarr` must match an app with slug `sonarr`. Fix whichever side is wrong —
no restart needed on the CraftPass side.

## Sessions stopped working after a restart

The signing keys live in `data/auth/keys/`. If that directory was recreated
(volume wiped, `chown` mishap), every old cookie and id_token is invalid —
by design. Users just sign in again; Jellyfin re-authenticates on next SSO
click.

## TOTP codes always rejected

* ±30s is tolerated (±1 step). More than that means clock skew — fix NTP
  on the VM and on the phone.
* A code is **single-use within its step**: right after enabling 2FA the
  same code won't sign you in — wait for the app to roll a new one. This
  is the replay protection, not a bug.
* Admin reset clears 2FA entirely: `/admin/users/<id>` → *Reset 2FA*.

## Locked out completely

*No admin, no 2FA device, no session*: from the VM,

```bash
docker exec -it craftpass python - <<'PY'
from craftpass import db
from craftpass.config import get_settings
conn = db.connect(get_settings())
conn.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL, totp_last_step=0, is_admin=1, is_active=1 WHERE username='chandima'")
conn.commit()
PY
```

(adjust the username) — then sign in with the password and re-enroll 2FA.

## Logs

```bash
docker logs craftpass          # application log
docker logs caddy              # guard decisions appear as 302s in access logs
```

Audit history (who did what) is in the admin console → Audit log, and is
trimmed to the newest `AUDIT_MAX_ROWS` (default 1000) events.
