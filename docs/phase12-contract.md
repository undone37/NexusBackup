# Phase 12 — API contract (UI redesign, KPI dashboard, OIDC, settings pages)

Status: contract v1 (2026-10-11). Decisions: plan.md §2 (rows "UI redesign", "Management dashboard",
"OIDC", "OIDC user provisioning", "Branding", "UI dependencies"). Backend and UI are built against
this file in parallel; the mock (`web/mock/api.ts`) implements it too. All endpoints below are under
`/api/v1`, JSON, session cookie + CSRF as today (docs/control-plane.md). Additive only.

## 1. Dashboard KPIs — `GET /dashboard?days=7|30` (all roles; tenant users see their tenants)
Computed server-side from the catalog (no client-side scans), cached ≤ 60 s.
```json
{
  "generated": 1791750000, "days": 30,
  "protection": { "objects": 412, "protected": 401, "unprotected": 11, "sla_ok": 395, "sla_breach": 6, "never": 11,
                  "worst": [ { "source": "pve-1-101", "name": "vm101 (web)", "kind": "pve", "tenant": "acme",
                               "last_ok": 1791700000, "age_s": 50000, "rpo_s": 86400, "sla": "ok|breach|never" } ] },
  "jobs": { "success_rate": 0.991, "total": 1240, "ok": 1229, "warning": 4, "failed": 7,
            "per_day": [ { "day": "2026-10-10", "ok": 41, "warning": 0, "failed": 1 } ],
            "failed_by_kind": [ { "kind": "pve", "failed": 3 } ] },
  "capacity": { "total": 0, "used": 0, "free": 0, "logical": 0, "physical": 0,
                "reduction": 4.2, "dedup": 3.1, "compression": 1.35,
                "per_day": [ { "day": "2026-10-10", "used": 0, "logical": 0 } ],
                "forecast_full_days": 214 },
  "offsite": { "tenants": 3, "lag_max_s": 3600, "lagging": 0, "lock_coverage": 1.0,
               "replication_lag_max_s": 900, "last_verify": 1791700000, "verify_failed": 0 }
}
```
- Object = a protected unit (PVE guest, agent host, TrueNAS dataset, share, plugin guest/source). RPO = the
  policy's schedule period (daily = 86400 s, …); `breach` when `age_s > rpo_s * 1.5`; `never` = in a group
  but no successful backup; `unprotected` = known guest not in any group (PVE/plugin guest lists cached).
- `capacity.per_day`: from a new daily sample table (catalog migration v10 `capacity_samples(day, tenant,
  used, logical)`), written by the scheduler's refresh; forecast = linear regression of the last 30 days,
  `null` when not growing or < 7 samples.
- `forecast_full_days`, ratios: `null` when unknown. `worst`: at most 10, breach/never first.

## 2. OIDC (authorization code + PKCE, generic IdP)
- `GET /auth/oidc` (no session) → `{ "enabled": true, "label": "Sign in with Keycloak" }`.
- `GET /auth/oidc/start?next=/path` → 302 to the IdP authorize endpoint (state + nonce + PKCE S256; pending
  login kept server-side ≤ 10 min, bound to a short-lived HttpOnly cookie).
- `GET /auth/oidc/callback?code&state` → validates state/nonce/PKCE, ID token (issuer, aud, exp, nonce,
  signature against JWKS, RS256/ES256/PS256), maps claims, creates/updates the user (JIT), sets the normal
  session cookie, 302 to `next` (same-origin path only). Errors → 302 `/#/login?oidc_error=<code>`.
- Settings `GET /settings/oidc` (admin, security_officer: read) / `PUT /settings/oidc` (admin; **quorum**
  `oidc.update` when approvals are on, because it changes who can log in):
  ```json
  { "enabled": true, "issuer": "https://idp.example.com/realms/nexus", "client_id": "nexusbackup",
    "client_secret_set": true, "client_secret": "write-only", "scopes": ["openid","profile","email","groups"],
    "username_claim": "preferred_username", "groups_claim": "groups", "label": "Sign in with Keycloak",
    "mappings": [ { "group": "nexus-admins", "role": "admin", "tenants": [] },
                  { "group": "acme-users", "role": "tenant_user", "tenants": ["acme"] } ] }
  ```
  Client secret sealed like other secrets. Discovery via `<issuer>/.well-known/openid-configuration`
  (egress allow-list gets the IdP host). `POST /settings/oidc/test` → discovery + JWKS fetch result.
- Users: `auth` = `local` | `oidc` (catalog v10 `users.auth`, `users.oidc_sub`). OIDC users have no
  password/TOTP (MFA is the IdP's job), cannot use local login, are refreshed (role, tenants, disabled if no
  mapping matches → login denied + audit) at every login. Highest-privilege matching mapping wins.
  Local accounts stay (break-glass). Quorum/approvals treat OIDC users like local users (by name).
- Audit: `auth.oidc_login`, `auth.oidc_denied`, `user.oidc_created`, `settings.oidc`.

## 3. Alert delivery — `GET/PUT /settings/alerts` (admin; read: security_officer), `POST /settings/alerts/test`
```json
{ "webhook_url": "https://hooks.example.com/x", "smtp": { "host": "mail.example.com", "port": 587,
  "starttls": true, "from": "nexus@example.com", "to": ["ops@example.com"], "user": "nexus",
  "password_set": true, "password": "write-only" }, "min_severity": "warning" }
```
Stored in the catalog (setting `alerts`, secrets sealed for the scheduler); the scheduler prefers it over
`/etc/nexus/alerts.json` (kept as fallback). Test sends one `test` alert through each configured channel and
returns `{ "webhook": "ok|error: …", "smtp": "ok|error: …" }`. Egress allow-list includes both hosts.

## 4. Appliance SSH keys — `GET /ssh-keys` (admin, operator, security_officer)
`[ { "name": "pve", "purpose": "Proxmox VE nodes (forced command)", "public_key": "ssh-ed25519 …",
  "fingerprint": "SHA256:…", "created": 0 } ]` (keys under `/etc/nexus/ssh`, public halves only).
`POST /ssh-keys/{name}/rotate` (admin, **quorum** `ssh_key.rotate`): the scheduler generates a new key; the
old one stays valid until `POST /ssh-keys/{name}/retire` so sources can be updated first.

## 5. Updates — `GET /updates` (admin, security_officer, operator: read)
`{ "booted": {"version": "0.0.1-alpha", "digest": "sha256:…", "since": 0}, "staged": null | {…},
  "available": null | {"version": "…", "digest": "…"}, "channel": "stable", "window": "Sun 03:00 120",
  "last_check": 0, "status": "idle|checking|staged|error", "error": null, "rollback": null | {…} }`
from `nexus-update status --json`. `POST /updates/check` (admin) triggers a check; `POST /updates/apply`
(admin, **quorum** `update.apply` when approvals are on) stages now instead of waiting for the window.

## 6. Plugin restores per snapshot kind (manifest, additive v1.4)
Restore spec gets optional `"applies_to": "guest" | "source" | "any"` (default `any`). The UI offers a
restore on a snapshot only if it matches (`plugin-<p>-<sid>-<guest>` = guest, `plugin-<p>-<sid>` = source);
the host refuses mismatches. PostgreSQL: `to_target` = guest, `pitr` = source.

## 7. Break-glass (sole administrator lost the authenticator / password)
Console only (physical or hypervisor console, root): `nexus-setup recover-admin [--user NAME]` — requires
the **recovery key** (as at setup), resets the chosen admin to "pending activation" and prints a new one-time
activation code; with approvals on and ≥ 2 approvers it refuses unless `--force-solo` (then flagged).
Audited (`user.break_glass`), alert `break_glass` (critical), UI banner until acknowledged.
Documented in manual/14-disaster-recovery.md ("Break-glass").

## Implementation notes and deviations (backend, 2026-10-11)
Clarifications agreed with the UI (integrator) and choices where this contract was open. **Deviations are marked ⚠.**
- §1 `protection`: `objects = protected + unprotected`, `protected = sla_ok + sla_breach + never`; `never` = in a
  group, no successful backup; `unprotected` = known object in no group. Known objects without a group: enrolled
  agents and the guests of the last `plugin_guests` listing per plugin source (no PVE guest inventory exists in the
  catalog yet, so unprotected PVE guests are not counted). `worst` sorts `never`, then `breach`, then by age.
  `jobs` counts `backup` / `plugin_backup` jobs finished in the window; `warning` = finished ok with
  `consistent: false`; `failed_by_kind` uses the source kind (`pve`, `linux`, `plugin:<kind>`, …).
  `capacity.used/total/free` = the store file system (scheduler, setting `capacity`); `physical` = bytes in the
  tenant stores, `logical` = local snapshot sizes (latest daily sample); `dedup` / `compression` are always `null`
  (not measured separately yet), `reduction` = logical / physical. Tenant users get their tenant's `used`
  (= physical) and `null` for total/free/forecast/replication lag. `offsite.lock_coverage` = share of the local
  snapshots in scope under a retention lock. Additive: `break_glass` (see §7).
- §2: ⚠ the client secret is encrypted with the web-api's own key (`enc:v1:`), not sealed to the scheduler — the
  web-api must send it to the token endpoint. Additive settings fields: `ca_pem` (private IdP CA), GET-only
  `redirect_uri` (to register at the IdP). Default scopes `["openid", "profile", "email"]` (no `groups` scope:
  Entra has none; Keycloak needs a group mapper / client scope), groups claim `groups`. ⚠ Mappings: `tenants` stays
  an array but holds 0 or 1 entries — `tenant_user` exactly one, admin / security_officer / operator none (all
  tenants); anything else → 400 on PUT. Claims come from the ID token (configure the IdP to put the groups claim
  there). Accounts are matched by (issuer, `sub`), never by name; the name is `username_claim` as it is (may
  contain `@`, e.g. an Entra UPN; ≤ 128 characters, printable, no whitespace); if any account with that name exists
  already (a local one in particular) the login is refused (`denied`, audit reason `name_conflict`) — never merged.
  "No mapping matches" refuses (`denied`) and disables the account; a disabled account (by an admin or that rule)
  is refused with `account_disabled` and is never re-enabled by a login — only by an admin. Error codes:
  `disabled` (single sign-on turned off on this appliance), `account_disabled`, `expired` (pending login older than
  10 min), `state`, `idp`, `token`, `denied` (no mapping, name conflict, unusable name, rate limit; details in the
  audit entry `auth.oidc_denied`). `next`: `/` or a same-origin path incl. fragment (`/#/jobs`).
  Also audited: `user.oidc_updated` (role/tenant changed at login), `settings.oidc_test`.
  `POST /settings/oidc/test` → flat `{"discovery": "ok" | "error: …", "jwks": "ok: <n> keys" | "error: …"}`.
- §3: `POST /settings/alerts/test` → flat `{"webhook"?: "ok" | "error: …", "smtp"?: …}`, one member per
  configured channel (the scheduler sends; the endpoint waits up to 45 s, else 202 `{job_id}`). `starttls: false`
  means implicit TLS on port 465, plain SMTP otherwise. Changing SMTP host/port/user requires the password again.
- §4: lists only key files below `/etc/nexus/ssh` that the configuration uses and that exist: PVE node keys
  (`nodes.*.key` of PVE sources, purpose "Proxmox VE nodes (forced command)") and SFTP offsite keys
  (`remote.key_file`, "Storage Box offsite (SFTP)"); TrueNAS sources keep their own per-source key pair (shown on
  the source). The appliance generates a key only when rotating (ed25519, OpenSSH format). ⚠ After a rotation the entry shows the **new** key (to install on the
  sources) and the old one as `previous: {public_key, fingerprint, created}` (still the one in use) until
  `retire`; one entry per name. Retire → 202 `{job_id}` (job `ssh_key_retire`), 409 without a rotation.
- §5: `staged` and `rollback` have the shape of `booted` (`{version, digest, since}`). `available` is set when an
  image newer than the booted one was found; status `staged` = downloaded, reboot pending (maintenance window).
  `POST /updates/apply` = install now: stage the available update if it is not staged yet and reboot into it
  outside the window (quorum `update.apply` while approvals are on); `checking`
  while a check/apply request waits for `nexus-update`. `nexus-update status --json` prints this view; the
  web-api reads the same view from `status.json` (`api` member). Additive: `applying`, `pending_request`.
- §6: enforced by the web-api and by `nexus-pluginhost`; docs/plugin-system.md "v1.4".
- §7: the banner follows the unacknowledged `break_glass` alert (kind `break_glass`, critical); `GET /auth/me` and
  `GET /dashboard` also return `break_glass: {at, user, alert, forced_solo}`. Only admin / security_officer can
  acknowledge that alert.
