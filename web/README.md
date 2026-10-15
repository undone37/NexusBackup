# NexusBackup Web UI

Svelte 5 + Vite single-page app in TypeScript. It talks only to the REST API in
`docs/control-plane.md`. The built files in `web/dist` are embedded into the
`web-api` binary, so the appliance image does not need Node.

## Commands

```sh
cd web
npm ci --ignore-scripts   # installs exactly what package-lock.json lists; runs no install scripts
npm run dev               # http://localhost:5173 with the in-memory mock API
npm run check             # svelte-check with type checking; warnings count as errors
npm run build             # writes web/dist (index.html + /assets/*-<hash>.{js,css,svg})
npm run preview           # serves dist with the production CSP header + the mock API
```

Mock users: `admin`, `so`, `so2` (security officers), `op` (operator) and
`acme` (tenant user of tenant `acme`). The password for all of them is `nexus`,
and any 6-digit code works as the TOTP code. `newop` is an operator pending
activation: on the sign-in page choose "Activate account" and enter the code
`DEMO-ACTIVATE-NEWOP-2026` (any 6-digit authenticator code is accepted);
`former-op` is disabled. `lwagner` is a single-sign-on (OIDC) operator: the mock
has no identity provider, so "Sign in with Keycloak" on the sign-in page signs
in as `lwagner` directly.

The mock is seeded with a fictional demo appliance that the manual's screenshots
use (`manual/tools/screenshots.mjs`): tenants `acme` (S3 Object Lock offsite,
replicated to the peer `dr-site`), `initech` (Storage Box offsite) and `globex`
(replicated from `hq-primary`); Proxmox VE, Linux and Windows agent, TrueNAS
(built-in and plugin), NFS, SMB and PostgreSQL sources; jobs incl. failures,
alerts, and pending approvals (approvals start enabled). Only example domains and
documentation IP ranges are used. `NEXUS_MOCK_EPOCH=<unix seconds>` fixes the mock
clock's start and `NEXUS_MOCK_SEED=<n>` makes ids, tokens and codes deterministic.

To use a real web-api instead of the mock:
`NEXUS_API=https://appliance:8443 npm run dev`. Vite then proxies `/api` and
does not verify the self-signed certificate.

## Dependencies

All packages are pinned to exact versions and end up in `dist` (nothing is
loaded from third parties at run time):

| package                                                                 | purpose                                                                       |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `svelte`                                                                | compiler and runtime (the runtime gets bundled)                               |
| `vite`, `@sveltejs/vite-plugin-svelte`                                  | build and dev server                                                          |
| `typescript`, `svelte-check`                                            | type checking (`npm run check`)                                               |
| `@lucide/svelte` (ISC)                                                  | icons; each icon is imported by path, only the used ones are bundled          |
| `@fontsource-variable/ibm-plex-sans`, `@fontsource/ibm-plex-mono` (OFL) | UI fonts; `app.css` references only the Latin / Latin Extended `.woff2` files |

The app has no router library, no UI kit, no CSS framework, no chart library
(the dashboard charts in `src/components/charts` are hand-written SVG) and no
QR library. `src/lib/qr.ts` is a small QR encoder (byte mode, ECC level M,
versions 1–40). Its output was checked by decoding it with OpenCV.

## Layout

```
mock/api.ts            dev/preview server middleware only (in-memory data), never bundled
src/main.ts, App.svelte  shell, role-aware navigation, hash router (#/path?query)
src/lib/api.ts         fetch wrapper: X-CSRF-Token, 401 handling, 202 {quorum_id} -> "pending approval"
src/lib/i18n.ts        every user-visible string (English for now; add a German object of the same shape)
src/lib/roles.ts       UI mirror of the RBAC table (only hides controls; the server decides)
src/app.css            design tokens (navy + teal palette, light-dark() pairs) and all global styles
src/lib/theme.svelte.ts  light / dark / follow the OS (top-bar toggle, stored per browser)
src/components/Logo.svelte + src/favicon.svg  the logo mark (replace both to rebrand)
src/pages/*            Login, Dashboard (KPIs, GET /dashboard), Snapshots, Files, Jobs, JobDetail, Alerts,
                       Quorum, Audit, Tenants, Sources, Agents, Policies, Groups, Users, Plugins, Settings
src/pages/settings/*   Settings tabs: Approvals, Alert delivery, Single sign-on (OIDC), SSH keys, Updates
src/components/charts/*  StackedBars, TrendLine, Ring (donut), HBars: SVG, tooltips, hidden data tables
src/components/Menu.svelte  action menu (native popover) used for the snapshot restore options
src/components/RestoreFiles.svelte  "restore to path" dialog for host snapshots (Snapshots + Files)
src/components/SchemaForm.svelte    form generated from a plugin's config_schema / params_schema
src/lib/schema.ts      form model + client-side validation of that JSON-Schema subset
src/lib/plugins.ts     plugin kind lookup, plugin snapshot name parsing, version compare
```

## Security notes

- **CSP.** The web-api sends `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; …`.
  The build is compatible with it:
  - `index.html` contains only `<script type="module" src="/assets/…">` and a `<link rel="stylesheet">`.
  - The module-preload polyfill is turned off.
  - `assetsInlineLimit: 0`, so no asset is inlined as a data URI.
  - The Svelte component CSS ends up in the single external `.css` file.
  - The code uses no `style=` attributes and no Svelte transitions (they would inject `<style>` elements).
    Positions that depend on data (chart tooltips, the popover menu) use `style:` directives with
    dynamic values only: Svelte applies them through the CSSOM (`element.style…`), which CSP does not
    restrict. Static `style:` values would be compiled into the template markup and blocked.
  - There is no `eval` or `new Function`. Svelte creates DOM from templates via `<template>.innerHTML`, which CSP allows because the templates contain no inline handlers or styles.

  `npm run preview` serves `dist` with the same CSP header. A headless-Chrome run
  through every screen reported no `securitypolicyviolation` events. The dev
  server runs without the CSP because Vite HMR injects inline styles.

- **CSRF.** The token from `POST /auth/login` is kept only in memory and is never
  written to storage. After a reload, `GET /auth/me` returns `{user, csrf}` again.
  Every non-GET request sends `X-CSRF-Token`.
- **Secrets.**
  - The source `token_secret` is write-only. GET returns `token_secret_set`, and
    leaving the field empty on edit keeps the stored secret.
  - The tenant offsite config contains only a key _file path_. The web-api
    refuses inline secrets in that blob.
  - The TOTP provisioning URI appears only in the dialog right after a user is
    created or the TOTP is reset.
- **Quorum.** Any 202 `{quorum_id}` answer shows the notice "Pending approval: request #N…".
  Creating a privileged user also returns the TOTP URI with the 202. The UI shows
  it and notes that the account only works after approval.

## Assumptions about the API (web-api v1)

- **Phase 12 (docs/phase12-contract.md).** Where the contract leaves a shape open, the UI assumes:
  `POST /settings/oidc/test` and `POST /settings/alerts/test` answer `{ <check>: "ok[: detail]" | "error: …" }`;
  after `POST /ssh-keys/{name}/rotate` the old key comes back as `previous: {public_key, fingerprint, created}`
  of the entry (two entries with the same name are handled too, newest = current); `staged` / `rollback` of
  `GET /updates` look like `booted`; the break-glass banner shows the unacknowledged alert of kind
  `break_glass` (admins) and acknowledges it with `POST /alerts/{id}/ack`; OIDC error codes `denied`,
  `disabled`, `expired`, `state`, `idp` and `token` have their own texts, others a generic one.
  The dashboard derives "not in a group" as `objects - sla_ok - sla_breach - never`.

- **File browsing.** `files_list` results come from the structured job result
  (`job.result.entries`, written by the scheduler).
- **Downloads.** For `files_get`, the UI takes `download_token` from the 202
  body, polls the job, then links to `/api/v1/downloads/<token>`.
- **Agents.** The one-time enrollment token and install command from `POST /agents` and
  `POST /agents/{id}/token` are shown once in a dialog and dropped from memory when it closes.
  "Enroll" is offered only while `token_expires` is in the future (otherwise the server answers 409).
- **Host snapshots.** Snapshots of Linux hosts are named `host-<agent id>`. The file browser handles them
  like `vm-`/`ct-` snapshots. "Restore to path" posts a `restore_files` job. The user must type the target
  agent's name, which is sent as `confirm`.
- **Audit paging.** The audit page loads newest first (`?order=desc&limit=100`)
  and pages backwards with `?before=<oldest seq shown>`.
