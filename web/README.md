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
`former-op` is disabled.

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

There are no runtime dependencies. All five packages are build-time
devDependencies, pinned to exact versions:

| package | purpose |
|---|---|
| `svelte` | compiler and runtime (the runtime gets bundled) |
| `vite`, `@sveltejs/vite-plugin-svelte` | build and dev server |
| `typescript`, `svelte-check` | type checking (`npm run check`) |

The app has no router library, no UI kit, no CSS framework, no web fonts and no
QR library. `src/lib/qr.ts` is a small QR encoder (byte mode, ECC level M,
versions 1–40). Its output was checked by decoding it with OpenCV.

## Layout

```
mock/api.ts            dev/preview server middleware only (in-memory data), never bundled
src/main.ts, App.svelte  shell, role-aware navigation, hash router (#/path?query)
src/lib/api.ts         fetch wrapper: X-CSRF-Token, 401 handling, 202 {quorum_id} -> "pending approval"
src/lib/i18n.ts        every user-visible string (English for now; add a German object of the same shape)
src/lib/roles.ts       UI mirror of the RBAC table (only hides controls; the server decides)
src/pages/*            Login, Dashboard, Snapshots, Files, Jobs, JobDetail, Alerts, Quorum,
                       Audit, Tenants, Sources, Agents, Policies, Groups, Users
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
  - The code uses no `style=` attributes, `style:` directives or Svelte transitions, which would inject `<style>` elements.
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
  - The tenant offsite config contains only a key *file path*. The web-api
    refuses inline secrets in that blob.
  - The TOTP provisioning URI appears only in the dialog right after a user is
    created or the TOTP is reset.
- **Quorum.** Any 202 `{quorum_id}` answer shows the notice "Pending approval: request #N…".
  Creating a privileged user also returns the TOTP URI with the 202. The UI shows
  it and notes that the account only works after approval.

## Assumptions about the API (web-api v1)

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
