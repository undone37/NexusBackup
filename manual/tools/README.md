# Manual tools

## screenshots.mjs

Regenerates every picture in `manual/images/` from the current web UI build against the seeded demo backend
(`web/mock/api.ts`). No appliance is needed.

```sh
(cd web && npm ci --ignore-scripts)        # once
node manual/tools/screenshots.mjs          # all scenes (about 2 minutes)
node manual/tools/screenshots.mjs users    # only some scenes (names: see the `scenes` list in the script)
```

What it does:

- builds the UI (`vite build`, skip with `SKIP_BUILD=1`) and serves it with `vite preview` (production CSP + mock API)
  on a free port (never 5173);
- starts headless Google Chrome (`/usr/bin/google-chrome`, override with `CHROME=`) and drives it over the DevTools
  protocol with Node's built-in WebSocket (Node 20.19+, no npm dependencies);
- presents the app as `https://backup.example.com/` (requests answered through the DevTools Fetch domain), so no local
  port appears in links;
- fixes the demo clock (`NEXUS_MOCK_EPOCH`, 2026-10-14 09:30 UTC) and the mock's random ids (`NEXUS_MOCK_SEED`); the
  browser clock follows the mock clock; viewport 1440×900 (a few tall dialogs use a taller viewport), light theme,
  device scale factor 1, UTC, en-US;
- signs in as admin, security officer, operator and tenant user, visits every page and the important dialogs, and walks
  through an account activation;
- recompresses the PNGs losslessly with `optipng` if it is installed.

Scenes change the demo state in order (new requests, approvals switched off at the end, an account activated), so
running a single scene can show slightly different data than a full run. `KEEP=1` keeps the browser profile, the vite
log and screenshots of failed scenes in a temporary directory.

Demo data: tenants `acme` (S3 Object Lock offsite, replicated to peer `dr-site`), `initech` (Storage Box offsite) and
`globex` (replicated from `hq-primary`); only example domains and documentation IP ranges. Demo logins are listed in
`web/README.md`.
