## What and why

<!-- One or two sentences. Link the plan.md phase or the issue. -->

## Checks

- [ ] `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`
- [ ] `(cd web && npm run check && npm run format:check)` if `web/` changed
- [ ] `prove pve-plugin/t` if `pve-plugin/` changed
- [ ] docs, manual and `state.md` updated; screenshots regenerated if the UI changed
- [ ] lab run, if the change touches a real system (which one: ...)
- [ ] no secrets, no emojis
