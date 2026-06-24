# CLAUDE.md

This project's contributor and architecture guide lives in **[AGENTS.md](AGENTS.md)** — read it
first. It covers the repo map, build/test/lint commands, architecture rules, how to add a tool,
how issues are tracked, and platform gotchas.

## Quick reference

```bash
# Pre-change gate (run before committing)
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
( cd crates/hlu-desktop && npm run build )   # frontend type-check

# Run things
cargo run -p hlu-discover-cli                 # discovery CLI
( cd crates/hlu-desktop && npm run tauri dev ) # desktop app (native window)
```

## Critical reminders (details in AGENTS.md)

- **Keep `hlu-core` GUI-free** and the lightweight binaries free of `tauri`/GUI deps (CI enforces
  this). Put network logic in `hlu-discovery`, not the app.
- **Adding a tool** = one entry in the `TOOLS` registry in `crates/hlu-desktop/src/App.tsx` + a view
  in `src/views/` (+ optional `#[tauri::command]` and `api.ts`/`types.ts` wrappers).
- **Don't run `cargo` builds while `npm run tauri dev` is running** — the watcher and cargo contend
  on `target/` and wedge the dev server. Stop it first.
- **Windows Smart App Control** may block fresh build scripts (`os error 4551`); re-run or
  `cargo clean -p <crate>` then rebuild. Never full-`cargo clean` while SAC is active.
- **Windows throttles outbound connects** → full port scans are ~40s regardless of concurrency;
  the Ports tool defaults to common ports for this reason.
- SSH usernames are heuristics (never knowable pre-auth); the four `SshStatus` states are distinct
  on purpose — preserve that distinction in UI.
- **Issues are tracked on GitHub Issues** (not in-repo files): list with `gh issue list`, read with
  `gh issue view <N>`, file with `gh issue create`. See AGENTS.md → Issue tracking.
