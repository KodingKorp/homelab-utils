# AGENTS.md

Guidance for humans **and AI coding agents** working in this repository. (Claude Code reads
[CLAUDE.md](CLAUDE.md), which points here. Cursor, Aider, Copilot Workspace, etc. read this file.)

Keep this file up to date when you change build commands, architecture rules, or add a tool.

---

## What this is

`homelab-utils` is a native desktop app (Tauri 2 + React) plus lightweight CLI tools for managing
a homelab LAN: discover devices, name them, detect SSH, scan ports/services, and connect. It's a
Rust **Cargo workspace**. See [README.md](README.md) for the product overview.

## Repository map

```
Cargo.toml                     # virtual workspace manifest (resolver 3, edition 2024)
rust-toolchain.toml            # pinned stable toolchain + rustfmt/clippy
dist-workspace.toml            # cargo-dist config for CLI binaries (template)
.github/workflows/             # ci.yml (fmt/clippy/test/build), release.yml (tauri-action + CLI)
crates/
  hlu-core/                    # lib: domain model + persistence. GUI-FREE. std + light deps only.
    src/model.rs               #   Device, SshStatus, SshInfo, DeviceStatus, ServicePort, helpers
    src/store.rs               #   SQLite working store (rusqlite) + JSON import/export
    src/paths.rs               #   per-OS data dir (directories crate)
    src/error.rs               #   CoreError / Result
  hlu-discovery/               # lib: async engine (tokio). Depends on hlu-core. NO GUI deps.
    src/lib.rs                 #   discover() orchestration + ScanConfig
    src/subnet.rs sweep.rs arp.rs mdns.rs oui.rs rdns.rs ssh.rs   # discovery sources
    src/portscan.rs            #   deep port scan + service identification
  hlu-discover-cli/            # bin `hlu-discover`: thin CLI over the engine. NO GUI deps.
  hlu-desktop/                 # Tauri 2 desktop app (frontend root)
    package.json vite.config.ts tsconfig*.json index.html
    src/                       #   React + TS frontend
      App.tsx                  #     app shell + TOOLS registry (left nav)
      views/                   #     one component per tool (DevicesView, PortsView, …)
      api.ts types.ts format.ts icons.tsx styles.css
    src-tauri/                 #   the Rust crate for the app (package `hlu-desktop`)
      src/lib.rs               #     run(): registers plugins, state, command handler
      src/commands.rs          #     #[tauri::command]s bridging the engine + store to the UI
      src/state.rs             #     AppState (Mutex<Store>)
      tauri.conf.json          #     window/bundle/plugin config
      capabilities/default.json#     webview permissions
      icons/                   #     app icons (regenerate: npm run tauri icon app-icon.png)
# future: crates/hlu-comms/ (lib) + crates/hlu-commsd/ (bin) for cross-device comms
```

## Setup & commands

Prerequisites: Rust stable ≥ 1.85, Node.js ≥ 18, and the platform
[Tauri prerequisites](https://tauri.app/start/prerequisites/) (Windows: WebView2, preinstalled on 11).

```bash
# Rust workspace
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all                         # --check in CI

# Run the discovery CLI
cargo run -p hlu-discover-cli            # add -- --json / --no-mdns / --no-ssh / --user <u> / --copy <ip>

# Desktop app (from crates/hlu-desktop)
npm install
npm run dev          # vite only (browser; Tauri APIs unavailable)
npm run tauri dev    # full native app with hot reload  ← use this to run the app
npm run build        # tsc + vite build (type-checks the frontend)
npm run tauri build  # production bundle/installer
```

**Pre-PR gate** (must pass): `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `npm run build` in `crates/hlu-desktop`.

## Architecture rules (do not break)

1. **`hlu-core` is GUI-free.** No `tauri`/UI crates. It's the shared model linked by the GUI *and*
   the CLI/daemons. Keep it dependency-light.
2. **One package per shippable binary.** The lightweight binaries (`hlu-discover-cli`, future
   `hlu-commsd`) must **not** depend on `tauri`/`wry`/`wgpu`. This structural separation — not
   feature flags — is what keeps them small. CI has a `cargo tree` guard that fails if a GUI crate
   leaks into `hlu-discover-cli`.
3. **Discovery/scan logic lives in `hlu-discovery`,** not in the app. The desktop commands and the
   CLI are thin wrappers over the same engine. Add network capability there with unit tests.
4. **Shared deps via `[workspace.dependencies]`** in the root `Cargo.toml`; members use
   `dep = { workspace = true }`. Edition 2024 / resolver 3. Each crate opts into lints with
   `[lints] workspace = true`.
5. **Naming:** crates and the org are prefixed `hlu-` (e.g. `hlu-core`); the installed CLI command
   is `hlu-discover`.
6. **Style:** `thiserror` for library errors, `anyhow` in the CLI; `tokio` for async; `tracing` for
   logs; no `unsafe` (workspace lint warns). Run `cargo fmt`.

## Domain model (`hlu-core`)

`Device` is the persisted unit. Key fields: stable `id` (MAC when known, else IP), `ip`, `mac`,
`vendor`, `custom_name` (user override), `ssh_user` (user's chosen login), `names` (mdns/upnp/
reverse-dns/netbios), `status`, `ssh: SshInfo`, `open_ports`, `services: Vec<ServicePort>`.

`SshStatus` is deliberately four-state — keep them distinct in UI: `Unknown`, `Unreachable`,
`PortReachable` (TCP open, not confirmed SSH), `ConfirmedSsh` (read an `SSH-` banner). A real SSH
login/username is **never** knowable before auth — `suggested_users` is a heuristic the user edits.

Persistence is a SQLite store (`Store`) keyed by `id`, with full `Device` JSON per row plus
mirrored columns; `export_json`/`import_json` give a human-readable backup. Data dir:
`directories::ProjectDirs::from("dev","KodingKorp","homelab-utils")`.

## Adding a new tool to the desktop app

The left nav is driven by a registry — adding a tool is one entry:

1. Create `crates/hlu-desktop/src/views/MyTool.tsx` exporting a `MyTool` component.
2. Add an icon to `src/icons.tsx`.
3. Register it in `src/App.tsx`:
   ```tsx
   { id: "mytool", label: "My Tool", icon: <MyIcon />, render: () => <MyTool /> }
   ```
4. If it needs backend work: add a `#[tauri::command]` in `src-tauri/src/commands.rs`, register it
   in the `generate_handler!` list in `src-tauri/src/lib.rs`, add any new permission to
   `capabilities/default.json`, then add a typed wrapper in `src/api.ts` and types in `src/types.ts`
   (these mirror the Rust serde shapes — snake_case field names). Put heavy logic in `hlu-discovery`.

Frontend conventions: views in `src/views/`, all backend calls go through `src/api.ts` (invoke keys
match the Rust command parameter names), TS types in `src/types.ts` mirror `hlu-core`'s serde output.

## Platform gotchas (read before debugging "weird" failures)

- **Windows Smart App Control** can block freshly-compiled build-script `.exe`s with
  `os error 4551` ("Application Control policy has blocked this file"). It's reputation-based and
  intermittent. Recovery: re-run the build, or `cargo clean -p <crate>` then rebuild to force a
  fresh binary. **Do not run a full `cargo clean` while SAC is active** — it forces the entire tree
  to rebuild back through SAC. CI runners are unaffected. (Turning SAC fully off is the only
  permanent fix, but that's irreversible without an OS reset.)
- **Windows throttles rapid outbound TCP connects**, so a full 1–65535 port scan takes ~40s
  regardless of `PortScanConfig.concurrency` — raising concurrency only adds system load. The Ports
  tool defaults to the fast common-port set for this reason; full range is explicit opt-in. A truly
  fast full scan would need raw/SYN sockets (admin-only) — a future "deep scan" mode.
- **Don't run `cargo build`/`clippy`/`test` while `npm run tauri dev` is running.** The Tauri file
  watcher and your cargo invocation contend on the `target/` lock and can wedge the dev server
  (window closes, never relaunches). Stop the dev server first, run your checks, then relaunch.
- Network scanning is scoped to the user's own LAN by design. Don't broaden scan targets or port
  lists casually — it can trip IDS/AV and has ToS implications on networks you don't own.

## CI / release

- `ci.yml`: fmt + clippy + test of the core crates on Win/macOS/Linux (+ a GUI-bloat guard), and a
  desktop build (frontend + `cargo clippy -p hlu-desktop`) on all three OSes.
- `release.yml`: on a `v*` tag, `tauri-action` builds + bundles the app per-OS, **signs the update
  artifacts and generates `latest.json`**, and publishes a GitHub Release; the CLI is built and
  attached too.

## Auto-update

The desktop app self-updates from GitHub Releases (Tauri updater plugin). The flow:
`src/updater.ts` (`checkForUpdate`/`applyUpdate`) → `App.tsx` auto-checks once on launch and renders
`src/components/UpdateBanner.tsx`; `src/views/SettingsView.tsx` has a manual check. Updates are
**minisign-verified** against `plugins.updater.pubkey` in `tauri.conf.json`.

To ship an update: **bump `version` in `tauri.conf.json` (and `package.json`)**, commit, then
`git tag vX.Y.Z && git push --tags`. CI signs and publishes; installed apps pick it up on next
launch. Requires the repo secret `TAURI_SIGNING_PRIVATE_KEY` (minisign private key) — **back it up;
losing it breaks updates for all installed apps**. The version in `tauri.conf.json` is the source of
truth the updater compares against, so it MUST be bumped per release. OS code-signing
(Apple Developer ID / Windows Authenticode) is still deferred — installs show OS warnings, and macOS
auto-update is only fully smooth once notarized; the updater itself works on Windows and Linux
AppImage unsigned.

## Commits & PRs

Small, focused commits with clear messages. Ensure the pre-PR gate passes. Keep this file and the
README accurate when behavior or commands change.
