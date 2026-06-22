# homelab-utils

> A native, blazing-fast desktop cockpit for your homelab — discover devices, name them, check SSH, scan ports, and connect in one click. No server to deploy, no YAML to maintain.

[![CI](https://github.com/KodingKorp/homelab-utils/actions/workflows/ci.yml/badge.svg)](https://github.com/KodingKorp/homelab-utils/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`homelab-utils` is an open-source desktop app (plus lightweight CLI tools) for managing the
machines, projects, and apps on your local network. It opens in under a second, auto-discovers
devices on your LAN, gives them sensible names, tells you which are reachable over SSH, scans
their ports to identify running applications, and lets you copy a ready-to-paste `ssh` command —
all from a single installable app that updates itself from GitHub.

Where comparable tools (Beszel, NetAlertX, Komodo, Homepage, Homarr, …) are self-hosted Docker
web apps configured through YAML or a database, `homelab-utils` is a **native, zero-deploy,
zero-config desktop app**.

> 🚧 **Early development.** The discovery + SSH + port-scanning tools work today. Cross-device
> comms binaries come next.

## Features

- 🔎 **Device discovery** — privilege-free LAN scan (mDNS/DNS-SD, UPnP/SSDP, a bounded TCP sweep,
  and the OS ARP cache). No admin rights required. Auto-refreshes on launch.
- 🏷️ **Auto-naming** — merges mDNS hostnames, UPnP friendly names, reverse-DNS, and MAC vendor
  (OUI) lookups into a stable display name you can override.
- 🔐 **SSH detection** — a fast, handshake-free banner probe distinguishes *port reachable* from
  *confirmed SSH*, parses an OS hint, and copies `ssh user@host` to your clipboard (editable
  username, remembered per device).
- 🛠️ **Ports & Services** — scans a host's ports (fast common-port set by default, or full
  1–65535) and identifies the running application per port via a well-known-port table, banner
  grabbing, and an HTTP probe.
- ⬆️ **Auto-update** — the desktop app checks GitHub Releases on launch and updates itself
  (minisign-verified), with a prompt and a manual "Check for updates" in Settings. (OS install
  warnings remain until code-signing is added.)

## Architecture

A single Cargo **workspace** with one package per shippable artifact, so the heavy desktop GUI
dependency tree never compiles into the lightweight CLI/daemon binaries.

```
crates/
  hlu-core/          # GUI-free domain model + persistence (shared by everything)
  hlu-discovery/     # async discovery + SSH-probe + port-scan engine (tokio). No GUI deps.
  hlu-discover-cli/  # `hlu-discover` — standalone CLI over the engine
  hlu-desktop/       # Tauri 2 desktop app
    src-tauri/       #   Rust backend (commands bridge the engine to the UI)
    src/             #   React + TypeScript frontend (Vite); tools live in src/views/
```

| Layer | Choice |
|---|---|
| Desktop shell | [Tauri 2](https://tauri.app) (Rust core + system WebView) |
| Frontend | React + TypeScript + Vite |
| Async runtime | tokio |
| Storage | SQLite (`rusqlite`) working store + JSON export |
| Auto-update | `tauri-plugin-updater` (GUI) · `dist` + `axoupdater` (CLI binaries) |

See **[AGENTS.md](AGENTS.md)** for the full developer/contributor guide (build commands,
conventions, how to add a tool, and platform gotchas) — written so both humans and AI coding
agents can work on the project effectively.

## Quickstart

**Prerequisites:** a recent **Rust** stable toolchain (≥ 1.85, for edition 2024), **Node.js** ≥ 18,
and the platform [Tauri prerequisites](https://tauri.app/start/prerequisites/) (on Windows:
WebView2, preinstalled on Windows 11).

```bash
# Clone
git clone https://github.com/KodingKorp/homelab-utils.git
cd homelab-utils

# Desktop app (dev) — opens the native window with hot reload
cd crates/hlu-desktop
npm install
npm run tauri dev

# …or the standalone discovery CLI (from the repo root)
cargo run -p hlu-discover-cli            # table output
cargo run -p hlu-discover-cli -- --json  # JSON
```

Build a release bundle/installer: `cd crates/hlu-desktop && npm run tauri build`.

## Releasing & auto-update

To ship an update: bump `version` in `crates/hlu-desktop/src-tauri/tauri.conf.json` (and
`package.json`), commit, then tag:

```bash
git tag v0.1.1 && git push --tags
```

That triggers [`.github/workflows/release.yml`](.github/workflows/release.yml): `tauri-action`
builds and bundles the desktop app for Windows/macOS/Linux, **signs the update artifacts and
generates `latest.json`**, and publishes a GitHub Release; the `hlu-discover` CLI is built and
attached too. Installed apps detect the new version on next launch (or via Settings → Check for
updates) and update themselves.

**Required once:** add the repo secret `TAURI_SIGNING_PRIVATE_KEY` (the minisign private key from
`npm run tauri signer generate`). Back the key up — if it's lost, installed apps can no longer
validate updates. OS code-signing (Apple Developer ID notarization, Windows Authenticode) is a
separate, later step that removes the install-time SmartScreen/Gatekeeper warnings.

## Contributing

Contributions are welcome! Please read **[AGENTS.md](AGENTS.md)** first — it documents the build/
test/lint commands, the architecture rules (e.g. keep `hlu-core` GUI-free; one package per
binary), and how to add a new tool to the app. Before opening a PR, make sure these pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

---

Made by [KodingKorp](https://github.com/KodingKorp).
