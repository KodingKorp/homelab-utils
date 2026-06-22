# homelab-utils

> A native, blazing-fast desktop cockpit for your homelab — discover devices, name them, check SSH, and connect in one click. No server to deploy, no YAML to maintain.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`homelab-utils` is an open-source desktop app (and a set of lightweight CLI/daemon
binaries) for managing the machines, projects, and apps running on your local network.
It opens in under a second, auto-discovers devices on your LAN, gives them sensible
names, tells you which ones are reachable over SSH, and lets you copy a ready-to-paste
`ssh` command — all from a single installable app that updates itself from GitHub.

Where comparable tools (Beszel, NetAlertX, Komodo, Homepage, Homarr, …) are self-hosted
Docker web apps configured through YAML or a database, `homelab-utils` is a **native,
zero-deploy, zero-config desktop app**.

## Status

🚧 **Early development.** The first milestone is local device discovery + SSH detection.
Cross-device discovery and comms binaries come after.

## Features (first milestone)

- 🔎 **Privilege-free LAN discovery** — mDNS/DNS-SD, UPnP/SSDP, a bounded TCP sweep, and
  the OS ARP cache. No admin rights required for the default scan.
- 🏷️ **Auto-naming** — merges mDNS hostnames, UPnP friendly names, reverse-DNS, and MAC
  vendor (OUI) lookups into a stable display name you can override.
- 🔐 **SSH detection** — a fast, handshake-free banner probe distinguishes *port reachable*
  from *confirmed SSH*, and parses an OS hint from the banner.
- 📋 **One-click SSH command** — copies `ssh user@host` (with a heuristic, editable username)
  to your clipboard.
- ⬆️ **Auto-update** — the desktop app updates itself from GitHub Releases.

## Architecture

A single Cargo **workspace** with one package per shippable artifact, so the heavy desktop
GUI dependency tree never compiles into the lightweight CLI/daemon binaries.

```
crates/
  hlu-core/          # GUI-free domain model + persistence (shared by everything)
  hlu-discovery/     # async discovery + SSH-probe engine (tokio). No GUI deps.
  hlu-discover-cli/  # `hlu-discover` — standalone CLI over the engine
  hlu-desktop/       # Tauri 2 desktop app (Rust backend + React/TypeScript UI)
```

| Layer | Choice |
|---|---|
| Desktop shell | [Tauri 2](https://tauri.app) (Rust core + WebView) |
| Frontend | React + TypeScript + Vite |
| Async runtime | tokio |
| Auto-update | `tauri-plugin-updater` (GUI) · `dist` + `axoupdater` (CLI binaries) |

## Building from source

Prerequisites: a recent **Rust** stable toolchain (≥ 1.85 for edition 2024), **Node.js**
≥ 18, and the platform [Tauri prerequisites](https://tauri.app/start/prerequisites/)
(on Windows: WebView2, preinstalled on Windows 11).

```bash
# Rust workspace (libs + CLI)
cargo build --workspace

# Standalone discovery CLI
cargo run -p hlu-discover-cli

# Desktop app (dev)
cd crates/hlu-desktop
npm install
npm run tauri dev
```

> **Windows note:** Smart App Control may block freshly-compiled, unreputed build-script
> executables during the first Tauri build (`os error 4551`). Re-running the build, or
> `cargo clean -p <crate>` then rebuilding, usually lets it through once the reputation check
> clears. CI runners are unaffected.

## Releasing & auto-update

Push a tag (`git tag v0.1.0 && git push --tags`) to trigger
[`.github/workflows/release.yml`](.github/workflows/release.yml):

- The **desktop app** is built and bundled for Windows/macOS/Linux via `tauri-action` and
  attached to a draft GitHub Release.
- The **`hlu-discover` CLI** is built per-platform and attached to the same release.

Auto-update signing is intentionally deferred: enable it before public launch by generating
updater keys (`npm run tauri signer generate`), adding the public key + endpoint to
`tauri.conf.json`, setting `bundle.createUpdaterArtifacts = true`, and adding the private key
as a repo secret (see the comments in `release.yml`). Code-signing/notarization
(Apple Developer ID, Windows Authenticode) is a separate, later step.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

---

Made by [KodingKorp](https://github.com/KodingKorp).
