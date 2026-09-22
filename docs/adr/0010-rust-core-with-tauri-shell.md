---
status: accepted
date: 2026-09-16
---

# Rust core with a Tauri shell

Renumbered from 0001 on 2026-09-22: two ADRs carried that number, and the tamper-evidence decision keeps it because every later ADR cites it as 0001. This is the earliest decision of the project despite its number.

## Context

The product must ship first on macOS, be installable by non-technical users through a menu bar app, and later run on Windows and Linux without a rewrite. A native SwiftUI app would feel most at home on macOS but would need separate shells per platform. Electron would work everywhere but adds a large runtime to a security utility.

## Decision

The scanner, watcher, quarantine store, daemon and CLI are one Rust Cargo workspace. The menu bar app is a Tauri 2 shell over the same core. Only the OS integration layer (launchd, notarization, file-system watching specifics) is platform-specific.

## Consequences

- One language and one binary family across platforms; the portability constraint is honored from day one.
- The UI is a webview and will feel slightly less native than SwiftUI. Accepted for a security utility.
- Access to Apple-only APIs (on-device Foundation Models) needs a small Swift bridge if adopted.
