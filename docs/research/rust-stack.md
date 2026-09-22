# Rust stack for core, daemon, UI and release

Date: 2026-09-16
Ticket: `.scratch/ai-antivirus/issues/05-rust-stack.md`
Scope: maturity, platform coverage and gotchas of the building blocks named in ADR 0010 (Rust Cargo workspace: core scanner, CLI, launchd daemon; Tauri 2 menu bar app; macOS 14+ first, Windows/Linux later).

Method: primary sources only (crates.io API and docs.rs, crate repositories, v2.tauri.app and the tauri source tree, Apple developer docs and man pages, docs.brew.sh, systemd man sources, Microsoft Learn). Every claim carries its source inline. Items that could not be traced to a primary source are marked **UNVERIFIED** in place and collected at the end. Version numbers and dates are as of 2026-09-16.

Two sub-reports produced earlier today are folded in here and superseded: `rust-stack-partial-watch-hash-toolchain.md` (sections 1, 3, 4) and `rust-stack-partial-yara-x.md` (section 2).

Section map: 1 file watching, 2 YARA-compatible matching, 3 hashing, 4 toolchain, 5 Tauri baseline and macOS 14, 6 tray / menu-bar-only app, 7 notifications, 8 autostart, 9 IPC daemon to app/CLI, 10 launchd packaging, 11 signing and notarization in CI, 12 Homebrew cask, 13 Tauri updater, 14 systemd and Windows service equivalents, 15 portability matrix.

---

## 1. File watching: `notify` and `notify-debouncer-full`

**Maturity**
- `notify` stable is 8.2.0 (2025-08-03, MSRV 1.77, FSEvents via `fsevent-sys`). A 9.0.0 line has been in release candidates for eight months (9.0.0-rc.5, 2026-08-30, MSRV 1.88, `objc2` bindings, `Config::with_fsevent_latency`, per-path `watch_with`, `watched_paths`/`update_paths`, tokio and futures handlers, `EventKindMask` filtering). Actively maintained (commits 2026-09-14), CC0-1.0. Support policy is N-2 stable Rust and MSRV may bump in minor releases. https://crates.io/api/v1/crates/notify , https://raw.githubusercontent.com/notify-rs/notify/main/notify/CHANGELOG.md
- `notify-debouncer-full` 0.7.0 stable (2026-01-23); 0.8.0-rc.2 pairs with notify 9. https://crates.io/api/v1/crates/notify-debouncer-full

**Backends and recursion**
- Linux inotify; macOS FSEvents by default, kqueue behind the `macos_kqueue` feature; Windows `ReadDirectoryChangesW`; BSD kqueue; `PollWatcher` everywhere. https://raw.githubusercontent.com/notify-rs/notify/main/README.md
- Recursive watching is native on FSEvents and Windows. inotify and kqueue emulate it by walking the tree and adding one watch per directory (inotify) or per file (kqueue), with a documented race for files created before the new watch exists. https://man7.org/linux/man-pages/man7/inotify.7.html , https://docs.rs/notify/9.0.0-rc.5/notify/

**Many watched paths**
- inotify: `max_user_watches` defaults to 1% of RAM clamped to [8192, 1048576]; hitting it surfaces as `ErrorKind::MaxFilesWatch`; queue overflow becomes `Flag::Rescan`. https://man7.org/linux/man-pages/man7/inotify.7.html , https://docs.rs/notify/9.0.0-rc.5/notify/
- kqueue: one file descriptor per watched file. Issue #596 documents "Too many open files" at ~300 files with the default ulimit of 256; maintainers recommend FSEvents on macOS. https://github.com/notify-rs/notify/issues/596
- Windows: 16 KB event buffer; overflow becomes `Flag::Rescan`. https://docs.rs/notify/9.0.0-rc.5/notify/
- FSEvents: `KernelDropped`/`UserDropped` and `MustScanSubDirs` are mapped to `Rescan`. Issue #412 reports ~16% of 1500 individually watched files never firing on any OS (closed wontfix upstream). https://github.com/notify-rs/notify/issues/412
- Design consequence: every backend can emit `Flag::Rescan`, so the daemon needs a full-rescan path and must never assume event completeness. This is an independent argument for the daily scheduled full scan.

**FSEvents semantics (macOS)**
- notify creates the stream with `FileEvents | NoDefer | WatchRoot`, so file-level paths are delivered (not just directories); default latency is zero; `sinceWhen = SinceNow`, so nothing is replayed from before the watcher started and there is no catch-up after daemon downtime. notify spawns its own CFRunLoop thread; no run-loop plumbing is needed. https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html , https://raw.githubusercontent.com/notify-rs/notify/main/notify/CHANGELOG.md
- Atomic-save editors produce create-and-rename or truncate-and-write patterns; APFS clone/copy-on-write emits metadata events on the source; symlinks are followed by default; renames are paired by cookie on inotify but unpaired on kqueue. https://docs.rs/notify/9.0.0-rc.5/notify/

**Debouncing**
- `notify-debouncer-full` stitches rename pairs, dedups creates, drops modify-after-create, orders events: `new_debouncer(timeout, tick_rate, handler)`. On macOS and Windows the default `FileIdMap` stats and caches one entry per file in the watched tree at watch time (memory caveat inferred from source, **UNVERIFIED** as documented); `NoCache` opts out but loses rename stitching. https://raw.githubusercontent.com/notify-rs/notify/main/notify-debouncer-full/src/lib.rs

**macOS TCC**
- Desktop, Documents and Downloads prompt on first access and need `NS*FolderUsageDescription` keys. A headless launchd agent has no UI to prompt from, so watching those folders from the daemon fails silently unless access was granted. The agent config directories (`~/.claude`, `~/.codex`) sit in the home root, which is not TCC-protected. Whether `~/Library/Application Support` is exempt: **UNVERIFIED**. https://developer.apple.com/documentation/bundleresources/information-property-list/nsdesktopfolderusagedescription

**Verdict:** Use `notify` 8.x with the default FSEvents backend plus `notify-debouncer-full`, watch a handful of directory roots (never per-file watches), and treat `Rescan` as "run a full scan"; port to Linux/Windows needs no code change beyond inotify limit handling.

---

## 2. YARA-compatible matching: `yara-x` vs a hand-rolled engine

**Maturity**
- `yara-x` 1.20.0 (2026-08-24), roughly monthly minors; 1.0.0 declared stable and "ready for production use" on 2025-06-04, with classic YARA moved to maintenance mode. BSD-3-Clause, VirusTotal. https://crates.io/api/v1/crates/yara-x , https://virustotal.github.io/yara-x/blog/yara-x-is-stable/ , https://github.com/VirusTotal/yara
- MSRV 1.93.0 and moving fast (1.85 to 1.93 in 14 months), edition 2024. https://raw.githubusercontent.com/VirusTotal/yara-x/main/Cargo.toml

**Build footprint**
- Pure Rust, but rule conditions compile to WebAssembly executed by `wasmtime` 45.x, a non-optional dependency on native targets. A `pulley` feature swaps the Cranelift JIT for the Pulley interpreter, which matters under the hardened runtime where JIT needs an entitlement (see section 11). `parallel-compilation` is off by default. https://github.com/VirusTotal/yara-x/blob/main/lib/Cargo.toml
- The 17 default modules pull in crypto and parser crates; trim with `default-features = false, features = ["string-module","math-module","hash-module"]`. Dependencies include `regex`, `regex-automata`, `wasmtime`, `walrus`, `protobuf`, `daachorse`, `memchr`, `bstr`, `memmap2`.
- Size proxies: the prebuilt CLI is 7.74 MB compressed for aarch64-darwin; a third-party report puts the wasmtime/Cranelift runtime overhead near 14 MiB (https://github.com/KalarisLabs/Skill-Doctor/issues/42, anecdotal). Official build time and binary size: **UNVERIFIED**.

**API (docs.rs 1.20.0)**
- `Compiler::new().add_source(..).build() -> Rules`; `Scanner::new(&rules).scan(bytes)` or `scan_file(path)`; `set_timeout`, `max_scan_size`; `define_global`/`set_global` accept i64, f64, bool, str and `serde_json::Value`, so derived facts (file path, surface kind, parsed config) can be injected for rules to reference. `relaxed_re_syntax(true)` must be called before adding rules for classic-YARA regex escapes. https://docs.rs/yara-x/latest/yara_x/struct.Compiler.html , https://docs.rs/yara-x/latest/yara_x/struct.Scanner.html
- `Scanner` is not `Send`/`Sync`: one scanner per thread, reusable across files; `Rules` are shareable.
- Results expose `matching_rules()`, identifier, namespace, tags, `metadata` (Integer/Float/Bool/String/Bytes) and `Match::range/data`, so severity and category can ride in `meta:`.
- `Rules::serialize/deserialize` produce a blob with magic `YARA-X\0\0` and a serialization version (currently 6), tied to the embedded engine version; never deserialize third-party blobs. Native code is embedded only with `native-code-serialization`. Consequence: ship precompiled packs only together with the binary; ship the feed as source rules and compile at startup. https://docs.rs/yara-x/latest/yara_x/struct.Rules.html
- Differences from classic YARA: `{` must be escaped outside repetition, invalid escapes are errors, base64 patterns need at least 3 bytes, modifiers once each, new `with` statement, `.len()`. https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/

**Scanning text files**
- Matching is byte-based; useful modifiers for Markdown/JSON/scripts are `nocase`, `ascii`, `wide` (UTF-16LE), `base64`/`base64wide` (catches base64-smuggled instructions), `fullword`. https://virustotal.github.io/yara-x/docs/writing_rules/text-patterns/
- Regex engine: atom-prefiltered Pike VM plus a FastVM subset, parsed by `regex-syntax`; no backreferences or lookaround (inferred from the parser, **UNVERIFIED** as a documented statement). 4096-byte verify limit per direction from an atom.
- No json/yaml/toml/markdown module. Structural checks over MCP config JSON, hook commands and env secrets need a separate `serde_json`/`toml` layer in Rust that either feeds facts via `set_global` or post-filters. Relevant modules for text: `string`, `math` (entropy), `hash`, `time`.

**Performance**
- May 2026: `daachorse` replaced `aho-corasick`; YARA Forge over 24 GB ran in 26.2 s vs 48.3 s for classic YARA. 1.20.0 added SIMD pattern matching. For this workload (hundreds of small text files, tens to hundreds of rules) wasmtime startup and rule compilation dominate, not scanning; `native-code-serialization` avoids the Cranelift compile at load. https://virustotal.github.io/yara-x/blog/yara-x-just-got-faster/

**Alternatives**
- The older `yara` crate 0.32.0 (2026-04-28, community, Hugal31/yara-rust) binds libyara 4.5.x and needs a C toolchain, bindgen/LLVM and OpenSSL. yara-x is the forward path; official bindings exist for Rust (native), Python, Go and C. https://crates.io/crates/yara
- Hand-rolled: `regex` 1.13.1, `regex-automata` 0.4.18, `aho-corasick` 1.1.5, `daachorse` 5.0.0, `globset` 0.4.20. `RegexSet` reports which patterns matched, not offsets; counts, offsets, conditions and tooling would all be re-implemented and the DSL would be non-portable.
- Existing rule sets for this domain: Cisco skill-scanner (Apache-2.0) ships YAML plus YARA-X packs and depends on `yara-x>=1.10,<2` (https://github.com/cisco-ai-defense/skill-scanner); Cisco mcp-scanner uses custom YARA rules (https://github.com/cisco-ai-defense/mcp-scanner); NVIDIA SkillSpector has 71 patterns and 4 YARA signatures (https://github.com/NVIDIA/SkillSpector); Agent Threat Rules has 683 regex YAML rules with no YARA export but transpilable (https://github.com/Agent-Threat-Rule/agent-threat-rules); SYARA is YARA-like with semantic extensions and not runnable by yara-x (https://github.com/nabeelxy/syara); DataDog GuardDog is mostly Semgrep (https://github.com/DataDog/guarddog). No large canonical pure-YARA prompt-injection ruleset exists.

**Verdict:** Adopt `yara-x` for T1 rules (interoperable format, already used by Cisco's skill-scanner, VirusTotal-maintained), accept the wasmtime footprint, pin its fast-moving MSRV, and pair it with a small serde-based structural layer for JSON/TOML config checks; a hand-rolled DSL saves megabytes but forfeits community rules.

---

## 3. Content hashing: BLAKE3 vs SHA-256

- `blake3` 1.8.7 (2026-08-20), CC0/Apache-2.0, edition 2024, no official MSRV (CI on 1.85.1); NEON assumed on aarch64; `Hasher::update_reader`, `update_mmap`, `update_mmap_rayon`; `update_rayon` is slower below 128 KiB. Specified in C2SP, not a NIST standard. https://crates.io/api/v1/crates/blake3 , https://docs.rs/blake3/latest/blake3/struct.Hasher.html
- `sha2` 0.11.0 (2026-03-25, RustCrypto), MSRV 1.85, edition 2024; the `asm` features were removed and SHA-256 is hardware-accelerated by default via runtime detection (ARMv8 SHA2 extensions on Apple Silicon, SHA-NI on x86). Depends on `digest` 0.11 while much of the ecosystem still pins 0.10, so duplicate crate versions are likely. https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/README.md
- Interoperability: SHA-256 is what users verify with `shasum -a 256` and what public threat intel keys on (VirusTotal keying on SHA-256: **UNVERIFIED** against a VirusTotal doc). Numeric throughput comparison: **UNVERIFIED**.
- Gotcha: mmap-hashing a file that another process truncates concurrently can SIGBUS (relevant because agents write their own config files); **UNVERIFIED** as a documented warning, so prefer `update_reader` over mmap for files under a few MB.

**Verdict:** SHA-256 (`sha2`) is the canonical Trust and Allowlist hash for interoperability; BLAKE3 is optional for internal change detection only, and with agent config files being tiny the speed difference is irrelevant.

---

## 4. Rust toolchain

- Stable is 1.98.1 (2026-09-03, a miscompilation point release); 1.99.0 is scheduled for 2026-10-01. Edition 2024 has been the `cargo new` default since 1.85 (2025-02-20). https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/ , https://releases.rs/
- Surveyed MSRVs are all satisfied: notify 1.77 (8.x) / 1.88 (9.x), blake3 ~1.85, sha2 1.85, yara-x 1.93. Tauri's MSRV is in section 5.

**Verdict:** Pin `rust-version` in the workspace and a `rust-toolchain.toml` at 1.98.x; expect a bump every few months driven by yara-x.

---

## 5. Tauri 2 baseline and macOS 14 minimum

- Latest stable `tauri` is 2.11.5 (2026-07-01); a 3.0.0-alpha line started 2026-09-13 (alpha.1 2026-09-15) and `max_stable_version` is still 2.11.5. Minors have landed every 2-3 months (2.7.0 2025-07-20 through 2.11.0 2026-04-30) with patches every 1-4 weeks; no 2.x release since July, so v2 is entering maintenance while v3 is in alpha. https://crates.io/api/v1/crates/tauri , https://crates.io/api/v1/crates/tauri/versions
- MSRV of tauri 2.11.5 and of the plugins is Rust 1.77.2; the workspace MSRV will be dictated by yara-x (1.93), notify-rust (1.89) and tarpc (1.85) instead. https://crates.io/api/v1/crates/tauri/2.11.5 , https://v2.tauri.app/plugin/notification/
- Webviews: WRY drives WKWebView on macOS, WebView2 on Windows (preinstalled since Windows 10 1803), WebKitGTK 4.1 (>= 2.40) on Linux. https://github.com/tauri-apps/tauri/blob/dev/README.md , https://github.com/tauri-apps/wry/blob/dev/README.md , https://v2.tauri.app/start/prerequisites/
- macOS minimum: development needs macOS 10.15+; the runtime floor is `bundle.macOS.minimumSystemVersion`, which "Defaults to `10.13`", is written to `LSMinimumSystemVersion` in Info.plist and exported as `MACOSX_DEPLOYMENT_TARGET` by tauri-build and the CLI. Nothing in Tauri caps the value, so macOS 14 is supported as a minimum; the project must set `"minimumSystemVersion": "14.0"` explicitly, and the Homebrew cask's `depends_on macos: :sonoma` must agree with it (section 12). https://v2.tauri.app/reference/config/#minimumsystemversion , https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-bundler/src/bundle/macos/app.rs , https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-build/src/lib.rs , https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/LaunchServicesKeys.html

**Verdict:** Pin `tauri = "2.11"` (not the v3 alpha), set `minimumSystemVersion` to `14.0` explicitly, and plan for a v3 migration in 2027 since 2.x releases have stopped.

---

## 6. Tray icon / menu-bar-only app

- `TrayIconBuilder` needs the `tray-icon` Cargo feature (desktop only): `icon()`, `icon_as_template(true)` ("macOS only"; template images per Apple's `NSImage.isTemplate`), `menu()`, `tooltip()` (Linux unsupported), `title()` (Windows unsupported), `show_menu_on_left_click()` (default true, Linux unsupported), `on_menu_event()`, `on_tray_icon_event()`. Loading PNG icons needs the `image-png` feature. Tauri 2.11.5 depends on `tray-icon` 0.24. https://v2.tauri.app/learn/system-tray/ , https://docs.rs/tauri/latest/tauri/tray/struct.TrayIconBuilder.html , https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri/Cargo.toml
- Events: `TrayIconEvent::Click { position, rect, button, button_state }` plus `DoubleClick` (Windows only), `Enter`, `Move`, `Leave`; `TrayIcon::rect()` gives the icon bounds for anchoring a popover window. "Linux: Unsupported. The event is not emitted even though the icon is shown", and `rect()` always returns `None` on Linux, so a Linux port must rely on the context menu. https://docs.rs/tauri/latest/tauri/tray/enum.TrayIconEvent.html , https://docs.rs/tauri/latest/tauri/tray/struct.TrayIcon.html
- Hiding the Dock icon: `tauri::ActivationPolicy::{Regular, Accessory, Prohibited}`; `App::set_activation_policy` at setup and `AppHandle::set_activation_policy` at runtime (added by PR #9842 so a settings window can flip to `Regular` and back), plus `set_dock_visibility(bool)`. Alternatively `LSUIElement = true` in an `Info.plist` next to `tauri.conf.json`, which Tauri merges (`bundle.macOS.infoPlist`). https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-runtime/src/lib.rs , https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri/src/app.rs , https://github.com/tauri-apps/tauri/pull/9842 , https://v2.tauri.app/reference/config/
- `app.macOSPrivateApi` (Cargo feature `macos-private-api`) only enables transparent windows and fullscreen prefs; not needed for a plain popover. https://v2.tauri.app/reference/config/
- Open issues to test early on macOS 14+: #15005 "Dock icon visible when app installed from .app bundle, but not in dev mode" (opened 2026-02-26, open: `LSUIElement`, `Accessory`, `Prohibited` and `set_dock_visibility(false)` all reported failing when launched via Launch Services); #12128 deep links re-show the Dock icon under Accessory (open); #15017 tao unconditionally calls `activateIgnoringOtherApps` at launch (PR #15223 pending); #5122 `set_activation_policy` broke `window.show()` in 1.x (fixed). A Tauri 2 issue about Accessory windows losing keyboard focus: **UNVERIFIED** (none found; mitigate with `window.set_focus()` or a runtime flip to `Regular`). https://github.com/tauri-apps/tauri/issues/15005 , https://github.com/tauri-apps/tauri/issues/12128 , https://github.com/tauri-apps/tauri/issues/15017 , https://github.com/tauri-apps/tauri/issues/5122
- Linux needs `libayatana-appindicator3-dev` or `libappindicator3-dev` (the tray-icon crate also has a `ksni` StatusNotifierItem backend; tray under Flatpak is issue #13599); the GNOME shell-extension requirement is **UNVERIFIED** against a Tauri source. Windows works natively. On macOS the tray must be created on the main thread. https://v2.tauri.app/start/prerequisites/ , https://github.com/tauri-apps/tray-icon , https://github.com/tauri-apps/tauri/issues/11293

**Verdict:** Tauri 2's tray plus `ActivationPolicy::Accessory` (with `LSUIElement` as belt and braces) gives a menu-bar-only app, but issue #15005 means the installed-bundle Dock-hiding path must be verified in the first spike, and the Linux port gets a menu-only tray with no click events.

---

## 7. Notification plugin

- `tauri-plugin-notification` 2.4.0 (2026-08-31; 3.0.0-alpha.0 exists), MSRV 1.77.2. Rust API `app.notification().builder().title(..).body(..).show()`; capability `notification:default`. Windows: "Only works for installed apps. Shows powershell name & icon in development." https://crates.io/api/v1/crates/tauri-plugin-notification/2.4.0 , https://v2.tauri.app/plugin/notification/
- "The Actions API is only available on mobile platforms": no click or action callbacks on macOS, Windows or Linux, so a notification cannot open the Finding directly; the tray window has to be the landing point. https://v2.tauri.app/plugin/notification/
- Underlying stack: `notify-rust` 4.11 (latest 4.18.0, 2026-06-16, MSRV 1.89) on all desktops, which wraps `mac-notification-sys` 0.6.15 on macOS ("A very thin wrapper around NSNotifications", still on the deprecated `NSUserNotification` API with a TODO to move to `UserNotifications`) and `tauri-winrt-notification` on Windows. https://raw.githubusercontent.com/tauri-apps/plugins-workspace/v2/plugins/notification/Cargo.toml , https://raw.githubusercontent.com/hoodie/notify-rust/main/Cargo.toml , https://github.com/h4llow3En/mac-notification-sys
- macOS dev vs release: the plugin calls `notify_rust::set_application("com.apple.Terminal")` under `tauri::is_dev()` and the app's own `identifier` otherwise, so release notifications need a bundled, Launch Services-registered app with that identifier (inferred from code: **UNVERIFIED** as a documented statement; issue #2143 "Notifications not working in MacOS" remains open). https://raw.githubusercontent.com/tauri-apps/plugins-workspace/v2/plugins/notification/src/desktop.rs , https://github.com/tauri-apps/plugins-workspace/issues/2143
- Consequence for the daemon: the launchd agent has no bundle identity of its own, so notifications should be raised by the Tauri app (or the CLI printing to the terminal), with the daemon pushing Findings over IPC (section 9).

**Verdict:** Use the plugin for fire-and-forget alerts from the app process only; do not design UX around notification clicks, and treat the deprecated `NSUserNotification` backend as a known debt to swap for a small `UserNotifications` bridge if Apple removes it.

---

## 8. Autostart plugin

- `tauri-plugin-autostart` 2.5.1 (2025-10-27), MSRV 1.77.2; `init(MacosLauncher::LaunchAgent | AppleScript, Some(args))`, `enable()`/`disable()`/`is_enabled()`, permissions `autostart:allow-enable` etc. https://crates.io/api/v1/crates/tauri-plugin-autostart/2.5.1 , https://v2.tauri.app/plugin/autostart/
- Mechanism (underlying `auto-launch` 0.6.0, 2026-01-10): macOS writes a plist to `~/Library/LaunchAgents/` (default) or adds a login item via AppleScript (only `--hidden`/`--minimized` args work); `auto-launch` also lists an SMAppService mode which the Tauri plugin does not expose; Windows writes `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`; Linux writes an XDG `~/.config/autostart/*.desktop`. The plugin derives the `.app` bundle path from the running executable and registers only the UI app. https://raw.githubusercontent.com/tauri-apps/plugins-workspace/v2/plugins/autostart/src/lib.rs , https://github.com/zzzgydi/auto-launch/blob/main/README.md
- Gotcha: with `MacosLauncher::LaunchAgent` the UI app gets its own `~/Library/LaunchAgents` plist alongside the daemon's SMAppService registration, so the user sees two Login Items entries and the cask's `uninstall launchctl:` must list both labels. Registering the app itself through `SMAppService.mainApp` (`objc2-service-management`, section 10) avoids the extra plist.

**Verdict:** Fine for the UI app, but since the daemon already needs `SMAppService`, register the app as a login item through the same binding and skip the plugin on macOS; keep the plugin for the Windows Run key and Linux XDG autostart later.

---

## 9. IPC between the daemon and the app / CLI

**Transport**
- Unix domain sockets on macOS/Linux via `tokio::net::UnixListener` (tokio 1.53.1, 2026-07-20, MSRV 1.71); Windows named pipes via `tokio::net::windows::named_pipe::ServerOptions` (`create`, `create_with_security_attributes_raw`, names like `\\.\pipe\name`). The socket file is not removed on close ("unlink(2) must be used"), so the daemon must unlink stale sockets at start. https://docs.rs/tokio/latest/tokio/net/struct.UnixListener.html , https://docs.rs/tokio/latest/tokio/net/windows/named_pipe/struct.ServerOptions.html , https://keith.github.io/xcode-man-pages/unix.4.html
- `interprocess` 2.4.4 (2026-09-03, MSRV 1.75, `tokio` feature, Windows/Linux/macOS tier-1) abstracts both as "local sockets": `ListenerOptions::new().name(..).mode(0o600).create_tokio()`, names via `GenericFilePath` (verbatim path or `\\.\pipe\..`) or `GenericNamespaced` (Windows: prepends `\\.\pipe\`; Linux: abstract namespace; other Unices including macOS: "Resolves to filesystem paths by prepending `/tmp/`"). `mode()` "will authenticate clients using their process credentials according to the write bits of the mode". Built-in `PeerCreds` gives `pid`/`euid`/`egid` on Windows, Linux and Darwin. https://crates.io/api/v1/crates/interprocess/2.4.4 , https://github.com/kotauskas/interprocess/blob/main/README.md , https://docs.rs/interprocess/latest/interprocess/local_socket/struct.ListenerOptions.html
- Path length: `sun_path` is 104 bytes on macOS ("at most 104 characters", xnu `bsd/sys/un.h`) and 108 on Linux. `~/Library/Application Support/<bundle id>/daemon.sock` can exceed that for long usernames; place the socket under `$TMPDIR` (per-user, 0700) or a short `~/Library/Caches/<short>/` path and assert the length at startup. https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/un.h , https://man7.org/linux/man-pages/man7/unix.7.html

**RPC layer**
- `tarpc` 0.38.0 (2026-08-12, MSRV 1.85, Google): transport-agnostic ("any type implementing `Stream<Item = Request> + Sink<Response>`"), with `serde_transport` = `tokio_serde::Framed<Framed<S, LengthDelimitedCodec>, ..>` over any `AsyncRead + AsyncWrite`, so a `UnixStream`, named pipe or interprocess stream plugs in directly with JSON or bincode. https://crates.io/api/v1/crates/tarpc/0.38.0 , https://raw.githubusercontent.com/google/tarpc/master/tarpc/src/serde_transport.rs
- Lighter: `tokio_util::codec::LengthDelimitedCodec` (u32 big-endian prefix, 8 MB default frame cap; tokio-util 0.7.19) plus `serde_json`. Heavier: `tonic` 0.14.6 gRPC over UDS (`serve_with_incoming(UnixListenerStream)`), Unix-only example. https://docs.rs/tokio-util/latest/tokio_util/codec/length_delimited/index.html , https://github.com/hyperium/tonic/blob/master/examples/src/uds/server.rs

**Peer authentication**
- Linux `SO_PEERCRED` returns pid/uid/gid of the peer at connect time. macOS `getpeereid(3)` returns effective uid/gid ("This mechanism is reliable"), implemented over `LOCAL_PEERCRED`; `LOCAL_PEERPID`/`LOCAL_PEEREPID` give the peer PID. Windows: `GetNamedPipeClientProcessId`, and the pipe DACL should use the logon SID because the default descriptor "grant[s] read access to members of the Everyone group and the anonymous account". https://man7.org/linux/man-pages/man7/unix.7.html , https://man.freebsd.org/cgi/man.cgi?query=getpeereid&sektion=3 , https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid , https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- Directory 0700 plus socket 0600 is standard practice, not a quoted requirement.

**Sidecars are not daemons**
- `bundle.externalBin` sidecars launched via `tauri-plugin-shell` are children of the UI process; the shell plugin kills every tracked child on `RunEvent::Exit`, so a sidecar cannot replace the launchd agent (it is still the right way to get the daemon binary signed and bundled, section 10). https://v2.tauri.app/develop/sidecar/ , https://raw.githubusercontent.com/tauri-apps/plugins-workspace/v2/plugins/shell/src/lib.rs

**Verdict:** Daemon listens on a 0600 Unix socket under `$TMPDIR` (named pipe with logon-SID DACL on Windows) via `interprocess` with tokio, verifies the peer uid with `PeerCreds`, and speaks a length-prefixed serde protocol (`tarpc` if typed RPC is wanted, `LengthDelimitedCodec` + JSON if not); the Tauri app and CLI are both plain clients.

---

## 10. launchd LaunchAgent packaging and installation from the app

**Plist keys** (`man 5 launchd.plist`, https://keith.github.io/xcode-man-pages/launchd.plist.5.html ; quotes checked against the local man page on macOS 26.6)
- `Label` (required), `Program`/`ProgramArguments` (absolute path) or `BundleProgram` ("an app-bundle relative path to the executable for the job. This key is only supported for plists that are installed using SMAppService").
- `RunAtLoad` defaults to false and the man page says it "should be avoided, as speculative job launches have an adverse effect on system-boot and user-login scenarios". `KeepAlive` may be `true` or a dict of `SuccessfulExit`, `Crashed`, `PathState`, `OtherJobEnabled`; `SuccessfulExit` implies `RunAtLoad`.
- `ThrottleInterval` defaults to 10 s between spawns. `ProcessType` `Background` applies background resource limits and is "preferable to using the HardResourceLimits, SoftResourceLimits and Nice keys"; if unspecified the system already throttles CPU and I/O. `LowPriorityIO`, `Nice`, `StandardOutPath`/`StandardErrorPath`, `EnvironmentVariables` (strings only), `MachServices`, `LimitLoadToSessionType` (agents only). `WatchPaths` is "highly discouraged, as filesystem event monitoring is highly race-prone", so watching stays inside the daemon (section 1).
- `AssociatedBundleIdentifiers`: a legacy plist installed by an app should carry the app's bundle id so the Login Items UI attributes it.

**launchctl** (`man 1 launchctl`, https://keith.github.io/xcode-man-pages/launchctl.1.html)
- Modern: `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/<label>.plist`, `launchctl bootout gui/$(id -u)/<label>`, `enable`/`disable` (persistent), `kickstart -k gui/$(id -u)/<label>` (restart), `print gui/$(id -u)/<label>` (status; "This output is NOT API in any sense at all"). `load`/`unload` are listed under legacy subcommands.

**SMAppService (macOS 13+)** https://developer.apple.com/documentation/servicemanagement/smappservice
- "In macOS 13 and later, use SMAppService to register and control LoginItems, LaunchAgents, and LaunchDaemons as helper executables for your app." `SMAppService.agent(plistName:)` requires the plist in `Contents/Library/LaunchAgents` of the app bundle; the plist uses `BundleProgram` relative to the bundle (e.g. `Contents/MacOS/<daemon>`); `register()`, `unregister()`, `status`, `openSystemSettingsLoginItems()`. https://developer.apple.com/documentation/servicemanagement/smappservice/agent(plistname:) , https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos
- User-facing behaviour: "Your app will be allowed to launch at login by default, and users will be notified"; clicking the notification opens Login Items; "you don't need to use an installer to write launch agents or create cleanup scripts anymore". https://developer.apple.com/videos/play/wwdc2022/10096/ . Items appear under System Settings > General > Login Items; MDM can pre-approve; macOS 14 adds a declarative status report for background tasks; macOS 26 prompts the user when background tasks outlive the app. https://support.apple.com/guide/deployment/manage-login-items-background-tasks-mac-depdca572563/web
- Rust binding: `objc2-service-management` 0.3.2 (2025-10-04, madsmtm/objc2) exposes `SMAppService` (`agentServiceWithPlistName`, `registerAndReturnError`, `unregisterAndReturnError`, `status`, `openSystemSettingsLoginItems`) behind the `objc2` and `SMAppService` features. https://crates.io/api/v1/crates/objc2-service-management , https://docs.rs/objc2-service-management/latest/objc2_service_management/struct.SMAppService.html
- `register()` bootstraps a LaunchAgent immediately and on every later login for that user; `status` returns `notRegistered`, `enabled`, `requiresApproval` ("the user needs to take action in System Settings before the service is eligible to run", also returned after the user revokes consent) or `notFound`; `unregister()` terminates a running agent. The app must check status at launch and call `openSystemSettingsLoginItems()` when approval is missing. https://developer.apple.com/documentation/servicemanagement/smappservice/register() , https://developer.apple.com/documentation/servicemanagement/smappservice/status-swift.enum/requiresapproval
- Trade-off: SMAppService keeps plist and daemon inside the code-signed bundle ("neither the system nor a third party can modify without breaking the code signature"; Homebrew/updater replacing the .app keeps the path valid); after the app is deleted the Login Items entry "may remain visible ... for some time" until overnight maintenance removes it. A legacy `~/Library/LaunchAgents` plist must use `Program` (not `BundleProgram`), needs `AssociatedBundleIdentifiers` and a matching Team ID, and leaves a file behind on uninstall unless the cask's `uninstall launchctl:`/`zap` removes it. https://developer.apple.com/documentation/servicemanagement/updating-your-app-package-installer-to-use-the-new-service-management-api . Exact wording of the background-items notification and the macOS 15 panel name "Login Items & Extensions": **UNVERIFIED** (forum threads only).
- Shipping the daemon and CLI as Tauri `bundle.externalBin` sidecars gets them copied into `Contents/MacOS`, signed with the same identity and hardened runtime, and covered by notarization automatically (section 11). https://v2.tauri.app/develop/sidecar/
- The daemon binary inside the bundle must be signed with the same Developer ID, hardened runtime and secure timestamp as the app for notarization ("Enable code-signing for all of the executables you distribute", "Enable the Hardened Runtime capability for your app and command line targets"). Tauri signs sidecars and frameworks "inside out" before the app (section 11). https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution

**Verdict:** Register the daemon with `SMAppService` via `objc2-service-management` and a `BundleProgram` plist in `Contents/Library/LaunchAgents`, with `KeepAlive` and `ProcessType=Background`; keep a `launchctl bootstrap` fallback for the CLI-only install path.

---

## 11. Code signing and notarization of a Tauri app in GitHub Actions (`tauri-action`)

**Tauri macOS signing** https://v2.tauri.app/distribute/sign/macos/
- Needs a "Developer ID Application" certificate (Account Holder only); free accounts cannot notarize; "Notarization is required when using a Developer ID Application certificate."
- Signing env: `APPLE_SIGNING_IDENTITY`, `APPLE_CERTIFICATE` (base64 `.p12`), `APPLE_CERTIFICATE_PASSWORD`; or `bundle.macOS.signingIdentity`.
- Notarization env: App Store Connect API key `APPLE_API_ISSUER`, `APPLE_API_KEY`, `APPLE_API_KEY_PATH` (preferred for CI), or Apple ID `APPLE_ID`, `APPLE_PASSWORD` (app-specific), `APPLE_TEAM_ID`. `--skip-stapling` exists for the slow first pass. Ad-hoc identity `-` signs but does not satisfy Gatekeeper.
- Config: `bundle.macOS.hardenedRuntime` defaults to `true`; `bundle.macOS.entitlements`, `providerShortName`, `minimumSystemVersion` (default `"10.13"`, written to `LSMinimumSystemVersion`; set `"14.0"`); `bundle.targets` accepts `"app"` and `"dmg"`; `bundle.externalBin` for sidecars named `<name>-<target-triple>`. https://v2.tauri.app/reference/config/ , https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-bundler/src/bundle/macos/app.rs , https://v2.tauri.app/develop/sidecar/

**What the bundler does** (tauri `dev` branch)
- Copies frameworks and sidecars, signs them first ("per apple, signing must be done inside out"), then the app; runs notarization automatically when the env vars resolve (`APPLE_TEAM_ID` missing is a hard error), zipping with `ditto -c -k --keepParent --sequesterRsrc`, `xcrun notarytool submit --wait`, then `xcrun stapler staple`. https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-bundler/src/bundle/macos/app.rs , https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-macos-sign/src/lib.rs
- The codesign call is `codesign --force -s <id> [--options runtime] [--entitlements ..]` with no explicit `--timestamp`; `man codesign` says the default "may result in some but not all code being signed with a timestamp". Whether Tauri output always carries the secure timestamp notarization demands: **UNVERIFIED**; verify in CI with `codesign -dvv` (look for `Timestamp=`). https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-macos-sign/src/keychain.rs , https://developer.apple.com/documentation/security/resolving-common-notarization-issues
- DMG: built by the bundled `bundle_dmg.sh`, then code-signed, but **not** notarized or stapled itself; only the .app inside is. Gatekeeper still finds the app's ticket online or stapled. Add a post-step `xcrun notarytool submit x.dmg --wait && xcrun stapler staple x.dmg` if offline first-launch matters. Icon positions are not applied when building DMGs on CI. https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-bundler/src/bundle/macos/dmg/mod.rs , https://v2.tauri.app/distribute/dmg/ , https://developer.apple.com/documentation/security/customizing-the-notarization-workflow
- **Corrected 2026-09-21** (see `macos-first-run-permissions.md` section 8 and `yara-x-pulley-benchmark.md`): `allow-jit` does not work, because wasmtime 45 does not use `MAP_JIT`; only `allow-unsigned-executable-memory` lets the JIT run. v1 builds yara-x with the `pulley` feature and ships with no entitlement. Original note follows.
- JIT note: yara-x's Cranelift JIT under the hardened runtime needs `com.apple.security.cs.allow-jit` in the entitlements, or the `pulley` feature (section 2). Entitlement requirement: **UNVERIFIED** against a yara-x doc; Apple documents the entitlement itself.

**tauri-action** https://github.com/tauri-apps/tauri-action
- Latest release action-v1.0.0 (2026-06-29); v1 drops Tauri v1, appends the app version to `.app.tar.gz`/`.sig`, and `latest.json` uses GitHub URLs. https://api.github.com/repos/tauri-apps/tauri-action/releases
- README matrix: `macos-latest` with `--target aarch64-apple-darwin` and `--target x86_64-apple-darwin`, `ubuntu-22.04`, `windows-latest`; `GITHUB_TOKEN` required. Inputs: `tagName`, `releaseName`, `releaseBody`, `releaseDraft`, `prerelease`, `uploadUpdaterJson` (default true; note the name is not `includeUpdaterJson`), `updaterJsonPreferNsis`, `updaterJsonKeepUniversal`, `uploadUpdaterSignatures` (default true), `uploadPlainBinary`, `args`, `projectPath`, `releaseAssetNamePattern`; `.app.tar.gz` upload is inferred from Tauri producing it under `bundle.createUpdaterArtifacts` (the README does not list the extension: **UNVERIFIED** verbatim). https://raw.githubusercontent.com/tauri-apps/tauri-action/dev/action.yml Updater signing env `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. Apple `APPLE_*` vars are passed through `env:` to the bundler. Uploads `.dmg`, `.app.tar.gz`, `.sig` and `latest.json` to the release. https://raw.githubusercontent.com/tauri-apps/tauri-action/dev/README.md

**Apple requirements**
- Developer ID cert, hardened runtime, secure timestamp, no `get-task-allow`, every nested executable signed; notarytool only since 2023-11-01 (altool retired); notarizable: apps, non-app bundles, UDIF disk images, flat installer packages; tickets are generated for each nested file; "Limit notarizations to 75 per day." https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution , https://developer.apple.com/documentation/security/customizing-the-notarization-workflow , https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool
- Apple Developer Program is 99 USD per year; notarization is a paid-membership feature. https://developer.apple.com/programs/enroll/ , https://developer.apple.com/support/compare-memberships/

**Windows and Linux**
- Windows: OV or EV Authenticode cert (OV "generally cheaper and available to individuals"; both build SmartScreen reputation since 2024), `bundle.windows.certificateThumbprint`/`digestAlgorithm`/`timestampUrl`, `bundle.windows.signCommand` for external tools, Azure Artifact Signing documented; SmartScreen warns until reputation accrues. https://v2.tauri.app/distribute/sign/windows/
- Linux: no signing step for AppImage/deb; build on the oldest supported base with WebKitGTK 4.1 (Ubuntu 22.04 / Debian 12); AppImages are 70+ MB vs 2-6 MB deb/rpm; RPM signing optional via `TAURI_SIGNING_RPM_KEY`. https://v2.tauri.app/distribute/appimage/ , https://v2.tauri.app/distribute/rpm/

**Verdict:** `tauri-action@v1` on `macos-latest` with the six `APPLE_*` secrets (API-key flavour) plus `TAURI_SIGNING_*` yields a signed, notarized, stapled .app and a signed DMG in one job; add a DMG staple step and a `codesign -dvv` timestamp assertion, and budget the 99 USD/year Developer ID enrollment as a hard prerequisite.

---

## 12. Homebrew cask publishing

- Notability for homebrew/cask: "at least 30 forks, 30 watchers or 75 stars", or "at least 90 forks, 90 watchers or 225 stars for a self-submission by the repository owner"; repositories under 30 days old are normally ineligible. https://docs.brew.sh/Package-Acceptance-Policy , https://docs.brew.sh/Acceptable-Casks
- Gatekeeper: artefacts "must pass Homebrew's Gatekeeper checks and must not require System Integrity Protection or Gatekeeper to be disabled or bypassed"; Homebrew applies quarantine attributes and audits casks on a default macOS configuration, and removes casks that fail. A Developer ID-signed and notarized app is therefore required in practice (the word "notarized" is not in the rule text: **UNVERIFIED** as a literal requirement, inferred). https://docs.brew.sh/Acceptable-Casks , https://docs.brew.sh/Homebrew-Security-and-Supply-Chain
- Command-line-only open source belongs in homebrew/core as a formula; a cask ships the app and can expose the CLI via `binary "#{appdir}/X.app/Contents/MacOS/x-cli"`. https://docs.brew.sh/Acceptable-Casks , https://docs.brew.sh/Cask-Cookbook
- Cookbook stanzas relevant here: `app`, `binary`, `auto_updates true` (when the app has a built-in updater), `depends_on macos: :sonoma` (symbol form; `brew audit --online` cross-checks `LSMinimumSystemVersion`), `livecheck` (prefer the `Git` strategy over `GithubLatest`), `uninstall launchctl: "<label>"` and `quit:`, `zap trash:` for `~/Library/LaunchAgents`, `Application Support`, `Caches`, `Logs`, `Preferences`; `url` with interpolated `version` and `sha256` from `shasum -a 256`. https://docs.brew.sh/Cask-Cookbook , https://docs.brew.sh/Brew-Livecheck
- Personal tap: `brew tap <user>/tap` maps to `github.com/<user>/homebrew-tap`; no acceptance policy, but "Code in a tap can run with your user's privileges". https://docs.brew.sh/Taps
- Windows winget: PR to microsoft/winget-pkgs, HTTPS installer from the publisher's site, hash match, silent install, AV scan of every submission; tools that trip PUA heuristics are not allowed, which is a live risk for a scanner product. No literal Authenticode requirement, but SmartScreen makes it advisable. https://learn.microsoft.com/en-us/windows/package-manager/package/repository , https://learn.microsoft.com/en-us/windows/package-manager/package/windows-package-manager-policies
- Linux: deb/rpm/AppImage from Tauri; `cargo install` for the CLI. https://doc.rust-lang.org/cargo/commands/cargo-install.html

**Verdict:** Start with a personal tap (`brew tap <org>/tap`) from the first notarized release and apply to homebrew/cask once the repo passes the 75-star or 90/225 self-submission bar; the cask needs `depends_on macos: :sonoma`, `uninstall launchctl:` for the agent label and a `zap` block.

---

## 13. Tauri updater plugin and its signing key

- `tauri-plugin-updater` 2.11.0 (2026-08-31; 3.0.0-alpha.0 exists), MSRV 1.77.2, default features `rustls-tls`, `system-proxy`, `zip`; Windows, Linux, macOS. https://crates.io/api/v1/crates/tauri-plugin-updater/2.11.0 , https://v2.tauri.app/plugin/updater/
- Keys: `cargo tauri signer generate -w ~/.tauri/<app>.key`; CI exports `TAURI_SIGNING_PRIVATE_KEY` (path or content) and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`; `plugins.updater.pubkey` holds the public key content; `bundle.createUpdaterArtifacts: true` ("will be removed in v3"). Signatures are minisign (`minisign-verify` 0.2 in the plugin). https://v2.tauri.app/plugin/updater/ , https://raw.githubusercontent.com/tauri-apps/plugins-workspace/v2/plugins/updater/Cargo.toml
- Artifacts: macOS `<app>.app.tar.gz` + `.sig`; Windows NSIS `.exe`/`.msi` + `.sig`; Linux `.AppImage` + `.sig`. `latest.json`: `version`, optional `notes`, `pub_date` (RFC 3339), `platforms.{darwin-aarch64, darwin-x86_64, windows-x86_64, linux-x86_64}.{url, signature}` (signature is file content, not a path). Endpoints support `{{current_version}}`, `{{target}}`, `{{arch}}`; TLS enforced in production; a dynamic server answers 200 or 204. tauri-action uploads the manifest (`uploadUpdaterJson`, section 11). https://v2.tauri.app/plugin/updater/
- Rust: `app.updater()?.check().await?` then `download_and_install` and `app.restart()`; on Windows "the application is automatically exited when the install step is executed". https://v2.tauri.app/plugin/updater/
- Writable location: not documented on the page. PR #2067 (updater 2.5.0, 2025-02-02) added an admin-prompt fallback via AppleScript when `/Applications/<App>.app` is not writable; issue #2455 (temp dir needs admin) is still open. https://github.com/tauri-apps/plugins-workspace/pull/2067 , https://github.com/tauri-apps/plugins-workspace/issues/2455
- Homebrew interplay: Tauri says nothing; Homebrew's `auto_updates true` stanza exists precisely for self-updating apps, and a cask-installed `.app` in `/Applications` is a normal bundle. Official Tauri support for cask-installed self-update: **UNVERIFIED**. A self-updated app drifts from the cask's recorded version until `brew upgrade` runs, which is the normal state for `auto_updates` casks. https://docs.brew.sh/Cask-Cookbook
- Key custody: the minisign private key is the single point of trust for updates; keep it and the rule-feed signing key (ticket 15) as separate GitHub Actions secrets with the passwords set, and document rotation (a rotated pubkey needs one release signed by the old key that carries the new one).

**Verdict:** Ship the updater from v1 with `createUpdaterArtifacts: true`, `latest.json` on GitHub releases via tauri-action and `auto_updates true` in the cask; it replaces the whole `.app`, so the SMAppService-registered daemon inside the bundle updates atomically with it, and the app should re-`register()` after restart to be safe.

---

## 14. systemd user service and Windows service equivalents

**Linux (systemd --user)**
- Unit path `~/.config/systemd/user/<name>.service` (or `$XDG_CONFIG_HOME/systemd/user`). `[Install] WantedBy=default.target` ("the main target of the user service manager, started by default when the service manager is invoked"). `Restart=on-failure` restarts on non-zero exit, signal, timeout or watchdog; `RestartSec` defaults to 100 ms. `systemctl --user enable --now <unit>`. `loginctl enable-linger <user>` keeps the user manager alive without a login session. https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html , https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html , https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html , https://www.freedesktop.org/software/systemd/man/latest/systemctl.html , https://www.freedesktop.org/software/systemd/man/latest/loginctl.html (man sources read from https://github.com/systemd/systemd/tree/main/man because freedesktop.org blocks automated fetches)

**Windows**
- `windows-service` 0.8.1 (2026-05-08, Mullvad) implements and manages Windows services. https://crates.io/api/v1/crates/windows-service , https://github.com/mullvad/windows-service-rs
- Services run in Session 0 under LocalSystem/LocalService/NetworkService or a service account and "cannot directly interact with a user"; Microsoft recommends a per-user helper started with `CreateProcessAsUser` talking to the service over named pipes. A per-user scanner that reads `%USERPROFILE%\.claude` is closer to a Task Scheduler logon task (`schtasks /create /sc onlogon /tn <name> /tr <exe>`, runs as the current user by default, `/rl LIMITED`, `/delay`) or a worker hosted by the tray app. LocalSystem is "not associated with any logged-on user account", so `HKEY_CURRENT_USER` and `%USERPROFILE%` resolve to the default user unless the service impersonates. Programmatically, the Task Scheduler COM API creates a `TASK_TRIGGER_LOGON` trigger with `UserId` set. Rust access to that COM API via the `windows` crate: **UNVERIFIED** (no primary-source example found). https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account , https://learn.microsoft.com/en-us/windows/win32/taskschd/logon-trigger-example--scripting- https://learn.microsoft.com/en-us/windows/win32/services/interactive-services , https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts , https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page , https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create

**Cross-platform abstraction**
- `service-manager` 0.11.0 (2026-02-18, chipsenkbeil) covers launchd, systemd, OpenRC, rc.d, sc.exe and WinSW with `ServiceLevel::User` for launchd and systemd; launchd restart policy is only Never vs Always (KeepAlive boolean), it writes legacy `~/Library/LaunchAgents` plists and calls `launchctl` (not SMAppService), and an sc.exe-installed binary must itself speak the SCM protocol via `windows-service`. The `ServiceInstallCtx` field set differs between README and docs.rs (`restart_policy` vs `disable_restart_on_failure`): **UNVERIFIED** for 0.11.0. https://crates.io/api/v1/crates/service-manager , https://docs.rs/service-manager/latest/service_manager/

**Verdict:** The daemon's "install me" abstraction should be `enum Supervisor { LaunchAgent(SMAppService), SystemdUser, WindowsLogonTask }`; `service-manager` is a fine fallback for Linux and the CLI path but not a substitute for SMAppService on macOS or for a per-user task on Windows.

---

## 15. Portability matrix

| Block | macOS 14+ (v1) | Windows | Linux | Notes |
|---|---|---|---|---|
| 1 File watching (`notify`) | FSEvents, recursive native, file-level paths | ReadDirectoryChangesW, recursive native, 16 KB buffer overflow -> Rescan | inotify, recursion emulated per directory, `max_user_watches` -> `MaxFilesWatch` | Same code; all backends can emit `Rescan`. Sec. 1 |
| 2 YARA-X | Pure Rust, wasmtime JIT (needs JIT entitlement under hardened runtime or `pulley`) | Pure Rust | Pure Rust | Same rules and code everywhere. Sec. 2 |
| 3 Hashing (`sha2`, `blake3`) | Hardware SHA-256 on Apple Silicon | SHA-NI | SHA-NI / NEON | Pure Rust. Sec. 3 |
| 4 Toolchain | 1.98.1 | 1.98.1 | 1.98.1 | MSRV driven by yara-x 1.93. Sec. 4 |
| 5 Tauri 2 shell | WKWebView, `minimumSystemVersion` 14.0 | WebView2 (Win10 1803+) | WebKitGTK 4.1 (Ubuntu 22.04+) | Sec. 5 |
| 6 Tray / menu-bar-only | Tray + `Accessory` policy; issue #15005 to verify | Native tray, no Dock concept | appindicator tray, menu only, no click events or `rect()` | Sec. 6 |
| 7 Notifications | `notify-rust` -> `NSUserNotification` (deprecated API), no click callbacks | WinRT toasts, installed apps only | D-Bus, no click callbacks | Sec. 7 |
| 8 Autostart (UI app) | LaunchAgent plist or SMAppService `mainApp` | HKCU Run key | XDG autostart | Sec. 8 |
| 9 Daemon IPC | Unix socket, `getpeereid`, 104-byte path limit | Named pipe, logon-SID DACL, `GetNamedPipeClientProcessId` | Unix socket, `SO_PEERCRED`, abstract namespace available | `interprocess` covers all three. Sec. 9 |
| 10/14 Daemon supervisor | SMAppService LaunchAgent (`BundleProgram`), `objc2-service-management` | Per-user Task Scheduler logon task (services live in Session 0 and cannot see the profile) | `systemd --user` unit, `WantedBy=default.target`, optional linger | Three implementations behind one trait; `service-manager` covers Linux and the launchd fallback. Sec. 10, 14 |
| 11 Signing / notarization | Developer ID + hardened runtime + notarytool via tauri-action; 99 USD/yr | Authenticode OV/EV or Azure Artifact Signing; SmartScreen reputation | None (optional RPM GPG) | Sec. 11 |
| 12 Package manager | Homebrew cask (tap first, homebrew/cask at 75 stars / 225 self-submitted) | winget (PUA heuristics are a risk for a scanner) | deb/rpm/AppImage, `cargo install` | Sec. 12 |
| 13 Updater | `.app.tar.gz` + minisign `.sig`, replaces bundle in `/Applications` | NSIS/MSI, app exits during install | AppImage only (deb/rpm users rely on the package manager) | Sec. 13 |

Portability constraint check: every core block (1-4, 9) is pure Rust with the same API on all three platforms; the OS integration layer named in ADR 0010 is exactly rows 6-8 and 10-13, and nothing in the v1 macOS design (SMAppService, FSEvents, notarization) leaks into the core crates.

---

## Unverified items

Collected from the sections above; each is also marked in place.

1. Apple's limit on the number of paths per FSEvents stream; whether `~/Library/Application Support` is exempt from TCC prompts; distro overrides of inotify limits (sec. 1).
2. `notify-debouncer-full` file-id cache memory cost as a documented caveat (inferred from source) (sec. 1).
3. yara-x official build time, binary size and compiled-ruleset memory footprint; regex lookaround/backreference rejection is inferred from the parser, not stated (sec. 2).
4. Numeric SHA-256 vs BLAKE3 throughput; VirusTotal keying on SHA-256; blake3 mmap SIGBUS as a documented warning (sec. 3).
5. The JIT entitlement requirement for yara-x under the hardened runtime is derived from Apple's entitlement docs, not from a yara-x statement (sec. 11).
6. Tauri 2 issue about Accessory-policy windows losing keyboard focus (none found); GNOME needing a shell extension for tray icons; `macOSPrivateApi` disqualifying App Store submission (sec. 6).
7. macOS release notifications requiring a Launch Services-registered bundle (inferred from `set_application` in the plugin source) (sec. 7).
8. Wording of the background-items notification and the macOS 15 "Login Items & Extensions" panel name; whether trashing the app clears an SMAppService registration beyond the overnight cleanup Apple documents (sec. 10).
9. Whether Tauri's `codesign` invocation (no `--timestamp`) always yields the secure timestamp notarization requires; whether tauri-action literally uploads `.app.tar.gz` (README does not name the extension) (sec. 11).
10. Homebrew requiring notarization as a literal rule (inferred from "must pass Homebrew's Gatekeeper checks"); the `depends_on macos: ">= :sonoma"` string form is not in the current cookbook, so use `:sonoma` (sec. 12).
11. Official Tauri support for self-updating a cask-installed app (sec. 13).
12. Rust access to the Windows Task Scheduler COM API via the `windows` crate; the exact `ServiceInstallCtx` field set in `service-manager` 0.11.0 (sec. 14).
