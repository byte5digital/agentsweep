# The daemon's signing identifier under Tauri's own signing

Date: 2026-10-14
Scope: what signing identifier Tauri's bundler gives the daemon sidecar, whether an Info.plist embedded in the daemon binary or any Tauri configuration changes it, and which artefacts of a Tauri build go stale when the daemon and the bundle are signed again after Tauri. Every fact below comes from a local experiment with an ad hoc identity (`APPLE_SIGNING_IDENTITY="-"`), or from the locally cached sources named beside it. Nothing was notarized, uploaded, installed, opened or registered; no real identity was used.

## Setup

- Apple M2 Max, macOS 26.6.2 (25G83), macOS SDK 26.5, Apple clang 21.0.0, rustc and cargo 1.98.1 (Homebrew).
- Tauri CLI 2.11.5, the version CI pins, run from the local npm cache; the workspace locks `tauri` 2.11.5 and `tauri-utils` 2.9.3.
- Release sidecars built by the sidecar script (`cargo auditable build --release`) for the host triple only, `aarch64-apple-darwin`. The universal bundle of ticket 92 could not be built here because the x86_64 standard library is not installed on this machine; every binary below is thin arm64. Signing is per architecture slice, so the experiments say nothing about the x86_64 slice beyond what CI's universal job checks.
- Bundle built with `tauri build --bundles app,dmg --config tauri.bundle.conf.json` plus a temporary configuration that turns `createUpdaterArtifacts` on, with a throwaway updater key generated in the temporary directory and an `.invalid` endpoint, and `CI=true` so the DMG script does not drive Finder.
- Every output was copied to a temporary directory, examined there and removed afterwards.

## E1: what Tauri runs

The Tauri CLI binary's strings name the arguments its signer passes to `/usr/bin/codesign`: `--force`, `-s`, `--options runtime`, `--keychain` and `--entitlements`. There is no `-i` or `--identifier`. The build log of E2 shows it signing each sidecar, then the app executable, then the app bundle, each with "replacing existing signature".

## E2: the bundle as Tauri builds it today

Sidecars as cargo leaves them carry the linker's ad hoc signature (`flags=0x20002(adhoc,linker-signed)`, identifier `agentsweepd-<hash>`, `Info.plist=not bound`). After `tauri build`:

| Code | Identifier | Flags | Info.plist | Entitlements |
|---|---|---|---|---|
| AgentSweep.app (and its executable) | `de.byte5.agentsweep` | `0x10002(adhoc,runtime)` | 16 entries | none |
| `Contents/MacOS/agentsweepd` | `agentsweepd-55554944ec6d…` | `0x10002(adhoc,runtime)` | not bound | none |
| `Contents/MacOS/agentsweep` | `agentsweep-55554944fdf0…` | `0x10002(adhoc,runtime)` | not bound | none |

- `codesign -d -r-` shows a designated requirement of the form `cdhash H"…"` on every one, the form codesign gives ad hoc code; a requirement naming an identifier and a Team ID needs a real identity and is not shown here.
- The hardened runtime flag is set on every binary even with the ad hoc identity. No `Timestamp=` line appears, as expected for ad hoc signatures.
- `codesign --verify --deep --strict` accepts the app.
- With no Info.plist, codesign takes the identifier from the file name; for ad hoc code it appends a hash suffix. Whether a real identity gets the bare file name is not shown here.

## E3: an Info.plist embedded in the daemon binary

A minimal C program linked with `-Wl,-sectcreate,__TEXT,__info_plist,<plist>`, then signed with `codesign --force -s - --options runtime` and no identifier, took the plist's `CFBundleIdentifier` as its identifier (`Info.plist entries=2`); the same program without the section took its file name. The linker's own ad hoc signature ignores the section in both cases.

The daemon was then built with its Info.plist (`CFBundleIdentifier` `de.byte5.agentsweep.daemon`, `CFBundleInfoDictionaryVersion`, `CFBundleName`) linked into the `__TEXT,__info_plist` section of `agentsweepd` only. `otool -l` shows the section, and the `.dep-v0` section of cargo auditable is still there. The bundle was built again exactly as in E2:

- `agentsweepd`: identifier `de.byte5.agentsweep.daemon`, flags `0x10002(adhoc,runtime)`, `Info.plist entries=3`, no entitlements.
- The app and the CLI sidecar: unchanged from E2 (the CLI keeps `agentsweep-<hash>`).
- `codesign --verify --deep --strict` accepts the app.
- The app inside the DMG Tauri built and the app inside the updater archive both carry the daemon with identifier `de.byte5.agentsweep.daemon`, and both verify.
- `agentsweepd --version` still runs and prints the label and version.

The identifier therefore survives `tauri build`'s own signing pass: that pass is the one that produces it.

## E4: Tauri configuration

The configuration schema of the locked `tauri-utils` 2.9.3, read from the local cargo registry, has no per-sidecar signing setting. `bundle.externalBin` is a plain list of paths. The macOS section offers `frameworks`, `files`, `bundleVersion`, `bundleName`, `minimumSystemVersion`, `exceptionDomain`, `signingIdentity`, `hardenedRuntime`, `providerShortName`, `entitlements`, `infoPlist`, `dmg` and `localePath`; `infoPlist` merges into the app's own Info.plist, and none of them names an identifier for a sidecar.

## E5: what a re-sign after Tauri leaves stale

On a copy of the E2 outputs, the daemon was re-signed with `codesign --force -s - --options runtime -i de.byte5.agentsweep.daemon`, and then the bundle with `codesign --force -s - --options runtime`, which is checklist item 15 as written.

- App: after the daemon's re-sign and before the bundle's, `codesign --verify --deep --strict` fails with "nested code is modified or invalid" naming the daemon. After the bundle's re-sign it verifies, and the app's CDHash has changed (`ff5ab6cd…` to `539a38ed…`). Any notarization ticket issued for the bundle Tauri signed was issued for the earlier CDHash; notarization itself was not run.
- DMG: mounted read-only, the app inside still has CDHash `ff5ab6cd…` and the daemon still has identifier `agentsweepd-55554944ec6d…`. It verifies, as the old bundle.
- Updater archive (`AgentSweep.app.tar.gz`): extracted, it holds the same old app and daemon. A tar of the re-signed app has a different SHA-256 from the archive Tauri built.
- Updater signature (`.app.tar.gz.sig`): its trusted comment names `AgentSweep.app.tar.gz` with the build's timestamp; it was made over the archive Tauri built, which holds the old bundle.
- `latest.json`: the Tauri CLI produced none (`find` over the outputs is empty). It is written by `tauri-action` from the `.sig`, so it could not be exercised locally; it carries the signature of the stale archive.

## Not established here

- Behaviour with a real Developer ID identity: the bare-name identifier, the identifier-based designated requirement, `Timestamp=`, and notarization of a bundle whose daemon carries an embedded Info.plist.
- The x86_64 slice and the universal bundle, which this machine cannot build.

## Question for the owner

Once this note is in, which shape does the release pipeline take so that the daemon carries its frozen identifier before notarization: (a) keep `tauri-action` for build, signing and the draft release, but without its own notarization, and add post-steps that re-sign the daemon and the bundle, rebuild the DMG and the updater archive, re-sign the archive with the updater key, notarize and staple, and replace the assets; (b) make Tauri's own signing yield the frozen identifier (for example through an identifier embedded in the daemon binary), which would amend checklist item 15; or (c) call the Tauri CLI directly and do signing, DMG, notarization and upload in the workflow's own steps, which would amend the `tauri-action` line of section 9.1?
