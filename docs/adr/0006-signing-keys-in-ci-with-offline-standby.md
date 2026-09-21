---
status: accepted
date: 2026-09-21
---

# Signing keys live in CI, with an offline standby for the Rule Feed

AgentSweep's self-protection is tamper-evident, not tamper-resistant (ADR 0001), so what a client accepts from the project rests on three keys: the Developer ID certificate, the minisign key of the app updater, and the minisign key of the Rule Feed. We decided to keep all three as password-protected secrets in one GitHub environment (`release`, required reviewers, reachable only from protected `v*` and `rules-v*` tags), and to pin a set of two Rule Pack public keys in the binary: the active key in CI and a standby key that is generated offline and never uploaded. A Rule Pack is accepted when its manifest carries a valid signature from any pinned key, its version is strictly greater than the one in use, and its minimum engine version is not newer than the client.

The Rule Feed exists to ship a Rule within hours of an incident, so signing has to happen in the release workflow. Holding only that key offline would buy little: the updater key must be in CI for `tauri-action` and is strictly more powerful, since it ships code, while a Rule Pack can only blind detection or cause restorable Quarantines. The standby key is what makes a leak survivable: every client in the field already trusts it, so signing moves to it within the hour, and an app release then drops the leaked key. During a planned rotation packs carry both signatures for two app releases. The Tauri updater allows one pinned key only, so its compromise is recovered through the two channels that do not depend on it, the notarized DMG and the Homebrew cask. Both procedures are written down in `SECURITY.md`.

The feed index (`rules/latest.json` on the `feed` branch) is deliberately unsigned. The signed manifest carries the pack version, so a forged index can freeze a client but never downgrade it, and the UI shows the signed release date of the rules in use.

## Considered options

- Sigstore keyless signing through GitHub OIDC: no long-lived key, but the daemon would need the Sigstore stack and its trust roots and could not verify a pack offline.
- An offline or hardware-token key for every Rule Pack: rejected because it slows the one thing the feed is for and protects less than the updater key that stays in CI anyway.
- A single pinned Rule Pack key rotated like the updater key (new key delivered under the old one): rejected because a leaked key could then only be replaced by trusting the leaked key once more.
- A signed index with a freshness window: rejected for v1; it turns every GitHub outage into a warning for non-technical users, and the visible rules date covers the freeze case.

## Consequences

- Until a client updates the app, a leaked active key can still feed it a higher-numbered pack. Accepted: no code runs, Quarantines are restorable, and the advisory tells users to update.
- The pinned key set is in binaries in the field, so changing the scheme later costs an overlap of at least two app releases.
