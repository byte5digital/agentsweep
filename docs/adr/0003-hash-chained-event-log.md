---
status: accepted
date: 2026-09-18
---

# Quarantine, Trust and audit state live in one hash-chained event log

AgentSweep needs to know what is in its quarantine store, which content hashes the user trusts, and what it did and when. ADR 0001 requires that state to be tamper-evident with a key held in the user's Keychain. We decided to keep all of it in a single append-only `events.jsonl`: every record carries the hash of the previous record and an HMAC-SHA256 over itself under a 32-byte key stored in the login Keychain under the app's signing identity. Quarantine, restore, re-enable, trust, untrust, purge and re-enforce are events. The quarantine manifest and the Trust table are derived views, rebuilt from the log and checked against the store's contents every time the daemon starts. The Baseline uses the same primitive.

One chain means one verification routine and one honest "state tampered" indicator, and the audit log the spec requires is the source of truth itself rather than a second thing to keep consistent. We chose an HMAC over a signature because only AgentSweep ever verifies the chain; nobody else needs to check it without the key.

Two failure states are kept apart on purpose. A record whose MAC or previous-hash does not verify while the key is present is *chain broken*: the app shows "state tampered" and freezes automatic quarantine until the user acknowledges. A well-formed chain with no key in the Keychain is *key missing*, which happens on a migrated Mac, a reset Keychain or a restored backup: the app shows "protection state was reset", generates a new key and starts a new chain whose first record points at the old log's last hash. Old records stay readable but are marked unverified, and the Developer posture says plainly that this state cannot rule out tampering. Treating a routine migration as an attack would make the app look broken on day one for the non-technical users v1 targets.

Amended 2026-09-21: the Baseline is a second chain, `baseline.jsonl`, with the same record envelope, the same key and the same verification routine, written only by the daemon. It is kept apart because it is far noisier than the Event Log (one record per Item on the first Scan, large tree manifests, a rewrite on every plugin update) and because, unlike the Event Log, it may be compacted. Each compaction writes a fresh chain of the current state and appends one `baseline-compacted` event to the Event Log carrying the old and the new head hash, so the audit chain anchors the Baseline and a swapped-in Baseline file is detectable. How the Baseline behaves in the key-missing and chain-broken states is in ADR 0007.

## Considered options

- Separate signed files for the quarantine manifest, the Trust table and the audit log: rejected because three files need three signatures, can drift apart, and a manifest that disagrees with the audit log has no arbiter.
- A SQLite database with a signature over an export: rejected because every write would re-sign the whole store and a partial-write crash leaves no way to tell corruption from tampering.
- An Ed25519 signature per record: rejected as needless; there is no third-party verifier, and a private key in the Keychain is no harder to steal than an HMAC key.
- Treating a missing key as tampering: rejected for the migration case above.
