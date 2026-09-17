---
status: accepted
date: 2026-09-17
---

# AgentSweep runs as the user and is tamper-evident, not tamper-resistant

AgentSweep's daemon is a LaunchAgent with the user's privileges, so any malware already running as that user can unload it, edit its quarantine store or replace its rule feed. We decided not to add a root privileged helper to own those stores. Instead the rule feed is signed and verified against a public key pinned in the binary, the quarantine manifest and the Baseline are signed with a key held in the user's Keychain, and the app shows "daemon not running" and "state tampered" states visibly. The threat model rules same-privilege malware out of scope, so a root helper would buy little protection at the cost of a privileged install prompt that scares the non-technical users v1 targets, a second process to keep in sync, and a store layout that is hard to change later. The spec says plainly that AgentSweep is tamper-evident, not tamper-resistant. Binary integrity comes from notarization and the hardened runtime.

## Considered options

- Root privileged helper via SMAppService daemon owning the quarantine store and rule feed: rejected for the install prompt, complexity and the fact that it still cannot stop user-level malware from feeding the agents a fresh malicious file.
- No self-protection at all: rejected because a silently unloaded daemon or a swapped rule feed would leave the user believing they are protected.
