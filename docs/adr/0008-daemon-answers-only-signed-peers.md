---
status: accepted
date: 2026-09-22
---

# The daemon answers only signed peers, so the CLI is two tools

The daemon is the one process that holds AgentSweep's file access (macOS attributes it to the app bundle, including any Documents or Full Disk Access grant the user makes), the Keychain keys behind the Event Log and the Baseline, and the only write path into the quarantine store. Any local process that can reach its socket can therefore ask it to read, move or rewrite files the caller itself could not touch. We decided that the daemon accepts a connection only from a peer that runs as the same uid *and* carries a code signature from byte5's Team ID: the menu bar app and the `agentsweep` binary shipped inside the bundle. Everything else is refused at the handshake, before any request is read. The request vocabulary stays closed on top of that: no request takes a path except a Folder Scan and revealing a Receipt; everything else addresses Item, Finding and Receipt ids.

The visible consequence is that the CLI is two tools with one name. The in-bundle `agentsweep` (linked into `PATH` by the cask, or by "Install command line tool" in Settings) is a client: status, Quarantine, Restore, Trust and a bare `agentsweep scan` go through the daemon and see what the daemon sees. `agentsweep scan <dir>` and any build from crates.io or `cargo install` run the core in-process under the terminal's own file access, never reach the daemon, write nothing, and report Drift as unavailable. A `cargo install`ed CLI cannot show status; that is deliberate, not a missing feature.

## Considered options

- A uid check only, the conventional 0600 socket: rejected because every process the user runs has the same uid, including an Agent that has been prompt-injected. Once the daemon holds Documents access, that Agent would gain it through the socket.
- A shared secret in the data directory that clients read: rejected because any same-uid process can read it too; it proves nothing a uid check does not.
- Letting unsigned CLIs through with a reduced vocabulary (status only): rejected because status includes Finding text and Item paths, the vocabulary would need its own audit, and the boundary would be argued about in every release. One rule is easier to keep than a graded one.
- Giving up on the daemon for the CLI and making every CLI command in-process: rejected because Quarantine, Trust and Restore must go through the single Event Log writer with the Keychain key, and a second writer is exactly what ADR 0003 forbids.
