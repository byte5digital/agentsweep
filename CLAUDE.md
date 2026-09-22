# AgentSweep: notes for agent sessions

AgentSweep scans the local configuration surfaces of Claude Code and Codex and quarantines what a deterministic Rule proves bad. Status: building v1 from a finished spec. Nothing is open for design; if a ticket seems to need a decision the spec does not make, say so instead of deciding.

## Read first, in this order

1. `CONTEXT.md`: the glossary. Use its capitalised terms (Item, Finding, Scan, Gate, ...) with exactly their meaning, in code names, comments and commits.
2. `.scratch/agentsweep/spec.md`: the v1 specification. Read sections 1 to 4 for scope and the data model, then the sections your ticket names. The build plan is section 11.
3. `rules/README.md`: the rule authoring contract and the struct-global schema ("What a rule sees").
4. `docs/adr/`: ten architecture decision records. Respect them; propose a new ADR rather than working around one.
5. `docs/research/`: the fact base. Facts are cited by file; decisions are never in there.

`.scratch/` is gitignored working state. In a git worktree it is absent; symlink it from the main checkout.

## Tickets

Build tickets live in `.scratch/agentsweep-build/issues/NN-slug.md`, numbered in dependency order. Each is sized for one session and lists what blocks it. Start a ticket only when every blocker is merged into `main`. When a ticket's branch is merged, change its `**Status:**` line to `done`. The earlier planning tickets in `.scratch/agentsweep/issues/` are resolved and superseded by the spec.

Workflow per ticket: one branch `ticket/NN-slug`, `/implement` with the ticket path, TDD at agreed seams, code review, then commit. Rebase onto `main` before merging. Never run two daemon tickets (19 onward) at once; their tests share the real socket, Keychain key and data directory.

## Commits

- Every commit carries a DCO sign-off: `git commit -s`. No CLA.
- Ask before every commit and before every push. Small, granular commits.
- Use the configured git identity; never override the author name or email.
- Conventional prose subject lines in the imperative, no ticket numbers required, glossary vocabulary.

## Non-negotiables from the spec

- Rust, one Cargo workspace, toolchain pinned as `rust-version`; `Cargo.lock` committed, `--locked` builds.
- YARA-X is the only rule language, built with the `pulley` feature; the core injects the Item as struct globals with the full schema and defaults before every scan. Rules never compute; adapters do.
- Never execute an Agent binary or a git binary. Git is read in-process with `gix`; Agent presence and version come from disk.
- Only T0 and T1 may quarantine automatically, only stable Rules, only eligible kinds. Everything else flags.
- Nothing leaves the machine except the three disclosed requests (Rule Feed, update check, opt-in Claude API). No telemetry, no crash reporting.
- Sensitive values (MCP env, headers, tokens, `.env` contents) are hashed in stores, redacted in output, never logged.
- The daemon is the only writer of the Event Log, Baseline, verdict cache and state file, and the only process that touches the Keychain.
- Fixtures and corpus samples are defanged: `.invalid` hosts, payloads that decode to `echo`.

## Conventions

- Names: AgentSweep in prose and UI, `agentsweep` in every machine-readable name; bundle id `de.byte5.agentsweep`.
- Rule ids are never reused; T1 from 0021 next, T2 0500 to 0899, generated 0900 to 0999. Every new T1 Rule ships on Probation with three bad and three good Fixtures; every Heuristic with two and two.
- Tests run on temporary copies, never on the real home. A developer flag on the in-process CLI is the only sanctioned way to look at the real machine, and its output is never committed.
- Prefer prose in tickets, ADRs and docs over paths and snippets; no em-dashes.
