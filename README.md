# AgentSweep

AgentSweep scans the local configuration surfaces of coding agents (Claude Code and Codex): skills, plugins, MCP configs, hooks, instruction files and settings. It finds malicious or tampered items before the agent loads them and quarantines the ones a deterministic rule can prove bad.

**Status: planning.** Nothing here runs yet. The design is being settled in the open; research notes live in `docs/research/`, decisions in `docs/adr/`, and the shared vocabulary in `CONTEXT.md`.

## Shape of v1

- Rust core, CLI (`agentsweep`), background daemon (`agentsweepd`) and a Tauri menu bar app, one Cargo workspace.
- Four-tier detection ladder: allowlist, deterministic rules, heuristics, opt-in AI judgement. Only the first two tiers may quarantine automatically.
- Nothing leaves your machine except an optional signed rule feed fetch and an opt-in Claude API call with your own key. No telemetry.
- macOS 14+ first, shipped as a notarized DMG and a Homebrew cask. Windows and Linux follow with an integration layer over the same core.

## What AgentSweep does not protect against

AgentSweep checks what coding agents load from disk. It does not protect against the following; each may be supported in a future version.

- Runtime prompt injection through tool results, web pages, issues and pull requests. Possibly supported in a future version.
- Behaviour of remote MCP servers and tool descriptions of servers whose source is not on disk; rug pulls before the first Baseline exists. Possibly supported in a future version.
- Payloads assembled only at runtime from network responses (the fetch pattern is flagged, the payload is invisible). Possibly supported in a future version.
- Malware already running with the user's privileges, including disabling AgentSweep itself. Possibly supported in a future version.
- Admin or MDM-level tampering beyond the read-only checks. Possibly supported in a future version.
- Integrity of the Agent binaries and of the user's general package dependencies (npm, PyPI, Makefiles). Possibly supported in a future version.
- Bugs in the Agents themselves (deep-link RCE, WebFetch exfiltration via pre-approved domains). Possibly supported in a future version.
- Social-engineering lures that never touch a Surface. Possibly supported in a future version.
- Projects the Agents have not yet opened, unless the user runs a Folder Scan. Possibly supported in a future version.

## Contributing

Contributions are welcome once the spec is published. All commits must carry a Developer Certificate of Origin sign-off (`git commit -s`); see `DCO`.

## License

Apache-2.0. See `LICENSE`.
