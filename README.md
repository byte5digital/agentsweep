# AgentSweep

AgentSweep scans the local configuration surfaces of coding agents (Claude Code and Codex): skills, plugins, MCP configs, hooks, instruction files and settings. It finds malicious or tampered items before the agent loads them and quarantines the ones a deterministic rule can prove bad.

**Status: planning.** Nothing here runs yet. The design is being settled in the open; research notes live in `docs/research/`, decisions in `docs/adr/`, and the shared vocabulary in `CONTEXT.md`.

## Shape of v1

- Rust core, CLI (`agentsweep`), background daemon (`agentsweepd`) and a Tauri menu bar app, one Cargo workspace.
- Four-tier detection ladder: allowlist, deterministic rules, heuristics, opt-in AI judgement. Only the first two tiers may quarantine automatically.
- Nothing leaves your machine except an optional signed rule feed fetch and an opt-in Claude API call with your own key. No telemetry.
- macOS 14+ first, shipped as a notarized DMG and a Homebrew cask. Windows and Linux follow with an integration layer over the same core.

## Contributing

Contributions are welcome once the spec is published. All commits must carry a Developer Certificate of Origin sign-off (`git commit -s`); see `DCO`.

## License

Apache-2.0. See `LICENSE`.
