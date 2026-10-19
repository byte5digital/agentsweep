# AgentSweep

AgentSweep watches the settings of the AI coding assistants Claude Code and Codex on your Mac. These assistants load skills, plugins, MCP servers, hooks and instruction files from disk, and any of those can be written by someone who wants the assistant to do harm. AgentSweep checks each of them before the assistant uses it, tells you in plain words what it found, and moves into quarantine only what a fixed rule proves bad. Everything else it flags for you to decide, and anything it moved can be put back with one click.

It runs quietly in the menu bar, checks again whenever something changes and once a day, and offers two levels of detail: Simple, for anyone, and Developer, with rule ids, paths and scores always visible.

**Status: version 0.1.0 is being prepared.** The app, the background service and the command line tool are built; the first release is not published yet. The install steps below start working when 0.1.0 appears on the releases page of this repository.

## Install

AgentSweep needs macOS 14 (Sonoma) or later and runs on Apple silicon and Intel Macs.

**With Homebrew** (arrives with 0.1.0):

```sh
brew install byte5digital/tap/agentsweep
```

This installs the app and puts its command line tool, `agentsweep`, on your path.

**Without Homebrew** (arrives with 0.1.0): download the DMG from the releases page of this repository on GitHub, open it and drag AgentSweep to Applications. The DMG is signed and notarized by Apple. The command line tool can then be added from Settings with **Install command line tool**.

On first launch a short setup asks one question per screen. Full Disk Access is never required.

### The command line tool on its own

`cargo install agentsweep` (arrives with 0.1.0, when the crate is published) gives only the on-demand scanner: `agentsweep scan <dir>` checks one folder before you open it with an assistant and answers "safe to open" or "do not open yet". It runs in the terminal, records nothing and writes nothing. It has no background service, does not watch anything, cannot quarantine and cannot show status, because the AgentSweep service answers only the signed tools of its own app. For protection that keeps running, install the app.

## What leaves your Mac

Exactly three requests ever leave the machine, each disclosed during setup and in Settings, and nothing else:

1. The Rule Feed fetch: AgentSweep asks GitHub for newer rules, with no identifiers. It has its own switch and is on by default.
2. The app update check: AgentSweep asks GitHub whether a newer version exists, with no identifiers. It has its own switch and is on by default.
3. The opt-in Claude API call for the AI check, made with your own key and only after you agree on an explicit consent screen.

There is no telemetry, no crash reporting and no anonymous statistics. By default the AI check runs on your Mac, with Apple's on-device model or with Ollama, or not at all.

## How it decides

Every Item on an assistant's settings passes a four-step ladder: an allowlist of known good content, deterministic Rules, Heuristics that add up to a Score, and an optional AI check for the cases in between. Only the first two steps may quarantine on their own; Heuristics and the AI check only flag. When a checked Item changes, AgentSweep compares it with what it saw before and shows the change. The Gate, on unless you switch it off, adds a small check to Claude Code and Codex that refuses a step while something flagged waits for your decision. A project can switch it off, so it is a backup, not the main protection.

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

## Reporting

A weakness in AgentSweep itself is reported privately; [SECURITY.md](SECURITY.md) says how.

A false alarm, a Rule or Heuristic that fires on something harmless, goes to the issue tracker of this repository. The **Report false positive** button on a Finding in the app opens a prefilled issue that carries the rule ids and versions but no content, names or paths, and nothing is sent until you press Submit on GitHub.

## Contributing

Contributions are welcome. New Rules arrive as pull requests with Fixtures; the authoring contract is in `rules/README.md`, the shared vocabulary in `CONTEXT.md` and the design decisions in `docs/adr/`. All commits must carry a Developer Certificate of Origin sign-off (`git commit -s`); see `DCO`.

## License

Apache-2.0. See `LICENSE`.
