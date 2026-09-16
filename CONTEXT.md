# AgentSweep

A scanner for the local configuration surfaces of coding agents (Claude Code, Codex) that finds and quarantines malicious skills, plugins, MCP servers, hooks and instruction files before the agent loads them.

## Language

**AgentSweep**:
The product. Written AgentSweep in prose and UI, `agentsweep` in every machine-readable name (CLI, crate, cask, bundle identifier suffix).
_Avoid_: the antivirus, the scanner (as a proper name), AV

**Agent**:
A locally installed coding agent whose configuration this tool protects. v1: Claude Code, Codex.
_Avoid_: Client, IDE, assistant

**Surface**:
A location on disk an Agent reads instructions or executable configuration from: skills, plugins, MCP configs, hooks, instruction files, settings.
_Avoid_: Repository, target, path

**Surface Adapter**:
The per-Agent component that knows where that Agent's Surfaces live and how they are structured. Adding an Agent means adding one Surface Adapter.
_Avoid_: Plugin, connector, integration

**Finding**:
One suspicious observation about one file or config entry, with a severity and the detection tier that produced it.
_Avoid_: Alert, detection, hit

**Quarantine**:
Moving a flagged item out of its Surface so the Agent cannot load it, in a way that can be restored. Automatic only for high-precision deterministic findings; everything else is flagged, never moved.
_Avoid_: Delete, block, isolate

**Scan**:
One pass over one or more Surfaces producing Findings.

## Detection

**Tier**:
One rung of the detection ladder. T0 Allowlist, T1 Rules, T2 Heuristics, T3 AI Judgement. Cheaper tiers run first; a later tier only sees what earlier tiers left undecided.
_Avoid_: Engine, stage, layer

**Allowlist (T0)**:
Known-good items identified by content hash or by official source. Skipped by all later tiers.

**Rule (T1)**:
A deterministic pattern with near-zero false positives. The only tier besides T0 whose findings may trigger automatic Quarantine.
_Avoid_: Signature, heuristic

**Heuristic (T2)**:
A scored indicator that raises suspicion but never quarantines on its own.

**AI Judgement (T3)**:
An opt-in model verdict on items T2 scored as ambiguous. Never quarantines. Runs locally by default, Claude API by opt-in.
_Avoid_: AI scan, LLM check

**Trust**:
A user decision that a specific content hash is safe. Trust is bound to the hash, so a changed file is re-scanned as new.
_Avoid_: Whitelist, ignore, exception
