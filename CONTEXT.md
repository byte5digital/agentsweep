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
A location on disk an Agent reads instructions or executable configuration from: skills, plugins, MCP configs, hooks, instruction files, settings, repository metadata, and env files that re-point the Agent.
_Avoid_: Repository, target, path

**Repository Metadata**:
The Surface kind made of the git files an Agent executes before trust: `.git/config` keys that run commands, `.git/hooks`, and gitdir pointers. Only for projects the Agent already knows.
_Avoid_: Git surface, repo config

**Surface Adapter**:
The per-Agent component that knows where that Agent's Surfaces live and how they are structured. Adding an Agent means adding one Surface Adapter.
_Avoid_: Plugin, connector, integration

**Item**:
One thing an Agent would load from a Surface, as scanned by AgentSweep: a file, a directory tree, or one entry inside a config file. The unit of identity, Trust, Baseline and Quarantine.
_Avoid_: Artifact, object, record, file (when an entry or tree is meant)

**Scope**:
Where an Item sits in the Agent's precedence: Managed, User or Project. Managed Items are read-only for AgentSweep.
_Avoid_: Layer, level, tier (reserved for detection)

**Provenance**:
How an Item got onto the Surface: manually placed, installed from a Marketplace, shipped inside a Plugin, written by the Agent itself, committed in the project's Repository, or unknown. What the Allowlist anchors on and what tells a repo-planted file from the user's own. Determined without ever running git.
_Avoid_: Source, origin, tracked (say Repository provenance)

**Activation**:
Whether the Agent would actually load an Item on its next launch: active, inactive with a reason (untrusted project, disabled, orphaned, stale hook hash), or unknown. Computed by the Surface Adapter, never by a Rule.
_Avoid_: Enabled, live, trusted (reserved for the user's Trust)

**Finding**:
One suspicious observation about one file or config entry, with a category (Threat or Exposure), a Severity and the detection tier that produced it.
_Avoid_: Alert, detection, hit

**Threat**:
A Finding whose content was planted by an attacker: a content author, a repo author or a dependency implant. The only Finding category that may ever be quarantined automatically.
_Avoid_: Malware, infection

**Severity**:
How bad a Finding is if true, in four steps: critical (code runs as the user or credentials leave), high (the Agent's behaviour, permissions or endpoints are hijacked), medium (an Exposure with a real leak path), low (hygiene). Never encodes confidence; the Tier does that.
_Avoid_: Risk level, score (reserved for the Heuristic tier), priority

**Exposure**:
A Finding about the user's own risky configuration, such as a plaintext secret or an unpinned package. Never quarantined automatically at any Tier.
_Avoid_: Hygiene, warning, misconfiguration

**Baseline**:
The recorded content hash of every item AgentSweep has scanned, kept per item so the next Scan can tell what changed.
_Avoid_: Snapshot, fingerprint store, cache

**Drift**:
A Finding that an item's content differs from its Baseline without a known user action. Drift alone never quarantines.
_Avoid_: Change, diff, modification

**Quarantine**:
Taking a flagged Item out of its Surface so the Agent cannot load it, in a way that can be restored: a file or tree is moved into the quarantine store, an entry is removed from its config file, a never-auto kind is neutralised in place. Automatic only for Threat findings from the Allowlist or Rule tiers; everything else is flagged, and the user may quarantine a Threat by hand.
_Avoid_: Delete, block, isolate, disable (that is the Agent's own switch, used only alongside a Quarantine)

**Receipt**:
The ordered record of what one Quarantine physically did to one Item, step by step, so that Restore can undo exactly those steps in reverse. One Quarantine, one Receipt.
_Avoid_: Backup, undo log, transaction

**Restore**:
Putting a quarantined Item back by replaying its Receipt in reverse. Restoring an automatically quarantined Item always grants Trust to that content hash, otherwise the next Scan would quarantine it again.
_Avoid_: Unquarantine, recover, whitelist

**Event Log**:
The single tamper-evident record of every Quarantine, Restore, Trust decision, purge and change of Judgement Engine. What is currently in quarantine and what is trusted are read from it, never stored separately.
_Avoid_: Audit trail, manifest, history (as a proper name)

**Scan**:
One pass over one or more Surfaces producing Findings.

**Protection**:
AgentSweep working in the background: watching the Surfaces and running scheduled Scans. It belongs to the Mac, not to the open window, so quitting the app does not end it. It is either on or off, and "off" is always shown, never implied.
_Avoid_: Real-time protection, shield, monitoring (runtime monitoring of an Agent is a different product)

**Needs Permission**:
The state of a project that the operating system will not let AgentSweep read until the user allows it. A project that Needs Permission has not been scanned and never counts towards an all-clear.
_Avoid_: Skipped, unreadable, clean

**Uninstall**:
Removing AgentSweep with an explicit choice about what is in Quarantine: restore it all, keep it, or delete everything. Keeping is the default, so removing the app never silently loses a quarantined Item.
_Avoid_: Remove, delete the app, reset

**Posture**:
How much the app shows, chosen at onboarding and changed in Settings: Simple (plain sentences, one clear action, technical details one click away per Finding) or Developer (ids, paths, hashes, Scores and matched text always visible). One UI, never two apps; a Posture changes wording and density, never what is detected or enforced.
_Avoid_: Mode, profile, view, expert mode

## Detection

**Tier**:
One rung of the detection ladder. T0 Allowlist, T1 Rules, T2 Heuristics, T3 AI Judgement. Cheaper tiers run first; a later tier only sees what earlier tiers left undecided.
_Avoid_: Engine, stage, layer

**Allowlist (T0)**:
Known-good items identified by content hash or by official source. Skipped by all later tiers.

**Rule (T1)**:
A deterministic pattern with near-zero false positives, written in one shared rule language and proven by its own Fixtures. The only tier besides T0 whose findings may trigger automatic Quarantine, and only once the Rule is stable rather than on Probation.
_Avoid_: Signature, heuristic, check

**Probation**:
The state of a new Rule from the moment it ships until one release has passed without a false-positive report. A Rule on Probation flags and offers Quarantine but never quarantines by itself.
_Avoid_: Beta, preview, draft

**Fixture**:
One concrete Item, with the facts an adapter would attach to it, that a Rule must either fire on (a bad Fixture) or stay silent on (a good Fixture, always a near miss). Every Rule ships with both.
_Avoid_: Sample, test case, example

**Rule Pack**:
A versioned, signed set of Rules and indicator lists. One is bundled in the app; a newer one fetched from the project's feed replaces it wholesale. Nothing merges rule by rule.
_Avoid_: Ruleset, feed (the feed delivers a Rule Pack), signature database

**Rule Feed**:
The project's own channel that delivers newer Rule Packs between app releases. On by default, one switch turns it off, and then only the bundled Rule Pack is used. A Rule Pack from the Rule Feed is accepted only if it is signed by the project and newer than the one in use.
_Avoid_: Update server, signature updates, cloud rules

**Indicator List**:
A plain list of hosts, addresses, package names or file names known from published incidents, rendered into a generated Rule at pack build. Edited as a list, never as a Rule.
_Avoid_: IOC file, blocklist (reserved for the Agents' own mechanisms)

**Heuristic (T2)**:
One rule of the Heuristic tier: a pattern that raises suspicion but has known legitimate uses, so it carries a Weight and never quarantines on its own. Written in the same rule language as a Rule.
_Avoid_: Indicator (reserved for Indicator List), signal, check

**Weight**:
The declared strength of one Heuristic, in three steps: 1 (weak, common in benign content, only meaningful in company), 2 (moderate, unusual but with known legitimate uses), 3 (strong, rarely benign, kept out of the Rule tier only because near misses exist). Separate from Severity, which says how bad, not how sure.
_Avoid_: Confidence, probability, points

**Score**:
The sum of the Weights of every Threat Heuristic that fired on one Item, each counted once. Never shown in the Simple posture. Exposure Heuristics do not contribute.
_Avoid_: Risk score, rating, threat level

**Band**:
Where an Item's Score falls: Clear, Ambiguous or Suspicious. Suspicious is a Threat Finding the user may quarantine by hand. Ambiguous is what AI Judgement is asked about and is hidden from the Simple posture. Clear is nothing.
_Avoid_: Level, bucket, verdict (reserved for AI Judgement)

**AI Judgement (T3)**:
The Tier that asks one Judgement Engine for a Verdict on each Item in the Ambiguous Band. Never quarantines. Runs locally by default, Claude API by opt-in. Labelled "AI check" in the Simple Posture; the glossary term stays AI Judgement everywhere else.
_Avoid_: AI scan, LLM check

**Judgement Engine**:
The model that AI Judgement asks: Apple on-device, Ollama on this machine, or the Claude API. Exactly one is active at a time and nothing ever switches between them on its own.
_Avoid_: Provider, backend, model (the model is what runs inside an engine), Tier

**Judgement Request**:
What is handed to the Judgement Engine for one Item: the Item's facts, the Heuristics that fired with their excerpts, and the Item's content with sensitive values redacted. The same for every engine.
_Avoid_: Prompt (the fixed instructions around the request), payload, context

**Verdict**:
A Judgement Engine's answer on one Item: malicious, benign or unsure. A malicious Verdict must quote the Item to count and moves it to Suspicious; benign moves it to Clear; unsure, or no Verdict at all because the engine failed, leaves it Ambiguous. A Verdict is never a Finding by itself and never a reason to quarantine.
_Avoid_: Result, classification, score, confidence

**Trust**:
A user decision that a specific content hash of a given kind is safe, wherever that content appears. Trust is bound to the hash, so a changed file is re-scanned as new; it never expires on its own.
_Avoid_: Whitelist, ignore, exception
