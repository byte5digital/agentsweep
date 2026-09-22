---
status: accepted
date: 2026-09-22
---

# The Gate is defence in depth and fails open

AgentSweep registers a hook in each Agent (the Gate) that refuses a turn or a tool call while an open Threat Finding stands on the project or on the Item about to be used. When the daemon cannot be reached, or the hook's own deadline passes, the Gate allows the turn and only prints "AgentSweep is not running, nothing was checked". We decided this knowing that a security control that allows on failure looks wrong: Quarantine is the primary control and already acts at load time; the Gate only closes the window between a Finding and the user's decision. Fail-closed is not enforceable either way, since both Agents proceed on a hook timeout, and it would lock every Agent session on the machine whenever the daemon is down, including after an Uninstall that left the entry behind. A repository the user opens can switch the Gate off with one settings key; that is accepted and shown as a per-project Health state, not fought.

## Considered options

- Fail closed (deny when the daemon is unreachable): rejected because the Agents ignore the hook after its timeout anyway, and because a stale entry would turn "AgentSweep is not running" into "no coding agent works on this Mac".
- Fail open silently: rejected because Protection being off must always be shown, never implied; the one-line system message is the cheapest way to show it inside the Agent.
- Not shipping a Gate and relying on Quarantine alone: rejected because Rules on Probation, Suspicious Heuristics, malicious Verdicts and Drift never quarantine by themselves, so a flagged skill stays usable until the user reacts.
