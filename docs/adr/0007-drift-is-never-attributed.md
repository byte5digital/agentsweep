---
status: accepted
date: 2026-09-21
---

# Drift is never attributed, and the Baseline advances only on a clean Scan or a known action

The threat model makes "unexpected change to the user's own configuration" a defended class: an MCP server whose `command` is swapped under an unchanged name, a hook that appears overnight. AgentSweep detects that by comparing each Item with its Baseline. The hard part is telling the user's own edit from a silent one. We decided not to try. AgentSweep never infers who changed an Item. A change counts as known only when it is one of a closed list: AgentSweep's own write (Quarantine, Restore, re-enforce, Re-enable), content whose hash already carries Trust, or the user's explicit Acknowledge. Everything else is Drift.

The Baseline holds the hash AgentSweep last *accepted* for an Item, and that hash moves forward in two ways only: a Scan ends with no open Finding on the Item, or a known action stands behind the change. It never moves because time passed. On the user's own executable configuration (Hook, McpServer, the executing and redirecting settings keys, ExecPolicy, Plugin, a Marketplace's source) Drift raises a Finding of its own that asks "was that you?", so on those kinds the Baseline waits for an answer. Elsewhere Drift is a fact the Heuristic tier may weigh, and a change that leaves the Item without a Finding is accepted by the Scan that evaluated it.

Acknowledge is deliberately weaker than Trust. It says "I made this change" and moves the Baseline; it does not say "this content is safe", so every Tier keeps scanning the content and a later Rule Pack may still flag it. It binds to the hash the user was shown and fails if the Item has changed since.

When the Keychain key is missing (ADR 0003's "protection state was reset"), the Baseline is not rebuilt from disk. The old records carry over as an unverified reference and Drift is still computed against them.

## Considered options

- A time window after an agent session in which changes count as the user's own: rejected because it favours the attacker. A prompt-injected agent writing a hook or an MCP entry is the attack, and it happens during a session. Without Endpoint Security (ruled out by ADR 0001) there is no way to see which process wrote a file.
- Advancing the Baseline after every Scan: rejected because a Drift Finding would disappear by itself on the next daily Scan, and a Suspicious Finding whose Score includes the Drift Heuristic would drop a Band overnight without anything having been decided.
- Never advancing without the user: rejected because project files change with every `git pull`; every instruction file would read as changed forever and the fact would stop meaning anything.
- Acknowledge as a form of Trust: rejected because Trust tells every Tier to leave that content alone for as long as its hash stays the same. A user who confirms "yes, I added that server" has said nothing about whether the server is safe.
- Re-bootstrapping the Baseline when the key is missing: rejected because deleting the Keychain item and editing a hook would then launder the edit into the new Baseline silently.
- Asking about every change on every kind: rejected because both Agents write to their own configuration on every "always allow" and auto-update plugins after session start. A question the user cannot answer teaches them to click yes, which destroys the one Finding whose value depends on being read. Items the Agent writes itself and consistent marketplace updates therefore raise no question, while the content Tiers still scan them.
