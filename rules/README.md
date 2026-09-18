# AgentSweep rule corpus

This directory is the Rule tier (T1) and, later, the Heuristic tier (T2) of AgentSweep: one directory per rule, each with the rule and the fixtures that prove it. It is also the source of every Rule Pack the app loads, bundled or fetched. The decisions behind this layout are recorded in ADR 0004 and in the wayfinder ticket "Rule tier (T1) design and rule corpus structure".

## One language

Every rule is a [YARA-X](https://virustotal.github.io/yara-x/) rule. There is no second DSL. Structural checks over parsed configuration work because the core injects the Item under scan as **struct globals** before every scan (see "What a rule sees"). Anything a rule would otherwise have to compute (resolved symlink targets, whether a path leaves the repository, whether a command sits in a temp directory, whether a file contains right-to-left script) is a field the Surface Adapter computes. Rules stay declarative.

Rules never derive Activation or Provenance, never hash, never read another file, and never see a Managed Item as anything but read-only.

## Layout

```
rules/
  README.md
  0001-decode-pipe-exec/
    rule.yar            one rule, name as_0001_decode_pipe_exec
    bad/<fixture>/      fixtures the rule must fire on
    good/<fixture>/     near misses the rule must stay silent on
  0002-.../
  0900-ioc-hosts/       generated from ../iocs/hosts.txt (see ../iocs/README.md)
```

Rule ids are integers, allocated in order, never reused. A retired rule keeps its directory with `status = "retired"`. Ids 0500 to 0899 are reserved for tier 2 heuristics and 0900 to 0999 for rules generated from the IOC lists; the bands are an allocation convenience only, a rule that changes tier keeps its id.

A fixture directory holds `item.toml` and exactly one of:

- `content`: the bytes of a file Item, or for an entry Item the canonical serialised entry (sorted keys, the same bytes ticket 09 hashes for Trust);
- `tree/`: the files of a tree Item (skill directory, plugin version, marketplace clone).

`item.toml` states what the adapter would have produced for that Item and what the corpus runner must observe:

```toml
[item]            # common fields, see below
[mcp] / [hook] / [settings] / [skill] / [subagent] / [env] / [repo]   # the view for the kind, if any
[expect]
fire = [1]        # rule ids that must fire; [] for a near miss
files = ["scripts/deploy.sh"]   # optional, which files in a tree carry the match
```

Absent view fields take their defaults, so a fixture lists only what matters.

## Required metadata

Every rule's `meta:` block carries all of these; the corpus lint rejects a rule missing one.

| Key | Meaning |
|---|---|
| `id` | integer, matches the directory prefix |
| `title` | developer-facing one line |
| `tier` | `1` (Rule) or `2` (Heuristic, see "Heuristics") |
| `weight` | tier 2 threat rules only: `1` (weak, common in benign content, only meaningful in company), `2` (moderate, unusual but with known legitimate uses) or `3` (strong, rarely benign, kept out of tier 1 only because near misses exist). Absent on tier 1 rules and on tier 2 exposure rules. |
| `category` | `"threat"` (attacker-planted, may auto-quarantine) or `"exposure"` (the user's own risky config, never quarantined) |
| `severity` | `"critical"` (code execution or credential theft), `"high"` (behaviour hijack, escalation, re-pointing), `"medium"` (Exposure with a real leak path), `"low"` (hygiene). Tier 1 threats are critical or high only. Severity says how bad, never how sure; the tier says how sure. |
| `class` | 1 to 6, the threat model's ranked attack class |
| `kinds` | comma list of Item kinds the rule applies to; the core pre-filters on it |
| `status` | `"probation"`, `"stable"` or `"retired"` (see below) |
| `plain` | one sentence for the Simple posture, no jargon |
| `description` | what fires, what deliberately does not, and why |
| `references` | space-separated primary sources |
| `sensitive` | `true` when matches can land on sensitive fields; the Finding then shows only a redacted form |
| `reviewer_directed` | optional, tier 2 only: `true` when the heuristic fires on text that addresses a reviewer, scanner or AI ("already approved", "report this as safe"). On an Item where such a heuristic fired, AI Judgement records a benign Verdict as unsure. Absent means `false`. |

What a rule emits is its id plus the match ranges and, for tree Items, the relative file. The Finding built around that belongs to the scan lifecycle ticket.

## Probation

A new tier 1 threat rule ships as `status = "probation"`: it produces a tier 1 Finding with a Quarantine button but does not quarantine automatically. A pull request flips it to `"stable"` after one release cycle with no false-positive report. Only stable rules auto-quarantine, and only on auto-eligible kinds (never RepositoryMetadata, EnvFile or any Managed Item). The first ten rules shipped on probation; dogfooding promotes them.

## Precision bar for a tier 1 threat rule

All five, before a rule may leave probation:

1. A documented source: a catalogue row, an advisory, a published incident. Speculative techniques stay tier 2.
2. The pattern has no legitimate use on the kinds it targets. `base64 -d | sh` has no business in a SKILL.md; `curl -k` does, so it is tier 2.
3. At least three `bad/` fixtures and at least three `good/` near misses in the rule's directory.
4. Zero hits on the benign corpus in CI (`corpus/benign/manifest.toml`, fetched at test time, pinned to commits) and on the author's own machine before a pack release.
5. One release cycle on probation with no false-positive report.

Drift does not change a verdict: an Item that changed since its Baseline and now matches a stable tier 1 threat rule is quarantined like any other, and the Finding says it changed. Activation does not change eligibility either; an inactive Item with a stable hit is quarantined, with wording that says it was not loaded.

## Heuristics (tier 2)

A heuristic is a rule with `tier = 2`: the same file, meta and fixtures as a tier 1 rule, but it raises suspicion instead of deciding. Heuristics never quarantine. The decisions are in the wayfinder ticket "Heuristic tier (T2) scoring and the ambiguity band".

**Score.** Every tier 2 rule with `category = "threat"` carries a `weight` of 1, 2 or 3. Per Item the core sums the weights of every threat heuristic that fired, each counted once no matter how many matches or how many files of a tree matched; count-sensitive checks belong inside the rule condition (`#pattern > n`). Tier 2 rules with `category = "exposure"` carry no weight and produce their own Exposure Finding each, like rule 0010.

**Bands.** The Score places the Item in one of three bands. The thresholds live in the pack `manifest.json` (`heuristics.ambiguous_at`, `heuristics.suspicious_at`) so a pack release can retune them; the v1 values are 2 and 4.

| Band | Score | What happens |
|---|---|---|
| Clear | below `ambiguous_at` | nothing; fired heuristics appear only in the Developer posture's item details |
| Ambiguous | `ambiguous_at` to `suspicious_at - 1` | handed to AI Judgement when enabled; hidden from the Simple posture except as a summary count; listed in the Developer posture |
| Suspicious | `suspicious_at` and up | one tier 2 Threat Finding per Item, both postures, with a manual Quarantine action |

An AI Judgement Verdict moves an Ambiguous Item to Suspicious (malicious, and only with a quote the core can find in the Item) or Clear (benign); unsure or no Verdict leaves it Ambiguous. A benign Verdict counts as unsure when a `reviewer_directed` heuristic fired on the Item, so text written to talk the engine round cannot clear the Item it sits in. The Score, weights and thresholds are never shown in the Simple posture; a Suspicious Finding there is one verdict sentence plus the fired heuristics' `plain` lines.

**Which Items.** Tier 2 runs on every Item the Allowlist did not clear and a stable tier 1 rule did not quarantine. Under a probation tier 1 hit the fired heuristics are shown as supporting detail of that Finding, not as a second Finding.

**Context heuristics.** A tier 2 rule may fire on view fields alone with no byte match (Baseline state, Provenance), capped at weight 2. Activation, Scope and the `registered` flag never change a Score.

**Fixture bar.** At least two `bad/` and two `good/` fixtures. The benign corpus run reports the hit count per heuristic instead of failing on it; a weight 3 heuristic must be at zero. Heuristics ship `stable`, there is no probation for a rule that cannot quarantine; `retired` still applies.

**Changing tier.** When a documented source appears for a heuristic, one pull request sets `tier = 1`, removes `weight`, sets `status = "probation"`, adds fixtures up to the tier 1 bar and keeps the id. A tier 1 rule demoted after false-positive reports takes `tier = 2` and a `weight`, keeping its id.

**User rules** in `rules.d/` carry the `weight` they declare, capped at 3, defaulting to 2 when missing.

## What a rule sees

The scan target is the Item's bytes: a file, each file of a tree in turn, or the canonical serialised entry. Alongside, these globals are always defined with their full schema; fields not meaningful for the Item's kind hold defaults. Strings default to `""`, booleans to `false`, integers to `0`. Every array holds at least one element (an empty string or an all-default struct) because YARA-X rejects empty arrays, and a sibling `<name>_n` carries the real count.

```
item      agent, kind, shape (file|tree|entry), scope (managed|user|project), project_root, path,
          provenance (manual|marketplace|plugin|agent_written|repository|unknown), provenance_ref,
          activation (active|inactive|unknown), activation_reason, registered, size, is_symlink,
          baseline (unchanged|changed|added|none; states defined by the Baseline ticket),
          provenance_official (true when provenance is an official marketplace),
          link_target, file_type (text|binary|archive|office|bytecode|unknown), has_rtl_script,
          file (relative path within a tree, set per file scanned)
mcp       name, transport (stdio|http|sse), command, command_resolved, command_in_temp,
          command_in_downloads, command_in_unknown_hidden_home, command_world_writable,
          args[], args_n, package, package_version, url, url_host, env_keys[], env_keys_n,
          header_keys[], header_keys_n, has_literal_authorization
hook      event, matcher, type, command, command_resolved, url
settings  key_path (dotted, array index as .N), value (string form), value_host
skill     name, allowed_tools[], allowed_tools_n, has_dynamic_context
subagent  name, permission_mode
env       keys[], keys_n            (values are sensitive and reach rules only as bytes)
repo      exec_keys[] {key, value, value_outside_repo}, exec_keys_n, gitdir_outside_repo,
          commondir_outside_repo, hook_executables[], hook_executables_n
```

Plugin, Marketplace, ExecPolicy, Workflow, InstructionFile and Generic have no view yet: rules on them are byte rules. A field is added only together with the first rule that reads it.

`command_in_unknown_hidden_home` is true when the resolved command sits under a dot-directory of the home that is not a known tool manager (`.nvm`, `.npm`, `.local`, `.cargo`, `.volta`, `.bun`, `.pyenv`, `.asdf`, `.mise`, `.rbenv`, `.deno`, `.claude`, `.codex`, `.agents`, ...). The list lives in the workspace adapter, not in rules.

## Provenance Repository, without running git

`provenance = "repository"` means the file is tracked by git in the project, with `provenance_ref` the HEAD commit. The workspace adapter computes it by reading `.git/index`, `HEAD` and refs in-process (the `gix` crate) and never executes a git binary: running `git ls-files` inside a cloned repository would itself trigger a planted `core.fsmonitor`. An unreadable index yields `unknown` and a Problem.

## Packs

A Rule Pack is this tree plus `manifest.json` (pack version, minimum engine version, per-file sha256) and a detached signature. The bundled pack is the same artifact embedded at build time. A fetched pack with a higher version replaces the bundled one wholesale; a pack whose minimum engine version exceeds the running app is ignored with a visible notice. Packs are released from this repository on their own tag series `rules-v<N>`, independent of app releases. Key handling is the distribution ticket's.

Developers may drop their own rules into the app's `rules.d/` directory. They load as an unsigned pack forced to tier 2: they can flag, never quarantine (weight handling under "Heuristics").

## Writing a rule

1. Take the next free id. Create `rules/<nnnn>-<slug>/rule.yar` with the full `meta:` block.
2. Prefer byte patterns on the Item's bytes; reach for a view field only when bytes cannot express the check. If the field does not exist, add it to the adapter and to the table above in the same pull request.
3. Write the near misses first. A rule that cannot name three legitimate look-alikes it stays silent on is not a tier 1 rule.
4. Run the corpus runner. Every fixture must produce exactly the ids in `expect.fire`.
5. Ship on probation.
