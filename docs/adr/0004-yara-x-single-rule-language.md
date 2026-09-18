# 0004. YARA-X is the only rule language, with the Item injected as struct globals

Date: 2026-09-18

## Status

Accepted

## Context

The Rule tier needs deterministic patterns over two kinds of input: raw bytes (markdown, shell scripts, JSON and TOML text) and structured facts about a configuration entry (an MCP server's resolved command path, a settings key path, a git config key). Three options were on the table: YARA-X alone, YARA-X for bytes plus a small matcher DSL over the adapter's parsed views, or a custom DSL for everything.

The deciding fact, verified against the yara-x 1.20 documentation: a `serde_json::Value` object passed to `Compiler::define_global` becomes a struct global that rules read with dotted access, including nested structs, typed arrays with iteration and indexing, and the string operators `contains`, `icontains`, `startswith`, `endswith`, `iequals` and regex `matches`. The constraints are that a global's shape is fixed at compile time, arrays may not be empty, nested or mixed, and null is rejected.

Cisco's skill-scanner and Ramparts already ship YARA-X packs for this domain, and no large pure-YARA prompt-injection corpus exists, so interoperability is worth something and a bespoke DSL forfeits it.

## Decision

- Every rule is a YARA-X rule. There is no second DSL.
- Before each scan the core defines one global per parsed-view kind (`mcp`, `hook`, `settings`, `skill`, `subagent`, `env`, `repo`) plus a common `item` global, each always present with its full schema. Fields that do not apply hold defaults; arrays always hold at least one element and carry a sibling count field.
- Anything a rule would otherwise compute is a view field computed by the Surface Adapter. A view field exists only when a rule reads it.
- The scan bytes of an entry Item are its canonical serialised form with sorted keys, the same bytes Trust hashes.
- Rules carry their routing and wording in `meta:` (`id`, `tier`, `category`, `severity`, `class`, `kinds`, `status`, `plain`, `description`, `references`, `sensitive`), read back from the compiled rules to build the index.
- New tier 1 threat rules ship with `status = "probation"` and cannot quarantine automatically until promoted after one release cycle without a false-positive report.
- Rule Packs replace the bundled pack wholesale by version; there is no per-rule merge.
- The corpus is one directory per rule with `bad/` and `good/` fixtures whose `item.toml` supplies the globals, so a rule is testable without an adapter.

## Consequences

- A community rule is one directory in one pull request, and packs from Cisco or Ramparts can be adapted rather than rewritten.
- The app carries wasmtime (about 14 MiB) and a fast-moving MSRV. The `pulley` feature avoids the JIT entitlement under the hardened runtime.
- Adding a view field is a core change with a conformance test, by design; rules cannot grow ad-hoc computation.
- The YARA-X CLI cannot define struct globals, so rules that read views are verified by the corpus runner, not by `yr scan`. The first ten rules and 54 fixtures were verified with a throwaway runner built on the yara-x crate on 2026-09-18.
- Probation delays every new auto-quarantine by one release; a bad rule cannot move a thousand users' files at once.
