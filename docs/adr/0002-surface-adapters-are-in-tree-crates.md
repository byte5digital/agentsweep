---
status: accepted
date: 2026-09-17
---

# Surface Adapters are in-tree Rust crates behind a core trait, not data manifests

Adding an Agent to AgentSweep means writing a Surface Adapter. We decided that an adapter is a Rust crate in the monorepo implementing a core trait, with a static declaration table (kinds, default config dir, surface table, enforcement capabilities) that the core reads instead of hardcoding paths. There is no YAML or JSON manifest format for adapters and no plugin ABI for out-of-tree adapters in v1. The "third adapter without touching the core" requirement is enforced by a conformance suite that runs every adapter against sanitised fixture trees, not by a declarative format.

The surface inventories showed that enumeration is logic, not a path list: Claude Code's project set is the key set of a JSON map plus a lossy slug directory, Codex resolves project trust through the directory, the project root and then the git root with worktrees mapping to the main checkout, Codex hook identity is a hash of a normalised TOML shape, and the live plugin registry differs from its documented schema. A manifest would have needed escape hatches for all of it within the first two agents. Compiled adapters also let the rule tier read one normalised parsed view per kind across agents, which a manifest could only express by embedding a transformation language.

The cost is that a contributor cannot add an agent by dropping in a file. We accept that: the kind vocabulary is a closed core enum by design (rules, severity and UX wording depend on it), so a new agent already needs a core review, and a `Generic` kind keeps a new adapter shippable with file-level rules before the core learns its specifics.

## Considered options

- Data-driven manifests (paths, kinds and scopes in YAML, loaded at runtime): rejected because project discovery, trust resolution and identity need real code for both v1 agents, and the escape hatches would have become the real format.
- Stable ABI or dynamically loaded adapters for out-of-tree contributions: rejected for v1 because it would freeze the Item and parsed-view shapes before a single rule reads them; reconsider once the rule corpus has stabilised the shapes.
