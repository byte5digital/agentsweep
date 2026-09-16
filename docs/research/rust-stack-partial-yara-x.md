# YARA-compatible matching: yara-x vs hand-rolled (PARTIAL, subagent findings, 2026-09-16)

Provenance: sub-report of the Rust stack research ticket, produced before the session rate limit. Fold into docs/research/rust-stack.md.

## yara-x crate
- Latest 1.20.0 (2026-08-24), roughly monthly minors; 1.0.0 stable 2025-06-04 ("ready for production use"). Classic YARA is in maintenance mode. https://crates.io/api/v1/crates/yara-x , https://virustotal.github.io/yara-x/blog/yara-x-is-stable/ , https://github.com/VirusTotal/yara
- BSD-3-Clause, MSRV 1.93.0 (moves fast: 1.85 to 1.93 in 14 months), edition 2024. https://raw.githubusercontent.com/VirusTotal/yara-x/main/Cargo.toml
- Pure Rust but conditions compile to WebAssembly executed by wasmtime 45.x, a non-optional dependency on native targets. No feature flag drops it. `pulley` feature uses the Pulley interpreter instead of Cranelift JIT (relevant for hardened runtime without JIT entitlement). `parallel-compilation` off by default. https://github.com/VirusTotal/yara-x/blob/main/lib/Cargo.toml
- Footprint proxies: prebuilt CLI 7.74 MB compressed (aarch64 darwin); third-party report of ~14 MiB Cranelift/wasmtime runtime overhead (https://github.com/KalarisLabs/Skill-Doctor/issues/42, anecdotal). Build time unverified but heavy.
- Default modules (17) pull in crypto crates; disable via `default-features = false, features = ["string-module","math-module","hash-module"]`.
- Dependencies: regex, regex-automata, regex-syntax, wasmtime, walrus, protobuf, daachorse (replaced aho-corasick), memchr, bstr, memmap2.

## API (docs.rs 1.20.0)
- `Compiler::new().add_source(...)`, `build() -> Rules`; `Scanner::new(&rules).scan(bytes)`; `scan_file`; `set_timeout`; `max_scan_size`; `define_global` / `set_global` accept i64, f64, bool, str and `serde_json::Value`, so structured facts (file path, kind, parsed config) can be injected for rules to reference. https://docs.rs/yara-x/latest/yara_x/struct.Compiler.html , https://docs.rs/yara-x/latest/yara_x/struct.Scanner.html
- `relaxed_re_syntax(bool)` mimics YARA's lax regex escapes; must be called before adding rules.
- Scanner is not Send/Sync: one scanner per thread, reusable across files. Rules shareable across scanners.
- Results: `matching_rules()`, `Rule::identifier/namespace/metadata/tags/patterns`, `Match::range/data`; `MetaValue` Integer/Float/Bool/String/Bytes. Severity and category can ride in `meta:`.
- `Rules::serialize/deserialize`: blob has magic "YARA-X\0\0" plus serialization version (currently 6); never deserialize third-party blobs. Native code embedded only with `native-code-serialization`. Precompiled packs are tied to the embedded engine version: ship packs with the binary, or ship source rules and compile at startup. https://docs.rs/yara-x/latest/yara_x/struct.Rules.html
- Differences from YARA: `{` must be escaped outside repetition; invalid escapes are errors; base64 patterns >= 3 bytes; modifiers once each; new `with` statement; `.len()`. https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/

## Scanning text files
- Byte matching; useful modifiers for Markdown/JSON: `nocase`, `ascii`, `wide` (UTF-16LE), `base64`/`base64wide` (catches base64-smuggled instructions), `fullword`. https://virustotal.github.io/yara-x/docs/writing_rules/text-patterns/
- Regex engine: atom-prefiltered Pike VM plus a FastVM subset; parsed by `regex-syntax`, so no backreferences or lookaround (inferred, not stated in docs). 4096-byte verify limit per direction from an atom.
- No json/yaml/toml/markdown module. Structural checks over MCP config JSON, hook commands and env secrets need a separate serde_json/toml layer, feeding derived facts via `define_global`/`set_global` or post-filtering. Relevant modules for text: `string`, `math` (entropy), `hash`, `time`.

## Performance
- May 2026: daachorse replaced aho-corasick; YARA Forge over 24 GB: yara-x 26.2 s vs classic YARA 48.3 s. v1.20.0 added SIMD pattern matching. https://virustotal.github.io/yara-x/blog/yara-x-just-got-faster/
- For this workload (hundreds of small text files, tens to hundreds of rules) wasmtime startup and rule compile dominate, not scanning. `native-code-serialization` avoids Cranelift compile at load.

## Bindings and the older `yara` crate
- Official APIs: Rust (native), Python, Go, C (all wrap Rust). `yara` crate 0.32.0 (2026-04-28, community, Hugal31/yara-rust) binds libyara 4.5.x, needs a C toolchain, bindgen/LLVM and OpenSSL; tracks a frozen engine. yara-x is the forward path.

## Hand-rolled alternative and existing rule sets
- Building blocks: regex 1.13.1, regex-automata 0.4.18, aho-corasick 1.1.5, daachorse 5.0.0, globset 0.4.20. `RegexSet` reports which patterns match, not offsets. A hand-rolled engine is small but the DSL is non-portable and you re-implement counts, offsets, conditions and tooling.
- Existing rule sets relevant to agent skills:
  - Cisco skill-scanner (Apache-2.0, Python): YAML + YARA-X packs under `skill_scanner/data/packs/{atr,core,promptguard}`, optional LLM judge, depends on `yara-x>=1.10,<2`. Strongest evidence YARA-X is already used for this domain. https://github.com/cisco-ai-defense/skill-scanner
  - Cisco mcp-scanner (Apache-2.0): custom YARA rules, scans client configs and stdio servers. https://github.com/cisco-ai-defense/mcp-scanner
  - NVIDIA SkillSpector (Apache-2.0): 71 patterns in 17 categories plus 4 YARA signatures. https://github.com/NVIDIA/SkillSpector
  - Agent Threat Rules (MIT): 683 YAML rules (Prompt Injection 223, Tool Poisoning 85, Skill Compromise 45, Context Exfiltration 109...), regex-based, no YARA export but transpilable. https://github.com/Agent-Threat-Rule/agent-threat-rules
  - SYARA (MIT): YARA-like syntax with semantic extensions, not runnable by yara-x. https://github.com/nabeelxy/syara
  - DataDog GuardDog: mostly Semgrep, one .yar. https://github.com/DataDog/guarddog
- Net: no large canonical pure-YARA prompt-injection ruleset exists; Cisco packs and ATR are the closest.

## Unverified
Official build time and binary size; ruleset memory footprint; regex lookaround rejection (inferred); yara-x-benchmarks contents; exact .yar paths in Cisco packs; whether any compat flag other than `--relaxed-re-syntax` exists.
