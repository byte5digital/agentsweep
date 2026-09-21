# yara-x `pulley` vs Cranelift JIT on the AgentSweep rule corpus

Date: 2026-09-21
Scope: cost of shipping macOS builds with yara-x's `pulley` feature (wasmtime interpreter, no executable memory) instead of the default Cranelift JIT, measured on the real `rules/` corpus and on real agent configuration files.

Method: one Rust crate (`Cargo.toml`, `src/main.rs` in this directory), four release builds (`target-jit`, `target-pulley`, `target-jit-ncs`, `target-pulley-ncs`; `ncs` = yara-x `native-code-serialization`). All 11 rules compiled from source with the eight struct globals defined per `rules/README.md`. One reused `Scanner`, `item` global set per file (kind derived from file name, `file_type = "text"`), every rule run on every file (no `kinds` pre-filter), files preloaded into memory so disk I/O is excluded. 20 passes, median pass reported. Cold start: 30 process spawns after 3 warm-ups, median wall time measured from the parent (`cold.py`). Raw output: `result-*.json`, `cold-results.json`.

## Setup

- Machine: Apple M2 Max, 64 GB, macOS 26.6.2 (25G83). rustc/cargo 1.98.1 (Homebrew).
- yara-x 1.20.0 (default features), wasmtime 45.0.3, pulley-interpreter 45.0.3, cranelift 0.132.3.
- Corpus: 3,189 files, 23,239,647 bytes (22.2 MiB). 3,049 from `~/.claude` (md, json, toml, yaml, yml, sh; under 1 MB; no `projects/`, no `*.jsonl`), 123 from `rules/**`, 17 from `docs/`. No duplication was needed. By type: 1,699 md, 1,223 json, 104 sh, 80 toml, 31 yaml/yml, 41 extensionless fixture `content` files, 11 yar.

## Enabling pulley

- Dependency line: `yara-x = { version = "1.20", features = ["pulley"] }`
- It coexists with default features; nothing has to be disabled. yara-x declares `pulley = ["wasmtime/pulley"]` and, when the feature is on, calls `config.target("pulley64")` on the wasmtime `Config` (`yara-x-1.20.0/src/wasm/mod.rs:750`). Cranelift is still linked (wasmtime is pulled with a hard-coded `cranelift` feature) but it emits Pulley bytecode, not arm64 code.
- wasmtime marks a Pulley `.text` section `SH_WASMTIME_NOT_EXECUTED`, so `CodeMemory::publish` skips `make_executable` (`wasmtime-45.0.3/src/runtime/code_memory.rs:204` and `:449`). No page is ever made executable. Confirmed empirically below.
- Binary size is unchanged in practice: 27.86 MB (JIT) vs 28.01 MB (pulley), unstripped.

## Results

| Metric | JIT (default) | pulley | Factor |
|---|---|---|---|
| Rule compile from source, 11 rules (median of 30 cold processes) | 34.4 ms | 36.6 ms | 1.07x |
| Full corpus scan, 3,189 files, `item` set per file (median of 20 passes) | 54.8 ms | 62.2 ms | 1.13x |
| Per file mean, same run | 17.2 us | 19.5 us | 1.13x |
| Throughput, same run | 424 MB/s | 373 MB/s | |
| Full corpus scan, globals never set (`BENCH_SET_GLOBALS=0`) | 40.6 ms | 48.2 ms | 1.19x |
| Per file mean, globals never set | 12.7 us | 15.1 us | 1.19x |
| Cold start, process spawn to first result, rules from source (wall) | 39.5 ms | 42.2 ms | 1.07x |
| Cold start, rules from `Rules::deserialize`, default serialisation (wall) | 11.4 ms | 11.2 ms | 1.0x |
| Cold start, rules from blob built with `native-code-serialization` (wall) | 5.5 ms | 5.7 ms | 1.0x |
| `Scanner::new` | 0.3 to 0.8 ms | 0.3 to 0.5 ms | |

- Slowdown: 1.13x on a realistic full scan (1.19x worst case with the cheapest per-file setup), about 7 ms on 3,189 files. Pass spread was 51 to 57 ms (JIT) and 59 to 64 ms (pulley), so the gap is real but small.
- Why so small: only rule conditions run in wasm. Pattern search (daachorse, SIMD, regex VMs) is native Rust in both builds, and with 11 rules the conditions are a minor share of scan time. The factor will grow with many condition-heavy rules (`for` loops over `#`/`@`, `math` calls); re-measure when the corpus reaches hundreds of rules.
- Setting `item` from a `serde_json::Value` per file costs about 4.5 us per file in both builds, more than the pulley penalty (2.3 us per file).
- Cold start is dominated by rule compilation (about 35 ms of about 40 ms) in both builds. Process spawn plus dyld is about 4 to 5 ms. The single-file scan itself is 0.06 ms after compile, 0.35 ms after deserialise.
- Match results identical in both builds: 35 rule hits on 30 files, same per-rule counts (0001: 14, 0002: 8, 0003: 3, 0004: 3, 0005: 4, 0900: 3), same FNV digest over (path, rule) pairs `2967ad853af2a6fa`. With globals unset both builds also agree (38 hits, digest `a6fdf03fc797f305`). Most hits are the repo's own `bad/` fixtures and docs.

## Serialised rules

- `Rules::serialize` works in both builds: 559,003 bytes, about 1 ms to write. Without `native-code-serialization` the blob carries only the wasm module, so `deserialize` runs Cranelift again: 6.3 ms (JIT) vs 6.1 ms (pulley). Still 5x faster than compiling from source.
- With `native-code-serialization`: blob 611,934 bytes (JIT, arm64 code) vs 628,240 bytes (pulley, Pulley bytecode); `deserialize` 0.80 ms vs 0.76 ms; process start to first result 1.7 ms internal, 5.5 ms wall.
- Pulley plus `native-code-serialization` avoids native code entirely: the blob holds interpreter bytecode, load is a `Module::deserialize` with no Cranelift run, and the signed binary loads and scans it under the hardened runtime with no entitlements (exit 0, correct match). The JIT blob under the same signature is killed (exit 137).
- The rust-stack.md caveats stand: blobs are tied to the engine version and must never come from a third party, so this is a local cache of compiled packs, not a distribution format.

## Hardened runtime, no entitlements

Signed with `codesign --force -s - --options runtime <binary>`; `codesign -dvv` shows `flags=0x10002(adhoc,runtime)`. Ad hoc signing does enforce the policy on this machine.

- `bench-jit`: exit status 137 (SIGKILL), nothing on stdout or stderr. Crash report: `EXC_BAD_ACCESS`, `SIGKILL (Code Signature Invalid)`, termination namespace `CODESIGNING`, indicator `Invalid Page`. Faulting thread: unsymbolicated JIT frame called from `wasmtime TypedFunc::call_raw` from `yara_x ScanContext::eval_conditions` from `Scanner::scan`. Rule compilation and `Scanner::new` succeed; the process dies on the first jump into generated code, so there is no error to catch, only a kill.
- `bench-pulley`: exit 0, correct result for the single file and for the full corpus (35 hits, same digest, median pass 63.2 ms, so signing does not change speed).
- `bench-jit` with `com.apple.security.cs.allow-jit` only: still exit 137. wasmtime 45.0.3 does not map code with `MAP_JIT` (no occurrence in `src/runtime/vm/sys/unix/`), so the JIT entitlement does not cover it.
- `bench-jit` with `com.apple.security.cs.allow-unsigned-executable-memory`: exit 0, runs normally. This, not `allow-jit`, is the entitlement a JIT build would need. It is the broader one and removes W^X protection for the whole process, which is a poor fit for a security scanner that parses hostile input. This corrects rust-stack.md section 11 and unverified item 5.

## Verdict

Ship macOS builds with `features = ["pulley"]` and no JIT entitlement: the cost is about 13 to 19 percent of an already tiny scan time (7 ms on 3,189 files) and nothing measurable on cold start, while the JIT alternative needs `allow-unsigned-executable-memory` and otherwise dies with an uncatchable SIGKILL. If CLI cold start matters, cache `Rules::serialize` output per pack version (11 ms instead of 40 ms; 5.5 ms with `native-code-serialization`, which stays entitlement-free under pulley).

## Caveats

- Ad hoc signature, not Developer ID; the hardened runtime flag is the same, but a notarized build was not tested.
- Eleven rules only. Scan cost is dominated by native pattern matching today; the pulley factor is a lower bound for a larger, condition-heavy pack.
- Single thread, files in memory, warm page cache. Compile times in `result-*.json` are single samples and noisy (35 to 79 ms); use the cold start medians.
- yara-x default modules were left on. Trimming modules changes binary size and build time, not these numbers.
