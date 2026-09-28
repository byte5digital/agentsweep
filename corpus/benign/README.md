# The benign corpus

Public content that is known to be good, used to measure two of the five conditions of the precision bar in spec section 4.2: a T1 Rule may not hit anything here, and every weight 3 Heuristic must be at zero. The sources are listed in `manifest.toml`, pinned to a commit and to a content digest, fetched at test time over plain HTTPS and never committed. The rule authoring contract in `rules/README.md` says what the digests pin and why.

The run is `cargo run -p agentsweep-xtask -- benign-corpus`. It is also part of the default test suite, where a missing network is a skip rather than a failure; CI sets `AGENTSWEEP_CORPUS_REQUIRED` so a fetch that did not happen fails there.

## Last recorded run

Taken on 2026-09-28 after the Rule 0001 scope change, the file-name-only generated Rules and the Heuristic precision fixes of that day: 33 sources, 1843 files laid out as the adapters would see them, 130 Items scanned. No T1 Rule hit anything. Every weight 3 Heuristic is at zero.

Items each Heuristic fired on:

| Heuristic | Items | Weight |
|-----------|------:|-------:|
| 0501 | 5 | 2 |
| 0503 | 17 | 1 |
| 0504 | 3 | 2 |
| 0511 | 2 | 1 |
| 0521 | 11 | 2 |
| 0522 | 5 | 1 |
| 0523 | 1 | 2 |
| 0524 | 7 | 2 |
| 0525 | 3 | 1 |
| 0530 | 2 | 1 |
| 0540 | 6 | 1 |
| 0542 | 2 | 2 |
| 0543 | 5 | 2 |
| 0551 | 6 | 1 |
| 0584 | 1 | 1 |
| 0585 | 1 | 2 |
| 0588 | 1 | 2 |
| 0593 | 1 | 2 |

Every Heuristic not listed fired on nothing. Before the fixes, 0520 (weight 3) fired on three quoted "ignore previous instructions" phrases in anti-injection guidance, and 0001 and 0903 had two and one T1 hit on documentation; all of those are at zero now. Record a new table here whenever the pack or the manifest changes.
