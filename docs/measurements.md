# Measurements

The budgets of specification section 6.10, measured rather than assumed. Every
figure here was taken on the author's own machine with a release build, against
the author's own home directory, with the stores and the socket in a temporary
directory that was deleted afterwards and the chain key held in the process
rather than in the login Keychain. No path, Item count detail, Finding or
anything else read out of that home is recorded here beyond the totals below.

Re-measure on every milestone that changes what a Scan does, and add a dated
section rather than editing an old one.

## 2026-09-24, milestone 6 (watcher, Change Scans, due check)

Machine: Apple M2 Max, 12 cores, 64 GB, macOS 26.6.2. Release build of
`agentsweepd`, taken with `--developer-budgets` for the Scans and by sampling
the running daemon for the idle figures.

What was on the machine: 535 Items across 35 pooled project roots and both
Agents, 84 Rules in the bundled pack.

| Budget | Asked for | Measured | |
|---|---|---|---|
| Idle CPU | 0 % | 0.0 % over three idle minutes | within |
| Idle memory | under 100 MB | 58.5 MB settled | within |
| Change Scan | under 1 s | 0.53 s to 0.61 s | within |
| Warm Full Scan | under 10 s | 1.8 s | within |
| Cold Full Scan | under 60 s | 6.4 s to 7.8 s | within |

Three notes that are not budget misses but are worth keeping:

- **Peak memory during a cold Full Scan is 218 MB.** The budget speaks only of
  idle memory and the figure settles to 58.5 MB within a few minutes of the
  Scan finishing, but a Scan that enumerates eagerly holds every Item's content
  at once, and on a machine with far more or far larger trees that peak is what
  would grow first. The physical footprint is the figure quoted throughout;
  resident size reads higher because it counts shared library pages.
- **Compiling the Rule Pack takes 0.77 s**, which is more than a Change Scan is
  allowed to take altogether. The daemon therefore compiles it once at start
  and hands the compiled pack to every Scan. A Scan that compiled its own would
  miss the Change Scan budget on any machine.
- **Most of a Change Scan is enumeration, not detection.** The adapters
  enumerate a whole Scope or none of it, so a Change Scan of one edited registry
  entry still reads the user-level Surfaces of both Agents. It judges only the
  Items the batch maps to, which is what keeps it at half a second, and the
  headroom to the one-second budget is what a much larger user-level
  installation would eat into first.

The measurement ran three times; the spread above is across those runs. Idle
CPU was sampled with `ps` over three minutes with the watcher following 90
declared roots, during which the daemon ran four Change Scans triggered by the
machine's own ordinary activity, each between 0.56 s and 0.61 s.
