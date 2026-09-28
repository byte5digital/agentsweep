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

## 2026-09-25, milestone 6 re-measured on the final code

Machine: Apple M2 Max, 12 cores, 64 GB, macOS 26.6.2. Release build of
`agentsweepd` with `--locked`, the Scans taken with `--developer-budgets` three
times over, the idle figures from a daemon left running for fourteen minutes
after its start Full Scan and sampled with `ps` and `footprint` once a minute.

What was on the machine: 538 Items across 35 pooled project roots and both
Agents, 84 Rules in the bundled pack.

| Budget | Asked for | Measured | |
|---|---|---|---|
| Idle CPU | 0 % | 0.0 % as `ps` reads it; 0.06 % from the CPU time the process accrued | within |
| Idle memory | under 100 MB | 65 MB to 71 MB settled; 188 MB for the first five minutes after a Full Scan | within once settled |
| Change Scan | under 1 s | 0.56 s to 0.58 s | within |
| Warm Full Scan | under 10 s | 0.60 s to 0.65 s | within |
| Cold Full Scan | under 60 s | 6.8 s to 7.9 s | within |

What changed against the day before, and why:

- **The warm Full Scan of the earlier section was not warm.** `item.baseline`
  is part of the evaluation key, and the first Full Scan a machine gets reads
  every Item as `none`. The Scan after it therefore found no key of its own in
  the cache and ran every Tier again; the 1.8 s recorded yesterday is that
  second Scan. The stopwatch now runs a second Full Scan first and sweeps the
  cache the way the daemon does behind every Full Scan, and it reports how many
  Items the warm Scan judged afresh: none, on all three runs. The second Full
  Scan still takes 1.8 s to 1.9 s.
- **Idle memory is within the budget only once the allocator has handed its
  freed pages back.** The footprint stays at the start Full Scan's peak for
  about five minutes and then falls to under 70 MB without anything in the
  daemon asking for it. A Full Scan every day, and one after every batch of
  more than two hundred paths, means the daemon spends a few minutes above the
  budget after each. The figure the budget names is the settled one, which is
  why this is recorded as within, but it is the first figure to watch.
- **Idle is not quite idle while an Agent is working.** The measurement ran
  while a Claude Code session was writing into the Agent's own directory, which
  is a declared root. Over fourteen minutes that was eleven batches, of which
  two mapped to Items and ran a Change Scan of 0.63 s each and the rest mapped
  to none and ran nothing. The 0.06 % above includes them; between batches the
  process accrued no measurable CPU time.
- **The Change Scan from an edit to the Finding** was also taken end to end on
  a temporary home with a synthetic registry, the watcher following it: an
  edited MCP server entry was a Finding 2.1 s after the write on three runs out
  of three, of which two seconds are the debounce's quiet and the Change Scan
  itself took 9 ms to 13 ms.
- **Compiling the Rule Pack takes 0.78 s to 0.84 s**, unchanged, and is still
  done once at start.

## 2026-09-28, how two of the budgets are read

No new figures; the owner settled how two of the measurements above count
against specification section 6.10.

- **Idle memory is read five minutes after a Scan.** The budget of under
  100 MB is measured against the settled footprint, taken once the allocator
  has handed back the pages a Full Scan used, which on the author's machine is
  about five minutes after the Scan ends. The higher figure in those first
  minutes is recorded beside it on every measurement and is not a miss.
- **The due check wakes once a minute.** The daemon asks whether a Full Scan
  is due every fifteen minutes, as the specification says, but the loop that
  asks sleeps a minute at a time, so a wall clock that jumped (a machine that
  was asleep) is noticed soon after the wake without subscribing to a wake
  notification. That minute is part of idle: idle CPU is measured with it
  running and stays at 0.0 %.
