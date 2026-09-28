---
status: accepted
date: 2026-09-28
---

# The daemon is synchronous, on blocking threads, with its own batch debouncer

The daemon serves a handful of peers over one Unix socket, follows the Surfaces through FSEvents, runs one Scan at a time and wakes once a minute to see whether a Full Scan is due. The core it drives is synchronous: a Scan is processor-bound work over files already on disk, and a YARA-X Scanner cannot move between threads. We decided that the daemon has no asynchronous runtime. The socket is served through `interprocess` with one blocking thread per connection; the accept loop, the watcher, the due check, the bundle watch, the Rule Feed fetch and the Scan each run on a thread of their own and share state through a few locks and channels. Neither the daemon nor the CLI links tokio; the menu bar app does, through Tauri, and that runtime never reaches the daemon.

The watcher gathers what changed into one batch with a debouncer of its own: a batch closes after two seconds of quiet or fifteen seconds of holding on, whichever comes first, and a batch of more than two hundred paths, a `Rescan` flag or a watcher error is a Full Scan instead (spec section 6.4). It is plain logic with no file system in it, so it is tested with synthetic events at synthetic moments. `notify-debouncer-full`, which spec section 6.1 named first, is not used: it debounces each path on its own clock, and the daemon wants one batch across every path, because one Change Scan per batch is what keeps an Agent's burst of writes to one enumeration.

If the AI Judgement queue later wants an asynchronous runtime (many concurrent requests to a cloud engine with their own deadlines), the swap is local. The socket module of the IPC crate and the daemon's service module are the two places that own threads and blocking reads; a runtime would replace the per-connection threads and the accept loop there, and the queue would run as tasks beside them. The core, the adapters, the watcher's debouncer and the Scan stay synchronous and would be called through the runtime's blocking pool. Until then a queue of at most two concurrent requests (spec section 4.4) fits on two more blocking threads.

## Considered options

- tokio for the socket and the scheduling: rejected because every piece of real work is synchronous and processor-bound, so the runtime would only wrap blocking calls in `spawn_blocking`, and it would add a large dependency to a security utility that has to be audited and whose `cargo deny` exceptions are re-read on every bump.
- `notify-debouncer-full`: rejected because it debounces per path and hands over events path by path; building one batch across paths on top of it would be a second debouncer anyway, and its per-path file-id cache is memory the daemon does not need.
- A thread pool shared by connections and Scans: rejected because a status request must be answered at once while a Full Scan runs; one thread per connection with a closed request vocabulary and a handful of peers costs nothing measurable.
