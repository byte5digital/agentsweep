//! The developer's stopwatch: the Scan budgets of spec section 6.10, measured
//! on the machine this is run on.
//!
//! It is off unless asked for by name and it is the one thing in the daemon
//! that looks at a real home on purpose, which is why it refuses to run
//! anywhere near the installed data directory or the login Keychain. It writes
//! only into the data directory it was given, binds no socket, registers
//! nothing and starts neither the watcher nor the due check.
//!
//! What it prints is a handful of durations and counts. It never prints a path, a
//! content hash or anything read out of the home, so the output of a run
//! against the author's own machine can be quoted in a measurements note
//! without leaking what is on it.

use std::error::Error;
use std::time::Instant;

use agentsweep_core::evaluation::EvaluationCache;
use agentsweep_core::keychain::MemoryKeySource;
use agentsweep_core::packs::LoadedPack;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::scan_pass::BACKGROUND_WORKERS;
use agentsweep_core::state::Trigger;

use crate::change_scan::ChangeScan;
use crate::full_scan::{FullScan, Unwatched};
use crate::machine::Machine;
use crate::options::{KeySourceChoice, Options};
use crate::watcher::Batch;

/// Runs the measurements and prints them.
pub fn measure(options: &Options) -> Result<(), Box<dyn Error>> {
    if options.key_source != KeySourceChoice::Memory {
        return Err("measuring takes `--key-source memory`: it may not touch the Keychain".into());
    }
    if Some(&options.data_dir) == DataDirectory::for_user().as_ref() {
        return Err(
            "measuring takes a `--data-dir` of its own: it may not write the installed one".into(),
        );
    }
    let directory = options.data_dir.clone();
    directory.create()?;
    let keys = MemoryKeySource::empty();
    let machine = match &options.home {
        Some(home) => Machine::named(home.clone()),
        None => Machine::real(options.home_directory()?),
    };

    let began = Instant::now();
    let loaded = LoadedPack::bundled()?;
    let pack = &loaded.rules;
    println!(
        "rule pack: {} rules compiled in {} ms",
        pack.len(),
        began.elapsed().as_millis()
    );

    // Cold: an empty evaluation cache and a Baseline that knows nothing, which
    // is the first Full Scan a machine ever gets.
    let cache = EvaluationCache::new();
    let scan = FullScan {
        machine: &machine,
        directory: &directory,
        keys: &keys,
        pack,
        manifest: &loaded.manifest,
        previous: &[],
        cache: &cache,
        workers: BACKGROUND_WORKERS,
        progress: &Unwatched,
        // A measurement reads the machine and never acts on it.
        acts: false,
    };
    let cold = scan.run(Trigger::DaemonStart)?;
    cache.sweep();
    println!(
        "cold Full Scan: {} ms, {} Items, {} Findings, {} project roots",
        cold.summary.duration_ms,
        cold.summary.items,
        cold.summary.findings(),
        cold.roots.len()
    );

    // The second Full Scan a machine gets is not yet a warm one: the cold
    // Scan judged every Item with `item.baseline` at `none`, which is part of
    // the evaluation key, so every key it left behind belongs to a Baseline
    // that no longer holds. This Scan fills the cache under the Baseline the
    // daemon will keep seeing, and the sweep after it is the one the daemon
    // makes behind every Full Scan.
    let second = scan.run(Trigger::Due)?;
    cache.sweep();
    println!(
        "second Full Scan: {} ms, {} Items",
        second.summary.duration_ms, second.summary.items
    );

    // Warm: everything re-enumerated and re-hashed, the Tiers skipped for every
    // key the Scan before it left in the cache. A key it misses is a key it
    // adds, so the difference in size is the count of Items judged afresh.
    let held = cache.len();
    let warm = scan.run(Trigger::ScanNow)?;
    println!(
        "warm Full Scan: {} ms, {} Items, {} cached keys, {} judged afresh",
        warm.summary.duration_ms,
        warm.summary.items,
        cache.len(),
        cache.len().saturating_sub(held)
    );

    // One edited MCP entry: the user registry of the first Agent that has one.
    let Some(registry) = user_registry(&machine) else {
        println!("Change Scan: no user registry on this machine to stand in for one");
        return Ok(());
    };
    let change = ChangeScan {
        machine: &machine,
        directory: &directory,
        keys: &keys,
        pack,
        manifest: &loaded.manifest,
        previous: &cold.raised,
        pooled: &warm.roots,
        cache: &cache,
        workers: BACKGROUND_WORKERS,
        acts: false,
    }
    .run(&Batch::of([registry]))?;
    match change {
        Some(change) => println!(
            "Change Scan of one registry entry: {} ms, {} Items",
            change.summary.duration_ms, change.summary.items
        ),
        None => println!("Change Scan: the registry of this machine holds no Item"),
    }
    Ok(())
}

/// The user registry of the first Agent that has one, which is the file an
/// edited MCP server entry lives in.
fn user_registry(machine: &Machine) -> Option<std::path::PathBuf> {
    let home = machine.home();
    [".claude.json", ".codex/config.toml"]
        .into_iter()
        .map(|relative| home.join(relative))
        .find(|path| path.is_file())
}
