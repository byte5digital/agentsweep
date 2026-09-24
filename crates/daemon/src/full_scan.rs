//! The Full Scan: everything AgentSweep protects, seen again.
//!
//! Detect every Agent, pool every project root, enumerate and hash everything,
//! recompute the watch roots and write the coverage, then run the per-Item
//! order of spec section 6.4 and advance the Baseline. It is the only Scan kind
//! that has seen it all, which is why one runs whenever the daemon starts.
//!
//! The order inside the Scan is not this module's: it is
//! [`agentsweep_core::scan_pass::ScanPass`], which applies the known actions,
//! computes `item.baseline`, runs T0, T1 and T2, asks the Drift question where
//! the specification says to ask it, and answers with the Baseline records to
//! append. What is here is the machine around that pass: reading the logs
//! before it, writing what it decided after it, and counting what it found.

use std::collections::BTreeMap;
use std::path::PathBuf;

use agentsweep_core::adapter::{Enumeration, WatchRoots};
use agentsweep_core::baseline::{Baseline, BaselineWriter};
use agentsweep_core::chain::{ChainError, ChainState};
use agentsweep_core::coverage::CoveragePlan;
use agentsweep_core::derived::{KnownActions, QuarantineManifest, TrustTable};
use agentsweep_core::drift::Declarations;
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::eventlog::EventLog;
use agentsweep_core::finding::{Category, Decided, Finding, Standing, standing};
use agentsweep_core::heuristics::Band;
use agentsweep_core::item::{ItemId, Kind, Scope};
use agentsweep_core::keychain::KeySource;
use agentsweep_core::pack::Manifest;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::rules::RulePack;
use agentsweep_core::scan_pass::{ScanKind, ScanPass};
use agentsweep_core::state::{ScanSummary, Trigger};

use crate::machine::{Machine, adapters, agents};

/// Why a Full Scan could not be run.
#[derive(Debug)]
pub enum ScanError {
    /// A chain could not be read or written.
    Chain(ChainError),
    /// The Rule Pack could not be loaded.
    Pack(String),
    /// The pass over the Items failed.
    Pass(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Chain(error) => write!(f, "{error}"),
            ScanError::Pack(detail) => write!(f, "the Rule Pack could not be loaded: {detail}"),
            ScanError::Pass(detail) => write!(f, "the Scan failed: {detail}"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<ChainError> for ScanError {
    fn from(error: ChainError) -> ScanError {
        ScanError::Chain(error)
    }
}

/// What one Full Scan left behind.
#[derive(Clone, Debug)]
pub struct ScanRun {
    /// The summary the state file keeps and the subscribe stream carries.
    pub summary: ScanSummary,
    /// Every Finding that stands, with where it stands.
    pub standing: Vec<Standing>,
    /// The Findings this Scan raised, which the next one compares against to
    /// know what is gone.
    pub raised: Vec<Finding>,
    /// The directories the watcher is to follow, recomputed by this Scan.
    pub watch_roots: WatchRoots,
    /// The project roots that were pooled.
    pub roots: Vec<PathBuf>,
    /// The Agents that were found, by adapter id.
    pub agents: Vec<(String, bool)>,
    /// What verifying the Event Log found.
    pub events: ChainState,
    /// What verifying the Baseline found.
    pub baseline: ChainState,
}

/// What a Scan reports as it goes.
pub trait Progress {
    /// The Scan looked at `done` of `total` Items.
    fn at(&self, done: usize, total: usize);
}

/// A Scan nobody is watching.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unwatched;

impl Progress for Unwatched {
    fn at(&self, _done: usize, _total: usize) {}
}

/// Runs one Full Scan over one machine and writes what it decided.
///
/// The Findings the last Scan raised are handed in, because a Finding that
/// this Scan did not raise is gone rather than absent, and only the previous
/// list can say so (spec section 4.5). A daemon that has just started hands an
/// empty list: its first Full Scan is the derivation, and nothing before it
/// stands.
pub fn run(
    machine: &Machine,
    directory: &DataDirectory,
    keys: &dyn KeySource,
    previous: &[Finding],
    trigger: Trigger,
    progress: &dyn Progress,
) -> Result<ScanRun, ScanError> {
    let started_at = Timestamp::now();
    let began = std::time::Instant::now();

    // Detect, then pool. An adapter names the projects its own Agent knows,
    // and every adapter then reads every root, which is what the `registered`
    // flag on an Item is about.
    let inventory = machine.inventory();
    let mut found = Vec::new();
    let mut roots: Vec<PathBuf> = Vec::new();
    for adapter in agents() {
        let detection = adapter.detect(&inventory);
        found.push((adapter.descriptor().agent.to_string(), detection.installed));
        for registration in adapter.projects(&inventory) {
            if registration.root.is_dir() {
                roots.push(registration.root);
            }
        }
    }
    roots.sort();
    roots.dedup();

    let host = machine.host(roots.clone());
    let adapters = adapters();

    // The workspace adapter reads the git files of every root once, and what
    // it worked out is stamped onto the Items of every other adapter.
    let workspace = agentsweep_adapter_workspace::Workspace::new();
    let provenances = workspace.provenances(&host, &roots);

    let mut enumeration = Enumeration::default();
    let mut watch_roots = WatchRoots::default();
    let mut plan = CoveragePlan::new();
    for adapter in &adapters {
        let found = adapter.enumerate(&host, &roots);
        let mut declared = adapter.watch_roots(&found);
        for root in declared.recursive.drain(..) {
            watch_roots.watch_recursively(root);
        }
        for root in declared.non_recursive.drain(..) {
            watch_roots.watch(root);
        }
        // Coverage is written for every kind the adapter yields in every Scope
        // it was handed, not only for the kinds that happened to produce an
        // Item: that is what makes a hook appearing next week `added` rather
        // than `none` (spec section 4.6.2). An Agent that is not installed
        // covers nothing, so the day it is installed its Items bootstrap
        // silently.
        if adapter.detect(&inventory).installed {
            let descriptor = adapter.descriptor();
            plan.enumerated(descriptor, &Scope::User);
            if host.system_root().is_some() {
                plan.enumerated(descriptor, &Scope::Managed);
            }
            for root in &roots {
                plan.enumerated(descriptor, &Scope::Project(root.clone()));
            }
        }
        enumeration.extend(found);
    }
    provenances.stamp(&mut enumeration);
    watch_roots.sort();
    progress.at(0, enumeration.items.len());

    // Everything the pass reads before it decides anything: what the Event Log
    // says was done, and what the Baseline last accepted.
    let log = EventLog::in_data_directory(directory);
    let view = log.read(keys)?;
    let trusted = TrustTable::rebuild(&view.events);
    let known = KnownActions::rebuild(&view.events);
    let quarantined = QuarantineManifest::rebuild(&view.events);

    let baseline = Baseline::in_data_directory(directory);
    let (mut writer, baseline_state) = BaselineWriter::open(&baseline, keys)?;
    let held = baseline.read(keys)?;

    let descriptors: Vec<_> = adapters
        .iter()
        .map(|adapter| *adapter.descriptor())
        .collect();
    let declarations = Declarations::of(&descriptors);

    let pack = RulePack::bundled().map_err(|error| ScanError::Pack(error.to_string()))?;
    let outcome = ScanPass::full(&pack, &held, &plan, &trusted, &known, &declarations)
        .at(started_at)
        .over(&mut enumeration)
        .map_err(|error| ScanError::Pass(error.to_string()))?;
    progress.at(enumeration.items.len(), enumeration.items.len());

    // Coverage first, because a Surface is covered before it is enumerated,
    // then one record per Item the Scan moved.
    for entry in outcome.entries() {
        writer.append(&entry)?;
    }

    let kinds: BTreeMap<ItemId, Kind> = enumeration
        .items
        .iter()
        .map(|item| (item.id.clone(), item.kind))
        .collect();
    let raised = outcome.report.findings.clone();
    let standing = standing(
        previous,
        &raised,
        &kinds,
        Decided {
            quarantined: &quarantined,
            trusted: &trusted,
            known: &known,
        },
    );

    let bands = count_bands(&outcome);
    let summary = ScanSummary {
        kind: ScanKind::Full,
        trigger,
        started_at,
        duration_ms: began.elapsed().as_millis() as i64,
        items: enumeration.items.len(),
        threats: raised
            .iter()
            .filter(|finding| finding.category == Category::Threat)
            .count(),
        exposures: raised
            .iter()
            .filter(|finding| finding.category == Category::Exposure)
            .count(),
        clear: bands.0,
        ambiguous: bands.1,
        suspicious: bands.2,
        rule_pack: Manifest::bundled().pack_version,
        engine: String::new(),
    };

    Ok(ScanRun {
        summary,
        standing,
        raised,
        watch_roots,
        roots,
        agents: found,
        events: view.state,
        baseline: baseline_state,
    })
}

/// How many Items fell in each Band.
fn count_bands(outcome: &agentsweep_core::scan_pass::ScanOutcome) -> (usize, usize, usize) {
    let mut counted = (0usize, 0usize, 0usize);
    for assessment in &outcome.report.assessments {
        match assessment.band {
            Band::Clear => counted.0 += 1,
            Band::Ambiguous => counted.1 += 1,
            Band::Suspicious => counted.2 += 1,
        }
    }
    counted
}
