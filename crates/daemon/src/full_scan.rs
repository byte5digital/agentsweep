//! The Full Scan, and the machinery every recording Scan shares.
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
//! append. What is here is the machine around that pass: pooling the roots
//! before it, enumerating what the adapters declare, reading the logs, writing
//! what it decided and counting what it found. A Change Scan
//! ([`crate::change_scan`]) does the same with a smaller enumeration, so the
//! pieces below are shared rather than the Full Scan's alone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use agentsweep_core::adapter::{Descriptor, Enumeration, SWITCH_ONLY, SurfaceAdapter, WatchRoots};
use agentsweep_core::baseline::{Baseline, BaselineWriter};
use agentsweep_core::chain::{ChainError, ChainState};
use agentsweep_core::coverage::CoveragePlan;
use agentsweep_core::derived::QuarantineEntry;
use agentsweep_core::derived::{KnownActions, QuarantineManifest, TrustTable};
use agentsweep_core::drift::Declarations;
use agentsweep_core::enforcement::primitives_for;
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::evaluation::{Evaluations, NoCache};
use agentsweep_core::eventlog::{Action, EventLog};
use agentsweep_core::finding::{Category, Decided, Finding, Standing, standing};
use agentsweep_core::finding::{FindingId, FindingState, RuleStatus, Severity, Source, Tier};
use agentsweep_core::finding::{RULE_WITHDRAWN_GONE, RULE_WITHDRAWN_STOPPED};
use agentsweep_core::heuristics::Band;
use agentsweep_core::item::{ItemId, Kind, Scope};
use agentsweep_core::keychain::KeySource;
use agentsweep_core::pack::Manifest;
use agentsweep_core::packs::LoadedPack;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::rules::RulePack;
use agentsweep_core::scan_pass::{BACKGROUND_WORKERS, ScanKind, ScanPass};
use agentsweep_core::state::{ScanSummary, Trigger};

use crate::actions::{Acting, ScanActions, act_in_scan};
use crate::machine::{Machine, adapters, agents};

/// Why a Scan could not be run.
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

/// What one Scan left behind.
#[derive(Clone, Debug)]
pub struct ScanRun {
    /// The summary the state file keeps and the subscribe stream carries.
    pub summary: ScanSummary,
    /// Every Finding that stands, with where it stands. A Change Scan only
    /// ever speaks for the Items it looked at.
    pub standing: Vec<Standing>,
    /// The Findings this Scan raised, which the next one compares against to
    /// know what is gone.
    pub raised: Vec<Finding>,
    /// The Items this Scan looked at, which is what it may speak for.
    pub looked_at: BTreeSet<ItemId>,
    /// The directories the watcher is to follow, recomputed by every Full
    /// Scan and empty after a Change Scan, which never saw enough to say.
    pub watch_roots: WatchRoots,
    /// The project roots that were pooled.
    pub roots: Vec<PathBuf>,
    /// The Agents that were found, by adapter id. Empty after a Change Scan.
    pub agents: Vec<(String, bool)>,
    /// What verifying the Event Log found.
    pub events: ChainState,
    /// What verifying the Baseline found.
    pub baseline: ChainState,
    /// When the Baseline was last compacted, as the Event Log records it.
    pub last_compaction: Option<Timestamp>,
    /// What the Scan did by itself: automatic Quarantines, re-enforces and
    /// the Items that keep coming back.
    pub acted: ScanActions,
    /// The newer, clean version found for each quarantined plugin, by the
    /// Receipt that stopped it, which is what offers Re-enable.
    pub fixed_versions: BTreeMap<String, String>,
    /// The Findings whose Quarantine switches the Item off where it stands,
    /// or did, which is what labels its pair of actions.
    pub switched: BTreeSet<FindingId>,
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
    let pack = LoadedPack::bundled().map_err(|error| ScanError::Pack(error.to_string()))?;
    FullScan {
        machine,
        directory,
        keys,
        pack: &pack.rules,
        manifest: &pack.manifest,
        previous,
        cache: &NoCache,
        workers: BACKGROUND_WORKERS,
        progress,
        acts: true,
    }
    .run(trigger)
}

/// One Full Scan, with everything it is allowed to use named.
pub struct FullScan<'a> {
    /// The machine to scan.
    pub machine: &'a Machine,
    /// Where the stores are.
    pub directory: &'a DataDirectory,
    /// The chain key behind them.
    pub keys: &'a dyn KeySource,
    /// The compiled Rule Pack in force. It is compiled once per daemon and
    /// handed to every Scan: compiling it per Scan would cost more than the
    /// Change Scan is allowed to take altogether (spec section 6.10).
    pub pack: &'a RulePack,
    /// What that pack states about itself: its version, which the Scan
    /// summary and the evaluation cache carry, and its Band thresholds.
    pub manifest: &'a Manifest,
    /// The Findings the last Scan raised.
    pub previous: &'a [Finding],
    /// The Tier outcomes this daemon already has.
    pub cache: &'a dyn Evaluations,
    /// How many worker threads run the Tiers.
    pub workers: usize,
    /// Who is told how far it has got.
    pub progress: &'a dyn Progress,
    /// Whether the Scan may act by itself: quarantine what a stable Rule
    /// proves bad and take out again what came back. The daemon's Scans do; a
    /// measurement of the budgets never touches the machine it measures.
    pub acts: bool,
}

impl FullScan<'_> {
    /// Detects, pools, enumerates everything and judges it.
    pub fn run(&self, trigger: Trigger) -> Result<ScanRun, ScanError> {
        let started_at = Timestamp::now();
        let began = std::time::Instant::now();

        let inventory = pool(self.machine);
        let adapters = adapters();
        let mut survey = survey(
            self.machine,
            &adapters,
            &inventory.roots,
            Covering::Everything(&inventory),
        );
        self.progress.at(0, survey.enumeration.items.len());

        let descriptors: Vec<Descriptor> = adapters
            .iter()
            .map(|adapter| *adapter.descriptor())
            .collect();
        let acting = Acting {
            machine: self.machine,
            roots: &inventory.roots,
        };
        let judged = Judgement {
            kind: ScanKind::Full,
            directory: self.directory,
            keys: self.keys,
            pack: self.pack,
            manifest: self.manifest,
            plan: &survey.plan,
            descriptors: &descriptors,
            previous: self.previous,
            trigger,
            at: started_at,
            cache: self.cache,
            workers: self.workers,
            acting: self.acts.then_some(&acting),
        }
        .over(&mut survey.enumeration, began)?;
        self.progress.at(
            survey.enumeration.items.len(),
            survey.enumeration.items.len(),
        );

        Ok(ScanRun {
            summary: judged.summary,
            standing: judged.standing,
            raised: judged.raised,
            looked_at: judged.looked_at,
            watch_roots: survey.watch_roots,
            roots: inventory.roots,
            agents: inventory.agents,
            events: judged.events,
            baseline: judged.baseline,
            last_compaction: judged.last_compaction,
            acted: judged.acted,
            fixed_versions: judged.fixed_versions,
            switched: judged.switched,
        })
    }
}

/// What the Agents' own registries say this machine holds.
#[derive(Clone, Debug, Default)]
pub struct Pooled {
    /// The Agents that were found, by adapter id.
    pub agents: Vec<(String, bool)>,
    /// Every project root any Agent's registry names and that is still there,
    /// pooled across the Agents and in a stable order.
    pub roots: Vec<PathBuf>,
}

/// Detects every Agent and pools every project root its own registry names.
///
/// Never crawls the file system: an Agent's registry is the only place a
/// project comes from, which is why re-pooling costs one read of the home
/// (spec section 1.2).
pub fn pool(machine: &Machine) -> Pooled {
    let host = machine.inventory();
    let mut pooled = Pooled::default();
    for adapter in agents() {
        let detection = adapter.detect(&host);
        pooled
            .agents
            .push((adapter.descriptor().agent.to_string(), detection.installed));
        for registration in adapter.projects(&host) {
            if registration.root.is_dir() {
                pooled.roots.push(registration.root);
            }
        }
    }
    pooled.roots.sort();
    pooled.roots.dedup();
    pooled
}

/// Which Surfaces one enumeration stands as coverage for.
#[derive(Clone, Copy, Debug)]
pub enum Covering<'a> {
    /// Everything an installed Agent has: the user's own Scope, the Managed
    /// layers where there are any, and every pooled root.
    Everything(&'a Pooled),
    /// Only these roots, which is what a Change Scan that bootstrapped a
    /// newly registered project may claim.
    Roots(&'a [PathBuf]),
}

/// What one enumeration of a machine found.
#[derive(Debug, Default)]
pub struct Survey {
    /// The Items and the Problems.
    pub enumeration: Enumeration,
    /// The directories the watcher is to follow.
    pub watch_roots: WatchRoots,
    /// The coverage this enumeration stands for.
    pub plan: CoveragePlan,
}

/// Enumerates one machine with the adapters and roots given.
///
/// The workspace adapter reads the git files of every root once and what it
/// worked out is stamped onto the Items of every other adapter, which is why
/// it is always in the list the caller hands over and always first.
pub fn survey(
    machine: &Machine,
    adapters: &[Box<dyn SurfaceAdapter>],
    roots: &[PathBuf],
    covering: Covering<'_>,
) -> Survey {
    let host = machine.host(roots.to_vec());
    let workspace = agentsweep_adapter_workspace::Workspace::new();
    let provenances = workspace.provenances(&host, roots);

    let mut survey = Survey::default();
    for adapter in adapters {
        let found = adapter.enumerate(&host, roots);
        let mut declared = adapter.watch_roots(&found);
        for root in declared.recursive.drain(..) {
            survey.watch_roots.watch_recursively(root);
        }
        for root in declared.non_recursive.drain(..) {
            survey.watch_roots.watch(root);
        }
        // Coverage is written for every kind the adapter yields in every Scope
        // it was handed, not only for the kinds that happened to produce an
        // Item: that is what makes a hook appearing next week `added` rather
        // than `none` (spec section 4.6.2). An Agent that is not installed
        // covers nothing, so the day it is installed its Items bootstrap
        // silently.
        let descriptor = adapter.descriptor();
        match covering {
            Covering::Everything(pooled) => {
                if adapter.detect(&host).installed {
                    survey.plan.enumerated(descriptor, &Scope::User);
                    if host.system_root().is_some() {
                        survey.plan.enumerated(descriptor, &Scope::Managed);
                    }
                    for root in &pooled.roots {
                        survey
                            .plan
                            .enumerated(descriptor, &Scope::Project(root.clone()));
                    }
                }
            }
            // A Change Scan covers only what it enumerated whole, which is a
            // root it has just bootstrapped and never the user's own Scope.
            Covering::Roots(claimed) => {
                if adapter.detect(&host).installed {
                    for root in claimed {
                        survey
                            .plan
                            .enumerated(descriptor, &Scope::Project(root.clone()));
                    }
                }
            }
        }
        survey.enumeration.extend(found);
    }
    provenances.stamp(&mut survey.enumeration);
    survey.watch_roots.sort();
    survey
}

/// What one pass over one enumeration decided, before the Scan-level facts are
/// put around it.
#[derive(Clone, Debug)]
pub struct Judged {
    /// The summary.
    pub summary: ScanSummary,
    /// Every Finding that stands.
    pub standing: Vec<Standing>,
    /// What this pass raised.
    pub raised: Vec<Finding>,
    /// The Items it looked at.
    pub looked_at: BTreeSet<ItemId>,
    /// What verifying the Event Log found.
    pub events: ChainState,
    /// What verifying the Baseline found.
    pub baseline: ChainState,
    /// When the Baseline was last compacted, as the Event Log records it.
    pub last_compaction: Option<Timestamp>,
    /// What the pass did by itself.
    pub acted: ScanActions,
    /// The newer, clean version of each quarantined plugin, by Receipt.
    pub fixed_versions: BTreeMap<String, String>,
    /// The Findings whose Quarantine is, or was, the Agent's own switch alone.
    pub switched: BTreeSet<FindingId>,
}

/// Reading the stores, running one pass and writing what it decided.
pub struct Judgement<'a> {
    /// Which Scan kind is running.
    pub kind: ScanKind,
    /// Where the stores are.
    pub directory: &'a DataDirectory,
    /// The chain key behind them.
    pub keys: &'a dyn KeySource,
    /// The compiled Rule Pack in force.
    pub pack: &'a RulePack,
    /// What it states about itself.
    pub manifest: &'a Manifest,
    /// The coverage this enumeration stands for.
    pub plan: &'a CoveragePlan,
    /// The adapters whose declarations a Drift decision reads.
    pub descriptors: &'a [Descriptor],
    /// The Findings the last Scan of these Items raised.
    pub previous: &'a [Finding],
    /// What started this Scan.
    pub trigger: Trigger,
    /// The moment it stands at.
    pub at: Timestamp,
    /// The Tier outcomes already held.
    pub cache: &'a dyn Evaluations,
    /// How many worker threads run the Tiers.
    pub workers: usize,
    /// Where the pass may act by itself, absent when it may not.
    pub acting: Option<&'a Acting<'a>>,
}

impl Judgement<'_> {
    /// Runs the pass and appends what it accepted.
    pub fn over(
        &self,
        enumeration: &mut Enumeration,
        began: std::time::Instant,
    ) -> Result<Judged, ScanError> {
        // Everything the pass reads before it decides anything: what the Event
        // Log says was done, and what the Baseline last accepted.
        let log = EventLog::in_data_directory(self.directory);
        let view = log.read(self.keys)?;
        let trusted = TrustTable::rebuild(&view.events);
        let known = KnownActions::rebuild(&view.events);
        let quarantined = QuarantineManifest::rebuild(&view.events);

        let baseline = Baseline::in_data_directory(self.directory);
        let (mut writer, baseline_state) = BaselineWriter::open(&baseline, self.keys)?;
        let held = baseline.read(self.keys)?;

        let declarations = Declarations::of(self.descriptors);
        let rule_pack = self.manifest.pack_version;

        let start = match self.kind {
            ScanKind::Change => ScanPass::change,
            _ => ScanPass::full,
        };
        let outcome = start(self.pack, &held, self.plan, &trusted, &known, &declarations)
            .with_bands(self.manifest.bands)
            .caching(self.cache, rule_pack, "")
            .with_workers(self.workers)
            .at(self.at)
            .over(enumeration)
            .map_err(|error| ScanError::Pass(error.to_string()))?;

        // The Tiers have decided. What a stable Rule proves bad on a kind
        // that may be taken out by itself is taken out now, in the per-Item
        // order, and what AgentSweep took out before and came back is taken
        // out again: both before the Baseline advances (spec section 6.4). A
        // chain that was tampered with freezes all of it until the user has
        // looked (ADR 0003).
        let frozen = view.state.freezes_automatic_quarantine()
            || baseline_state.freezes_automatic_quarantine();
        let acted = match self.acting {
            Some(acting) => act_in_scan(
                acting,
                self.directory,
                self.keys,
                enumeration,
                &outcome.report.findings,
                &quarantined,
                frozen,
                self.at,
            ),
            None => ScanActions::default(),
        };

        // Coverage first, because a Surface is covered before it is
        // enumerated, then one record per Item the Scan moved.
        for entry in outcome.entries() {
            writer.append(&entry)?;
        }

        // Whatever the pass did by itself is in the Event Log now, and where
        // every Finding stands is read from what the log says after it.
        let (quarantined, trusted, known) = match acted.wrote() {
            true => {
                let after = log.read(self.keys)?;
                (
                    QuarantineManifest::rebuild(&after.events),
                    TrustTable::rebuild(&after.events),
                    KnownActions::rebuild(&after.events),
                )
            }
            false => (quarantined, trusted, known),
        };

        let kinds: BTreeMap<ItemId, Kind> = enumeration
            .items
            .iter()
            .map(|item| (item.id.clone(), item.kind))
            .collect();
        let mut raised = outcome.report.findings.clone();
        raised.extend(acted.keeps_coming_back.iter().cloned());
        let mut standing = standing(
            self.previous,
            &raised,
            &kinds,
            Decided {
                quarantined: &quarantined,
                trusted: &trusted,
                known: &known,
            },
        );
        // An Item that is back on its Surface with the content a Receipt took
        // out, and was not taken out again, is not stopped: the Agent would
        // load it. Its Findings are open, beside the one that says it keeps
        // coming back.
        for placed in standing.iter_mut() {
            if placed.state == FindingState::Stopped
                && acted.returned.contains(&placed.finding.item_id)
            {
                placed.state = FindingState::Open;
                placed.receipt_id.clear();
            }
        }
        // A Full Scan speaks for everything, so what the store holds stands
        // as stopped even when no Scan since raised it: the Item is not on
        // its Surface to raise anything about, and the Receipt is the record.
        if self.kind == ScanKind::Full {
            let present: BTreeSet<&ItemId> = kinds.keys().collect();
            let mut held: Vec<&QuarantineEntry> = quarantined
                .entries()
                .filter(|entry| !present.contains(&entry.item_id))
                .collect();
            held.sort_by_key(|entry| entry.quarantined_at);
            for entry in held {
                let stopped = stopped_by(entry, self.pack);
                if standing.iter().any(|placed| placed.id == stopped.id) {
                    continue;
                }
                standing.push(stopped);
            }
        }
        withdrawn(&mut standing, self.pack);
        let fixed_versions = fixed_versions(&quarantined, enumeration, &raised);
        let switched = switched(&standing, &quarantined, enumeration, self.acting);

        let bands = count_bands(&outcome);
        let summary = ScanSummary {
            kind: self.kind,
            trigger: self.trigger,
            started_at: self.at,
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
            rule_pack,
            engine: String::new(),
        };

        Ok(Judged {
            summary,
            standing,
            raised,
            looked_at: kinds.into_keys().collect(),
            events: view.state,
            baseline: baseline_state,
            last_compaction: view
                .events
                .iter()
                .filter(|recorded| recorded.event.action == Action::BaselineCompacted)
                .map(|recorded| recorded.recorded_at)
                .next_back(),
            acted,
            fixed_versions,
            switched,
        })
    }
}

/// Says what the Rule Pack in force no longer stands behind.
///
/// Nothing here decides anything: the pack decided, by not carrying the Rule
/// any more. A Finding it raised under the previous pack and that this Scan
/// did not raise is already gone, and says why. A quarantined Item stays
/// where it is, in the store, and says that the Rule that stopped it was
/// withdrawn; Restore is what it offers first (spec sections 6.4 and 8.4).
/// The Activity line for a withdrawal is not made here: it is built from the
/// `rule-pack` record the daemon wrote when the pack was put in force, so it
/// outlives the daemon that saw it.
fn withdrawn(standing: &mut [Standing], pack: &RulePack) {
    for placed in standing.iter_mut() {
        let Source::Rule(id) = placed.finding.source else {
            continue;
        };
        if pack.metas().any(|meta| meta.id == id) {
            continue;
        }
        match placed.state {
            FindingState::Stopped => {
                placed.finding.plain = RULE_WITHDRAWN_STOPPED.to_string();
            }
            FindingState::Gone => {
                placed.finding.plain = RULE_WITHDRAWN_GONE.to_string();
            }
            _ => {}
        }
    }
}

/// The stopped Finding one Receipt stands for, built from the Event Log and
/// the Rule Pack alone, for an Item no Scan raises anything about any more
/// because it is in the store.
fn stopped_by(entry: &QuarantineEntry, pack: &RulePack) -> Standing {
    let source = entry
        .finding_id
        .split('|')
        .nth(1)
        .and_then(|segment| match segment {
            "score" => Some(Source::Score(0)),
            "drift" => Some(Source::Drift),
            "keeps-coming-back" => Some(Source::KeepsComingBack),
            rule => rule
                .strip_prefix("rule/")
                .and_then(|id| id.parse::<i64>().ok())
                .map(Source::Rule),
        })
        .unwrap_or(Source::Rule(entry.rule_id));
    let meta = pack.metas().find(|meta| meta.id == entry.rule_id);
    let finding = Finding {
        item_id: entry.item_id.clone(),
        source,
        content_hash: entry.content_hash.clone(),
        category: meta.map(|meta| meta.category).unwrap_or(Category::Threat),
        severity: meta.map(|meta| meta.severity).unwrap_or(Severity::High),
        tier: entry
            .tier
            .or(meta.map(|meta| meta.tier))
            .unwrap_or(Tier::Rules),
        status: meta
            .map(|meta| meta.status)
            .unwrap_or(RuleStatus::Probation),
        title: meta
            .map(|meta| meta.title.clone())
            .unwrap_or_else(|| "Quarantined by AgentSweep".to_string()),
        plain: match (meta, source) {
            (Some(meta), _) => meta.plain.clone(),
            // A Receipt made on a Rule the pack in force no longer carries:
            // the Item stays stopped and says the Rule was withdrawn.
            (None, Source::Rule(id)) if id != 0 => RULE_WITHDRAWN_STOPPED.to_string(),
            (None, _) => {
                "AgentSweep took this out of its place, so the Agent cannot load it.".to_string()
            }
        },
        sensitive: meta.is_some_and(|meta| meta.sensitive),
        file: String::new(),
        matches: Vec::new(),
        heuristics: Vec::new(),
        drift: None,
    };
    let id = match entry.finding_id.is_empty() {
        true => FindingId::of(&finding),
        false => FindingId::from_recorded(&entry.finding_id),
    };
    Standing {
        id,
        finding,
        state: FindingState::Stopped,
        receipt_id: entry.receipt_id.clone(),
    }
}

/// The Findings whose Quarantine is the Agent's own switch alone: a stopped
/// one whose Receipt switched the Item off in place, and an open one on an
/// Item the adapter would switch off rather than take out, asked of the file
/// as it stands. Nothing is written; it only decides how the pair of actions
/// reads.
fn switched(
    standing: &[Standing],
    quarantined: &QuarantineManifest,
    enumeration: &Enumeration,
    acting: Option<&Acting<'_>>,
) -> BTreeSet<FindingId> {
    let host = acting.map(Acting::host);
    let mut switched = BTreeSet::new();
    for placed in standing {
        let by_receipt = quarantined
            .for_receipt(&placed.receipt_id)
            .map(QuarantineEntry::switched_in_place);
        let flips = match (by_receipt, &host) {
            (Some(done), _) => done,
            (None, Some(host)) => enumeration
                .items
                .iter()
                .find(|item| item.id == placed.finding.item_id)
                .and_then(|item| {
                    let adapter = crate::actions::adapter_for(&item.agent)?;
                    primitives_for(&*adapter, host, item).ok()
                })
                .is_some_and(|primitives| primitives == SWITCH_ONLY),
            (None, None) => false,
        };
        if flips {
            switched.insert(placed.id.clone());
        }
    }
    switched
}

/// The newer version of each quarantined plugin that this Scan found and
/// raised no Threat Finding on, by the Receipt that stopped the old one.
///
/// Nothing is switched on because of it: it is what offers the one-click
/// Re-enable, which the user asks for (spec section 5.4).
fn fixed_versions(
    quarantined: &QuarantineManifest,
    enumeration: &Enumeration,
    raised: &[Finding],
) -> BTreeMap<String, String> {
    let mut fixed = BTreeMap::new();
    for entry in quarantined.entries() {
        if entry.kind != Some(Kind::Plugin) || !entry.natively_disabled {
            continue;
        }
        let Some(newer) = enumeration
            .items
            .iter()
            .find(|item| item.id == entry.item_id && item.content_hash != entry.content_hash)
        else {
            continue;
        };
        let threatened = raised.iter().any(|finding| {
            finding.item_id == newer.id
                && finding.content_hash == newer.content_hash
                && finding.category == Category::Threat
        });
        if !threatened {
            fixed.insert(entry.receipt_id.clone(), newer.content_hash.clone());
        }
    }
    fixed
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
