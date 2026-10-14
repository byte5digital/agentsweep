//! The Change Scan: only the Items behind one batch of changed paths.
//!
//! It never claims to have seen anything it was not told about (`CONTEXT.md`).
//! The batch is mapped to Items through each adapter's `items_for_path`, only
//! those Items are judged, and the Findings the last Scan raised about other
//! Items are left exactly where they were rather than being declared gone.
//!
//! Two things happen besides. The roots are pooled again, because the batch may
//! have touched an Agent's own project registry and a project that has just
//! been trusted is a Surface AgentSweep has never looked at. Such a root is
//! enumerated whole and bootstrapped silently: its coverage is written by this
//! Scan, so every Item in it reads `none` and none of them is Drift (spec
//! section 6.4). And the enumeration is kept to what the batch could possibly
//! be about: the pooled roots a changed path falls inside, plus the roots that
//! have just appeared. The user's own Scope is always read, because that is
//! where most of what AgentSweep protects lives and an adapter enumerates it
//! whole or not at all.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use agentsweep_core::adapter::Descriptor;
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::evaluation::Evaluations;
use agentsweep_core::finding::Finding;
use agentsweep_core::item::{ItemId, Scope};
use agentsweep_core::keychain::KeySource;
use agentsweep_core::pack::Manifest;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::rules::RulePack;
use agentsweep_core::scan_pass::ScanKind;
use agentsweep_core::state::Trigger;

use crate::actions::Acting;
use crate::full_scan::{Covering, Judgement, ScanError, ScanRun, pool, survey};
use crate::machine::{Machine, adapters};
use crate::permission::Access;
use crate::watcher::Batch;

/// One Change Scan, with everything it is allowed to use named.
pub struct ChangeScan<'a> {
    /// The machine to scan.
    pub machine: &'a Machine,
    /// What the Scan may read by itself, as for a Full Scan: a newly
    /// registered root that Needs Permission is never bootstrapped.
    pub access: Access<'a>,
    /// Where the stores are.
    pub directory: &'a DataDirectory,
    /// The chain key behind them.
    pub keys: &'a dyn KeySource,
    /// The compiled Rule Pack in force.
    pub pack: &'a RulePack,
    /// What it states about itself.
    pub manifest: &'a Manifest,
    /// Every Finding the last Scan left standing. The ones about Items this
    /// Scan does not look at come back untouched.
    pub previous: &'a [Finding],
    /// The project roots the last Full Scan pooled. A root that is not among
    /// them and is in a registry now is one this Scan bootstraps.
    pub pooled: &'a [PathBuf],
    /// The Tier outcomes this daemon already has.
    pub cache: &'a dyn Evaluations,
    /// The active Judgement Engine, None while AI Judgement is off.
    pub judge: Option<&'a agentsweep_core::judged::Judge>,
    /// How many worker threads run the Tiers.
    pub workers: usize,
    /// Whether the Scan may act by itself, as a Full Scan may.
    pub acts: bool,
}

impl ChangeScan<'_> {
    /// Scans the Items behind one batch of changed paths.
    ///
    /// Answers with nothing when the batch turned out to be about no Item at
    /// all. A watched root holds more than Surfaces: an Agent writes its own
    /// transcripts, its todo lists and its shell snapshots inside the very
    /// directory its skills and settings live in, and none of that is an Item.
    /// Such a batch is a Scan of nothing, and a Scan of nothing is not worth a
    /// line in the Scan history, a state file write or an event.
    pub fn run(&self, batch: &Batch) -> Result<Option<ScanRun>, ScanError> {
        let started_at = Timestamp::now();
        let began = std::time::Instant::now();

        // The registries are read again on every batch. They are the only
        // place a project comes from and reading them is reading the home, so
        // a batch that touched one re-pools without anybody having to work out
        // which file is a registry.
        let inventory = pool(self.machine, &self.access);
        let bootstrapped: Vec<PathBuf> = inventory
            .roots
            .iter()
            .filter(|root| !self.pooled.contains(root))
            .cloned()
            .collect();

        let touched = in_play(&inventory.roots, batch, &bootstrapped);
        let adapters = adapters();
        let mut survey = survey(
            self.machine,
            &adapters,
            &touched,
            Covering::Roots(&bootstrapped),
        );

        // What the batch is about: the Items every adapter maps its paths to,
        // and everything in a root that has just been bootstrapped, which no
        // path in the batch points at.
        let mut wanted: BTreeSet<ItemId> = BTreeSet::new();
        for adapter in &adapters {
            for path in batch.paths() {
                wanted.extend(adapter.items_for_path(&survey.enumeration, path));
            }
        }
        for item in &survey.enumeration.items {
            if let Scope::Project(root) = &item.scope
                && bootstrapped.contains(root)
            {
                wanted.insert(item.id.clone());
            }
        }
        survey
            .enumeration
            .items
            .retain(|item| wanted.contains(&item.id));
        survey
            .enumeration
            .problems
            .retain(|problem| told_about(&problem.path, batch, &bootstrapped));

        if survey.enumeration.items.is_empty() && survey.enumeration.problems.is_empty() {
            return Ok(None);
        }

        // Only the Findings about Items this Scan looks at may be declared
        // gone by it; the rest are not its business and are handed back as
        // they were.
        let mine: Vec<Finding> = self
            .previous
            .iter()
            .filter(|finding| wanted.contains(&finding.item_id))
            .cloned()
            .collect();

        let descriptors: Vec<Descriptor> = adapters
            .iter()
            .map(|adapter| *adapter.descriptor())
            .collect();
        let acting = Acting {
            machine: self.machine,
            roots: &touched,
        };
        let judged = Judgement {
            kind: ScanKind::Change,
            directory: self.directory,
            keys: self.keys,
            pack: self.pack,
            manifest: self.manifest,
            plan: &survey.plan,
            descriptors: &descriptors,
            previous: &mine,
            trigger: Trigger::Watcher,
            at: started_at,
            cache: self.cache,
            judge: self.judge,
            workers: self.workers,
            acting: self.acts.then_some(&acting),
        }
        .over(&mut survey.enumeration, began)?;

        Ok(Some(ScanRun {
            summary: judged.summary,
            standing: judged.standing,
            raised: judged.raised,
            looked_at: judged.looked_at,
            // A Change Scan never saw enough to recompute the watch roots, and
            // says so by declaring none.
            watch_roots: agentsweep_core::adapter::WatchRoots::default(),
            roots: inventory.roots,
            withheld: Vec::new(),
            agents: Vec::new(),
            events: judged.events,
            baseline: judged.baseline,
            last_compaction: judged.last_compaction,
            acted: judged.acted,
            fixed_versions: judged.fixed_versions,
            facts: judged.facts,
            switched: judged.switched,
            gate_facts: judged.gate_facts,
            // A Change Scan never detected every Agent nor read every root, so
            // it speaks only for the Ambiguous Items among the ones it looked
            // at.
            overview: agentsweep_core::overview::Overview {
                ambiguous: judged.ambiguous,
                checked: judged.checked,
                ..Default::default()
            },
            // Only a Full Scan checks the Gate's registration.
            gate_lines: None,
        }))
    }
}

/// The project roots this batch could be about: the ones a changed path falls
/// inside, and the ones that have just appeared in a registry.
fn in_play(pooled: &[PathBuf], batch: &Batch, bootstrapped: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = pooled
        .iter()
        .filter(|root| {
            bootstrapped.contains(root) || batch.paths().any(|path| path.starts_with(root))
        })
        .cloned()
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// True when this path is one the watcher told the Scan about, or sits in a
/// root the Scan has just bootstrapped.
fn told_about(path: &Path, batch: &Batch, bootstrapped: &[PathBuf]) -> bool {
    batch.paths().any(|changed| changed == path)
        || bootstrapped.iter().any(|root| path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_roots_a_changed_path_falls_inside_are_enumerated() {
        let pooled = vec![PathBuf::from("/src/demo"), PathBuf::from("/src/other")];
        let batch = Batch::of([PathBuf::from("/src/demo/.mcp.json")]);
        assert_eq!(
            in_play(&pooled, &batch, &[]),
            vec![PathBuf::from("/src/demo")]
        );
    }

    /// A root that has just appeared in a registry is enumerated whole, even
    /// though nothing in the batch points at it: the batch touched the
    /// registry, not the project.
    #[test]
    fn a_root_that_has_just_appeared_is_enumerated_whatever_the_batch_says() {
        let pooled = vec![PathBuf::from("/src/demo"), PathBuf::from("/src/new")];
        let batch = Batch::of([PathBuf::from("/home/.claude.json")]);
        let fresh = vec![PathBuf::from("/src/new")];
        assert_eq!(
            in_play(&pooled, &batch, &fresh),
            vec![PathBuf::from("/src/new")]
        );
    }

    /// A Problem about a path nobody mentioned is not this Scan's to report.
    #[test]
    fn a_problem_outside_the_batch_is_dropped() {
        let batch = Batch::of([PathBuf::from("/home/.claude.json")]);
        let fresh = vec![PathBuf::from("/src/new")];
        assert!(told_about(Path::new("/home/.claude.json"), &batch, &fresh));
        assert!(told_about(Path::new("/src/new/.env"), &batch, &fresh));
        assert!(!told_about(Path::new("/src/demo/.env"), &batch, &fresh));
    }
}
