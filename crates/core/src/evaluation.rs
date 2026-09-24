//! The evaluation cache: the Tier outcome of one Item, keyed by everything a
//! Tier could have read.
//!
//! A Full Scan always re-enumerates and re-hashes, because nothing but a fresh
//! read can say what is on the Surface now. What it may skip is the Tiers: if
//! the content, the facts the Rules read, the Rule Pack and the Judgement
//! Engine are all the ones that produced an [`Assessment`] earlier in this
//! daemon's life, running them again produces the same Assessment (spec
//! section 6.4).
//!
//! The cache lives in memory, is rebuilt at daemon start, is cleared when a
//! Rule Pack is accepted and is never persisted: nothing here is a record of
//! anything, and a daemon that starts with an empty cache is only slower, never
//! wrong.
//!
//! The key is the one spec section 6.4 fixes, the Item hash and a facts hash
//! over Activation, Provenance, `item.baseline` and `registered`, plus the Rule
//! Pack version and the engine version, with the Item's own id folded in. The
//! id is not in the specification's list and does not have to be: it can only
//! ever make the key stricter. It is here because an Assessment names the Item
//! it is about, so reusing one across two Items that happen to hold the same
//! bytes would hand the second Item the first one's Findings.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::heuristics::Assessment;
use crate::item::{BaselineState, Item, sha256_hex};

/// What one cached Tier outcome is filed under.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvaluationKey(String);

impl EvaluationKey {
    /// The key of one Item under one Rule Pack and one Judgement Engine.
    ///
    /// `baseline` is the state the Scan computed for the Item, which is a
    /// Rule-visible fact and so part of the key rather than of the Item as the
    /// adapter yielded it.
    pub fn of(item: &Item, baseline: BaselineState, rule_pack: u64, engine: &str) -> EvaluationKey {
        let facts = [
            item.id.as_str(),
            item.activation.as_str(),
            item.activation.reason(),
            item.provenance.as_str(),
            item.provenance.reference(),
            baseline.as_str(),
            match item.registered {
                true => "registered",
                false => "unregistered",
            },
        ]
        .join("\u{1f}");
        EvaluationKey(format!(
            "{}:{}:{}:{}",
            item.content_hash,
            sha256_hex(facts.as_bytes()),
            rule_pack,
            engine
        ))
    }

    /// The key as one string, which is what a log line and a test read.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EvaluationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a Scan looks before it runs the Tiers, and what it tells afterwards.
///
/// A trait rather than the type below, because a Folder Scan and the
/// in-process command line interface have no cache at all and say so by
/// handing over [`NoCache`] instead of by passing an option around.
pub trait Evaluations: Sync {
    /// The Assessment this key stands for, if one is held.
    fn lookup(&self, key: &EvaluationKey) -> Option<Assessment>;

    /// Takes the Assessment the Tiers produced for this key.
    fn remember(&self, key: EvaluationKey, assessment: Assessment);
}

/// A cache that holds nothing, which is what a Scan that may not skip a Tier
/// runs with.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCache;

impl Evaluations for NoCache {
    fn lookup(&self, _key: &EvaluationKey) -> Option<Assessment> {
        None
    }

    fn remember(&self, _key: EvaluationKey, _assessment: Assessment) {}
}

/// The daemon's in-memory evaluation cache.
#[derive(Debug, Default)]
pub struct EvaluationCache {
    held: Mutex<HashMap<EvaluationKey, Assessment>>,
}

impl EvaluationCache {
    /// An empty cache, which is what every daemon starts with.
    pub fn new() -> EvaluationCache {
        EvaluationCache::default()
    }

    /// Throws everything away.
    ///
    /// This is the seam a newly accepted Rule Pack calls: a pack change means
    /// every cached outcome was produced by rules that are no longer the ones
    /// in force, whatever the pack version says (spec section 6.4).
    pub fn clear(&self) {
        self.held.lock().expect("the cache is not poisoned").clear();
    }

    /// How many outcomes are held.
    pub fn len(&self) -> usize {
        self.held.lock().expect("the cache is not poisoned").len()
    }

    /// True when nothing is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Evaluations for EvaluationCache {
    fn lookup(&self, key: &EvaluationKey) -> Option<Assessment> {
        self.held
            .lock()
            .expect("the cache is not poisoned")
            .get(key)
            .cloned()
    }

    fn remember(&self, key: EvaluationKey, assessment: Assessment) {
        self.held
            .lock()
            .expect("the cache is not poisoned")
            .insert(key, assessment);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::heuristics::Band;
    use crate::item::{Activation, Kind, Provenance, Scope};

    fn instruction_file(locator: &str, content: &str) -> Item {
        Item::file(
            "claude-code",
            Scope::User,
            Kind::InstructionFile,
            locator,
            PathBuf::from("/nowhere").join(locator),
            Provenance::Manual,
            Activation::Active,
            content.as_bytes().to_vec(),
        )
    }

    fn assessment(item: &Item) -> Assessment {
        Assessment {
            item_id: item.id.clone(),
            score: 0,
            band: Band::Clear,
            fired: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// The same Item, the same pack and the same engine is the same key, so a
    /// Full Scan that re-hashes unchanged content skips the Tiers.
    #[test]
    fn the_same_item_under_the_same_pack_reads_back_out_of_the_cache() {
        let item = instruction_file("a.md", "# hello\n");
        let key = EvaluationKey::of(&item, BaselineState::Unchanged, 1, "");
        let cache = EvaluationCache::new();
        assert!(cache.is_empty());
        assert!(cache.lookup(&key).is_none());

        cache.remember(key.clone(), assessment(&item));
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.lookup(&key).map(|held| held.item_id),
            Some(item.id.clone())
        );
    }

    /// Every part of the key is part of the key: change one and the Tiers run
    /// again.
    #[test]
    fn content_facts_the_pack_and_the_engine_each_change_the_key() {
        let item = instruction_file("a.md", "# hello\n");
        let base = EvaluationKey::of(&item, BaselineState::Unchanged, 1, "");

        let edited = instruction_file("a.md", "# hello there\n");
        assert_ne!(
            EvaluationKey::of(&edited, BaselineState::Unchanged, 1, ""),
            base
        );

        assert_ne!(
            EvaluationKey::of(&item, BaselineState::Changed, 1, ""),
            base
        );
        assert_ne!(
            EvaluationKey::of(&item, BaselineState::Unchanged, 2, ""),
            base
        );
        assert_ne!(
            EvaluationKey::of(&item, BaselineState::Unchanged, 1, "ollama/llama3"),
            base
        );

        let mut inactive = item.clone();
        inactive.activation = Activation::Unknown;
        assert_ne!(
            EvaluationKey::of(&inactive, BaselineState::Unchanged, 1, ""),
            base
        );

        let mut unknown = item.clone();
        unknown.provenance = Provenance::Unknown;
        assert_ne!(
            EvaluationKey::of(&unknown, BaselineState::Unchanged, 1, ""),
            base
        );

        let mut registered = item.clone();
        registered.registered = true;
        assert_ne!(
            EvaluationKey::of(&registered, BaselineState::Unchanged, 1, ""),
            base
        );
    }

    /// Two Items with the same bytes are two keys, so neither is ever handed
    /// the other's Findings.
    #[test]
    fn two_items_holding_the_same_bytes_are_two_keys() {
        let one = instruction_file("a.md", "# hello\n");
        let other = instruction_file("b.md", "# hello\n");
        assert_eq!(one.content_hash, other.content_hash);
        assert_ne!(
            EvaluationKey::of(&one, BaselineState::Unchanged, 1, ""),
            EvaluationKey::of(&other, BaselineState::Unchanged, 1, "")
        );
    }

    /// A pack change empties the cache, which is the seam the Rule Pack
    /// milestone calls.
    #[test]
    fn clearing_the_cache_is_the_seam_a_new_rule_pack_pulls() {
        let item = instruction_file("a.md", "# hello\n");
        let cache = EvaluationCache::new();
        cache.remember(
            EvaluationKey::of(&item, BaselineState::Unchanged, 1, ""),
            assessment(&item),
        );
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }

    /// A Scan that may not skip a Tier says so by running without a cache.
    #[test]
    fn the_cache_that_holds_nothing_never_answers() {
        let item = instruction_file("a.md", "# hello\n");
        let key = EvaluationKey::of(&item, BaselineState::Unchanged, 1, "");
        let cache = NoCache;
        cache.remember(key.clone(), assessment(&item));
        assert!(cache.lookup(&key).is_none());
    }
}
