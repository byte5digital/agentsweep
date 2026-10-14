//! The Verdict cache, `verdicts.jsonl`.
//!
//! The third file of the data directory is not a chain. Every record carries
//! an HMAC over itself under the same Keychain key the Event Log and the
//! Baseline use, and nothing links one record to the next: a Verdict is an
//! answer about one Item, and losing one costs a question to the Judgement
//! Engine, never the integrity of anything else. A record whose MAC does not
//! verify is a cache miss and is dropped without a word, which is what keeps a
//! tampered cache from ever becoming a state to explain to the user (spec
//! section 4.6.6).
//!
//! The daemon is the only writer, as it is for both chains. The in-process
//! command line interface has no cache at all.
//!
//! What is here is the envelope, the key it is sealed under, the read that
//! drops what does not verify, the lookup by cache key, and the compaction
//! that runs behind a completed Full Scan. The cache key is the one spec
//! section 4.4 fixes: the hash of the full redacted Judgement Request
//! together with the engine, the model id the engine reports and the prompt
//! version. Only a Verdict is ever cached, malicious, benign or unsure, and
//! without expiry; no Verdict is never written here, which the types carry:
//! a record is made from a [`Verdict`] and from nothing else.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

// Sealing is the daemon's alone; any process may verify.
#[cfg(feature = "daemon")]
use crate::envelope::hmac_sha256_hex;
use crate::envelope::{Timestamp, canonical, hex_to_bytes, hmac_sha256_verify};
use crate::item::sha256_hex;
use crate::judgement::{Category, PROMPT_VERSION, Verdict, contain_reason};
use crate::keychain::{ChainKey, KeyError, KeySource};
use crate::paths::DataDirectory;

/// The name the file carries in every record, so a record of another store
/// cannot be read as a Verdict.
const STORE: &str = "verdicts";

/// The cache key of one Judgement Request under one engine, model and
/// prompt version: the sha256 of the four, each kept apart from the next by a
/// separator no hash or name holds.
pub fn cache_key(request_hash: &str, engine: &str, model: &str, prompt_version: &str) -> String {
    let joined = [request_hash, engine, model, prompt_version].join("\u{1f}");
    sha256_hex(joined.as_bytes())
}

/// A Verdict as a record's payload carries it. The reason and the quotes are
/// kept on a malicious Verdict only, because nothing else ever shows them.
pub fn verdict_value(verdict: &Verdict) -> Value {
    let mut map = Map::new();
    match verdict {
        Verdict::Malicious {
            category,
            reason,
            evidence,
        } => {
            map.insert("category".to_string(), Value::from(category.as_str()));
            map.insert(
                "evidence".to_string(),
                Value::Array(
                    evidence
                        .iter()
                        .map(|quote| Value::from(quote.as_str()))
                        .collect(),
                ),
            );
            map.insert("reason".to_string(), Value::from(reason.as_str()));
            map.insert("verdict".to_string(), Value::from("malicious"));
        }
        Verdict::Benign => {
            map.insert("verdict".to_string(), Value::from("benign"));
        }
        Verdict::Unsure => {
            map.insert("verdict".to_string(), Value::from("unsure"));
        }
    }
    Value::Object(map)
}

/// Reads back what [`verdict_value`] wrote. The reason is contained once
/// more on the way out, so a record can never carry more than the checks of
/// AI Judgement let through.
pub fn verdict_of_value(value: &Value) -> Option<Verdict> {
    match value.get("verdict")?.as_str()? {
        "malicious" => Some(Verdict::Malicious {
            category: Category::parse(value.get("category")?.as_str()?)?,
            reason: contain_reason(value.get("reason")?.as_str()?),
            evidence: value
                .get("evidence")?
                .as_array()?
                .iter()
                .map(|quote| quote.as_str().map(str::to_string))
                .collect::<Option<Vec<String>>>()?,
        }),
        "benign" => Some(Verdict::Benign),
        "unsure" => Some(Verdict::Unsure),
        _ => None,
    }
}

/// One cached Verdict as the file holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedVerdict {
    /// The cache key: the hash of the redacted Judgement Request together with
    /// the engine, the model id and the prompt version.
    pub key: String,
    /// The engine that answered.
    pub engine: String,
    /// The model it ran, as that engine names it.
    pub model: String,
    /// The version of the fixed prompt the answer was given under.
    pub prompt_version: String,
    /// When the answer was cached.
    pub recorded_at: Timestamp,
    /// The answer itself, as [`verdict_value`] writes it.
    pub verdict: Value,
}

impl CachedVerdict {
    /// The record one Verdict becomes under the prompt version in force. Only
    /// a Verdict makes a record: no Verdict has no way in.
    pub fn of(
        request_hash: &str,
        engine: &str,
        model: &str,
        recorded_at: Timestamp,
        verdict: &Verdict,
    ) -> CachedVerdict {
        CachedVerdict {
            key: cache_key(request_hash, engine, model, PROMPT_VERSION),
            engine: engine.to_string(),
            model: model.to_string(),
            prompt_version: PROMPT_VERSION.to_string(),
            recorded_at,
            verdict: verdict_value(verdict),
        }
    }

    /// The Verdict the record carries, if it reads as one.
    pub fn decoded(&self) -> Option<Verdict> {
        verdict_of_value(&self.verdict)
    }

    /// The payload a record carries. Only a writer needs it, and only the
    /// daemon may hold one.
    #[cfg(feature = "daemon")]
    fn to_payload(&self) -> Value {
        let mut map = Map::new();
        map.insert("engine".to_string(), Value::from(self.engine.as_str()));
        map.insert("key".to_string(), Value::from(self.key.as_str()));
        map.insert("model".to_string(), Value::from(self.model.as_str()));
        map.insert(
            "prompt_version".to_string(),
            Value::from(self.prompt_version.as_str()),
        );
        map.insert(
            "recorded_at".to_string(),
            Value::from(self.recorded_at.to_string()),
        );
        map.insert("verdict".to_string(), self.verdict.clone());
        Value::Object(map)
    }

    /// Reads back the payload a record carries.
    fn from_payload(payload: &Value) -> Option<CachedVerdict> {
        let text = |field: &str| payload.get(field).and_then(Value::as_str);
        Some(CachedVerdict {
            key: text("key")?.to_string(),
            engine: text("engine")?.to_string(),
            model: text("model")?.to_string(),
            prompt_version: text("prompt_version")?.to_string(),
            recorded_at: Timestamp::parse(text("recorded_at")?)?,
            verdict: payload.get("verdict")?.clone(),
        })
    }
}

/// One record of the Verdict cache: a payload and the MAC over it.
///
/// It is the record envelope of [`crate::envelope`] with the two fields a
/// chain needs taken out, because this file is not a chain: no record points
/// at the one before it and no position is checked. What is kept is the one
/// canonical serialisation, so that any edited byte is caught by the MAC.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SealedRecord {
    epoch: u64,
    recorded_at: Timestamp,
    payload: Value,
    mac: String,
}

impl SealedRecord {
    #[cfg(feature = "daemon")]
    fn seal(epoch: u64, recorded_at: Timestamp, payload: Value, key: &ChainKey) -> SealedRecord {
        let mut sealed = SealedRecord {
            epoch,
            recorded_at,
            payload,
            mac: String::new(),
        };
        sealed.mac = hmac_sha256_hex(key, &canonical(&sealed.body()));
        sealed
    }

    fn body(&self) -> Value {
        let mut body = Map::new();
        body.insert("epoch".to_string(), Value::from(self.epoch));
        body.insert("payload".to_string(), self.payload.clone());
        body.insert(
            "recorded_at".to_string(),
            Value::from(self.recorded_at.to_string()),
        );
        body.insert("store".to_string(), Value::from(STORE));
        Value::Object(body)
    }

    fn line(&self) -> Vec<u8> {
        let mut whole = match self.body() {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        whole.insert("mac".to_string(), Value::from(self.mac.as_str()));
        canonical(&Value::Object(whole))
    }

    fn mac_matches(&self, key: &ChainKey) -> bool {
        let Some(expected) = hex_to_bytes(&self.mac) else {
            return false;
        };
        hmac_sha256_verify(key, &canonical(&self.body()), &expected)
    }

    /// Reads a line back, insisting on the one form AgentSweep writes. A line
    /// that is anything else is not a record.
    fn parse(line: &[u8]) -> Option<SealedRecord> {
        let value: Value = serde_json::from_slice(line).ok()?;
        let map = value.as_object()?;
        if map.get("store")?.as_str()? != STORE {
            return None;
        }
        let parsed = SealedRecord {
            epoch: map.get("epoch")?.as_u64()?,
            recorded_at: Timestamp::parse(map.get("recorded_at")?.as_str()?)?,
            payload: map.get("payload")?.clone(),
            mac: map.get("mac")?.as_str()?.to_string(),
        };
        (parsed.line() == line).then_some(parsed)
    }
}

/// Why the Verdict cache could not be used.
#[derive(Debug)]
pub enum CacheError {
    /// The file could not be read or written.
    Io(io::Error),
    /// The key could not be read.
    Key(KeyError),
    /// The Event Log could not anchor a compaction.
    Chain(crate::chain::ChainError),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheError::Io(error) => write!(f, "the Verdict cache could not be used: {error}"),
            CacheError::Key(error) => write!(f, "{error}"),
            CacheError::Chain(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CacheError {}

impl From<io::Error> for CacheError {
    fn from(error: io::Error) -> CacheError {
        CacheError::Io(error)
    }
}

impl From<KeyError> for CacheError {
    fn from(error: KeyError) -> CacheError {
        CacheError::Key(error)
    }
}

/// The Verdict cache file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerdictCache {
    path: PathBuf,
}

impl VerdictCache {
    /// The cache kept at this path.
    pub fn at(path: impl Into<PathBuf>) -> VerdictCache {
        VerdictCache { path: path.into() }
    }

    /// The cache of a data directory.
    pub fn in_data_directory(directory: &DataDirectory) -> VerdictCache {
        VerdictCache::at(directory.verdicts())
    }

    /// Where the cache is kept.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the cache, keeping only what the key in hand vouches for.
    ///
    /// A record that does not verify is a cache miss: it is counted and
    /// dropped, and nothing is said about it. Without a key nothing verifies,
    /// so the whole cache is a miss and the Judgement Engine is asked again.
    pub fn read(&self, keys: &dyn KeySource) -> Result<VerdictCacheView, CacheError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(CacheError::Io(error)),
        };
        let key = keys.load()?;
        let mut view = VerdictCacheView::default();
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let held = SealedRecord::parse(line)
                .filter(|record| key.as_ref().is_some_and(|key| record.mac_matches(key)))
                .and_then(|record| CachedVerdict::from_payload(&record.payload));
            match held {
                Some(verdict) => {
                    view.verdicts.insert(verdict.key.clone(), verdict);
                }
                None => view.dropped += 1,
            }
        }
        Ok(view)
    }
}

/// The Verdict cache as one read left it: what verified, and how much did not.
#[derive(Clone, Debug, Default)]
pub struct VerdictCacheView {
    verdicts: BTreeMap<String, CachedVerdict>,
    /// How many records were dropped as cache misses.
    pub dropped: usize,
}

impl VerdictCacheView {
    /// The Verdict cached under this request key, if one verified.
    pub fn get(&self, key: &str) -> Option<&CachedVerdict> {
        self.verdicts.get(key)
    }

    /// The Verdict cached for one Judgement Request under one engine and
    /// model and the prompt version in force. A record whose own fields do
    /// not name the same engine, model and prompt version is a miss, and so
    /// is one whose payload does not read as a Verdict.
    pub fn lookup(&self, request_hash: &str, engine: &str, model: &str) -> Option<Verdict> {
        let key = cache_key(request_hash, engine, model, PROMPT_VERSION);
        self.verdicts
            .get(&key)
            .filter(|held| {
                held.engine == engine
                    && held.model == model
                    && held.prompt_version == PROMPT_VERSION
            })
            .and_then(CachedVerdict::decoded)
    }

    /// Every cached Verdict, by request key.
    pub fn verdicts(&self) -> impl Iterator<Item = &CachedVerdict> {
        self.verdicts.values()
    }

    /// How many Verdicts the cache holds.
    pub fn len(&self) -> usize {
        self.verdicts.len()
    }

    /// True when the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.verdicts.is_empty()
    }
}

impl From<crate::chain::ChainError> for CacheError {
    fn from(error: crate::chain::ChainError) -> CacheError {
        CacheError::Chain(error)
    }
}

/// One engine and model that is installed and may answer, which is what a
/// cached Verdict has to name to survive a compaction.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InstalledModel {
    /// The engine, as the settings file spells it.
    pub engine: String,
    /// The model id that engine reports.
    pub model: String,
}

impl InstalledModel {
    /// One engine and its model.
    pub fn new(engine: &str, model: &str) -> InstalledModel {
        InstalledModel {
            engine: engine.to_string(),
            model: model.to_string(),
        }
    }

    /// True when a cached Verdict was given by this engine and model under
    /// the prompt version in force.
    pub fn answered(&self, verdict: &CachedVerdict) -> bool {
        verdict.engine == self.engine
            && verdict.model == self.model
            && verdict.prompt_version == PROMPT_VERSION
    }
}

#[cfg(feature = "daemon")]
pub use writer::{VerdictCacheWriter, VerdictCompaction, compact};

#[cfg(feature = "daemon")]
mod writer {
    use std::fs::{File, OpenOptions};
    use std::io::Write as _;

    use super::{CacheError, CachedVerdict, InstalledModel, SealedRecord, VerdictCache};

    use crate::eventlog::{Action, Actor, Event, EventLog, EventLogWriter};
    use crate::item::sha256_hex;
    use crate::keychain::{ChainKey, KeySource};
    use crate::paths::DataDirectory;

    /// What one compaction of the Verdict cache did.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct VerdictCompaction {
        /// How many records the file held before, verified or not.
        pub before: usize,
        /// How many it holds now.
        pub after: usize,
        /// The sha256 of the compacted file, which the `verdicts-compacted`
        /// event carries.
        pub hash: String,
    }

    /// Compacts the Verdict cache: keeps every record that verifies and was
    /// given by an installed engine and model under the prompt version in
    /// force, drops everything else, and anchors the compacted file in the
    /// Event Log with one `verdicts-compacted` event, the twin of
    /// `baseline-compacted` (spec sections 4.6.6 and 5.5).
    ///
    /// Answers with nothing, and writes nothing, when there is nothing to
    /// drop or no key to seal a record with: a cache nobody can vouch for is
    /// left for a key to come back, never rewritten under a new one.
    pub fn compact(
        directory: &DataDirectory,
        keys: &dyn KeySource,
        installed: &[InstalledModel],
    ) -> Result<Option<VerdictCompaction>, CacheError> {
        let cache = VerdictCache::in_data_directory(directory);
        let Some(key) = keys.load()? else {
            return Ok(None);
        };
        let written = match std::fs::read(cache.path()) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(CacheError::Io(error)),
        };
        let before = written
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count();
        let view = cache.read(keys)?;
        let kept: Vec<&CachedVerdict> = view
            .verdicts()
            .filter(|verdict| installed.iter().any(|model| model.answered(verdict)))
            .collect();
        if kept.len() == before {
            return Ok(None);
        }

        let mut bytes = Vec::new();
        for verdict in &kept {
            let record = SealedRecord::seal(0, verdict.recorded_at, verdict.to_payload(), &key);
            bytes.extend(record.line());
            bytes.push(b'\n');
        }
        let fresh = cache.path().with_extension("jsonl.compacting");
        {
            let mut file = File::create(&fresh)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&fresh, cache.path())?;
        let done = VerdictCompaction {
            before,
            after: kept.len(),
            hash: sha256_hex(&bytes),
        };

        let log = EventLog::in_data_directory(directory);
        let (mut events, _) = EventLogWriter::open(&log, keys)?;
        let event = Event::new(Action::VerdictsCompacted, Actor::Auto)
            .noting("old_records", done.before.to_string())
            .noting("new_records", done.after.to_string())
            .noting("hash", done.hash.as_str());
        events.append(&event)?;
        Ok(Some(done))
    }

    /// The write side of the Verdict cache.
    ///
    /// The daemon is the only writer (spec section 6.2), which this type
    /// carries: it exists only in a build with the `daemon` feature. The
    /// in-process command line interface has no cache and cannot compile one.
    #[derive(Debug)]
    pub struct VerdictCacheWriter {
        file: File,
        key: ChainKey,
        epoch: u64,
    }

    impl VerdictCacheWriter {
        /// Opens the cache for appending, generating a key if none is held.
        ///
        /// Unlike a chain there is nothing to verify first: a record that does
        /// not verify later is simply a miss, so a new key costs the cache and
        /// nothing else.
        pub fn open(
            cache: &VerdictCache,
            keys: &dyn KeySource,
        ) -> Result<VerdictCacheWriter, CacheError> {
            if let Some(parent) = cache.path().parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(cache.path())?;
            let key = match keys.load()? {
                Some(key) => key,
                None => keys.renew()?,
            };
            Ok(VerdictCacheWriter {
                file,
                key,
                epoch: 0,
            })
        }

        /// Appends one Verdict and flushes it to the disk.
        pub fn append(&mut self, verdict: &CachedVerdict) -> Result<(), CacheError> {
            let record = SealedRecord::seal(
                self.epoch,
                verdict.recorded_at,
                verdict.to_payload(),
                &self.key,
            );
            let mut line = record.line();
            line.push(b'\n');
            self.file.write_all(&line)?;
            self.file.sync_all()?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::keychain::MemoryKeySource;

    fn moment() -> Timestamp {
        Timestamp::parse("2026-09-24T10:00:00.000Z").expect("a readable moment")
    }

    fn verdict(key: &str) -> CachedVerdict {
        CachedVerdict {
            key: key.to_string(),
            engine: "ollama".to_string(),
            model: "a-model".to_string(),
            prompt_version: "1".to_string(),
            recorded_at: moment(),
            verdict: serde_json::json!({"verdict": "benign"}),
        }
    }

    /// Until AI Judgement exists nothing writes the file, and a Scan that
    /// looks for a Verdict finds none rather than an error.
    #[test]
    fn a_cache_that_was_never_written_is_empty() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let view = VerdictCache::in_data_directory(&data)
            .read(&keys)
            .expect("an absent cache reads as empty");
        assert!(view.is_empty());
        assert_eq!(view.dropped, 0);
    }

    #[test]
    fn a_verdict_round_trips_through_the_envelope() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let cache = VerdictCache::in_data_directory(&data);

        let mut writer = VerdictCacheWriter::open(&cache, &keys).expect("the cache opens");
        writer.append(&verdict("k1")).expect("a record is written");
        writer.append(&verdict("k2")).expect("a record is written");

        let view = cache.read(&keys).expect("the cache reads back");
        assert_eq!(view.len(), 2);
        assert_eq!(view.get("k1"), Some(&verdict("k1")));
        assert_eq!(view.dropped, 0);
    }

    /// Spec section 4.6.6: a record failing its MAC is a cache miss and is
    /// dropped silently, never a state the user has to be told about.
    #[test]
    fn a_record_that_does_not_verify_is_a_cache_miss() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let cache = VerdictCache::in_data_directory(&data);
        {
            let mut writer = VerdictCacheWriter::open(&cache, &keys).expect("the cache opens");
            writer.append(&verdict("k1")).expect("a record is written");
            writer.append(&verdict("k2")).expect("a record is written");
        }

        let written = std::fs::read_to_string(cache.path()).expect("the cache is readable");
        let tampered = written.replace("\"engine\":\"ollama\"", "\"engine\":\"claude\"");
        std::fs::write(cache.path(), tampered).expect("the cache is writable");

        let view = cache.read(&keys).expect("the cache still reads");
        assert!(view.is_empty());
        assert_eq!(view.dropped, 2);
    }

    /// Without the key nothing in the cache can be vouched for, so everything
    /// is a miss and the engine is asked again.
    #[test]
    fn a_missing_key_makes_the_whole_cache_a_miss() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let cache = VerdictCache::in_data_directory(&data);
        {
            let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
            let mut writer = VerdictCacheWriter::open(&cache, &keys).expect("the cache opens");
            writer.append(&verdict("k1")).expect("a record is written");
        }

        let view = cache
            .read(&MemoryKeySource::empty())
            .expect("the cache still reads");
        assert!(view.is_empty());
        assert_eq!(view.dropped, 1);
    }

    /// Nothing links one record to the next: a lost record costs one question
    /// to the Judgement Engine and leaves every other answer readable.
    #[test]
    fn the_cache_is_not_a_chain() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let cache = VerdictCache::in_data_directory(&data);
        {
            let mut writer = VerdictCacheWriter::open(&cache, &keys).expect("the cache opens");
            for key in ["k1", "k2", "k3"] {
                writer.append(&verdict(key)).expect("a record is written");
            }
        }

        let written = std::fs::read_to_string(cache.path()).expect("the cache is readable");
        let kept: Vec<&str> = written
            .lines()
            .enumerate()
            .filter(|(index, _)| *index != 1)
            .map(|(_, line)| line)
            .collect();
        std::fs::write(cache.path(), format!("{}\n", kept.join("\n")))
            .expect("the cache is writable");

        let view = cache.read(&keys).expect("the cache reads back");
        assert_eq!(view.len(), 2);
        assert!(view.get("k1").is_some());
        assert!(view.get("k3").is_some());
        assert_eq!(view.dropped, 0);
    }

    #[test]
    fn a_line_of_another_store_is_not_a_verdict() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let cache = VerdictCache::in_data_directory(&data);
        std::fs::create_dir_all(data.root()).expect("a writable data directory");
        std::fs::write(
            cache.path(),
            b"{\"chain\":\"events\",\"epoch\":0,\"mac\":\"00\",\"payload\":{},\"previous\":\"0\"}\n",
        )
        .expect("the cache is writable");

        let view = cache.read(&keys).expect("the cache still reads");
        assert!(view.is_empty());
        assert_eq!(view.dropped, 1);
    }

    fn malicious() -> Verdict {
        Verdict::Malicious {
            category: Category::InstructionFileInjection,
            reason: "It hides an instruction.".to_string(),
            evidence: vec!["ignore the rules".to_string()],
        }
    }

    /// The key names the engine and the model: the same request under
    /// another engine or another model is a miss.
    #[test]
    fn a_verdict_is_found_only_under_its_own_engine_and_model() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let cache = VerdictCache::in_data_directory(&data);
        let mut writer = VerdictCacheWriter::open(&cache, &keys).expect("the cache opens");
        for (hash, verdict) in [
            ("r1", malicious()),
            ("r2", Verdict::Benign),
            ("r3", Verdict::Unsure),
        ] {
            writer
                .append(&CachedVerdict::of(
                    hash,
                    "ollama",
                    "qwen3:8b",
                    moment(),
                    &verdict,
                ))
                .expect("a record is written");
        }

        let view = cache.read(&keys).expect("the cache reads");
        assert_eq!(view.lookup("r1", "ollama", "qwen3:8b"), Some(malicious()));
        assert_eq!(
            view.lookup("r2", "ollama", "qwen3:8b"),
            Some(Verdict::Benign)
        );
        assert_eq!(
            view.lookup("r3", "ollama", "qwen3:8b"),
            Some(Verdict::Unsure)
        );
        assert_eq!(view.lookup("r1", "apple", "qwen3:8b"), None);
        assert_eq!(view.lookup("r1", "ollama", "gemma3:12b"), None);
        assert_eq!(view.lookup("r9", "ollama", "qwen3:8b"), None);
        assert_ne!(
            cache_key("r1", "ollama", "qwen3:8b", PROMPT_VERSION),
            cache_key("r1", "ollama", "qwen3:8b", "0")
        );
    }

    /// A reason read back is contained again, whatever the file held.
    #[test]
    fn a_reason_read_back_is_contained() {
        let value = serde_json::json!({
            "verdict": "malicious",
            "category": "exposure",
            "reason": "see [here](https://x.invalid) \u{202e}now",
            "evidence": ["q"],
        });
        let Some(Verdict::Malicious { reason, .. }) = verdict_of_value(&value) else {
            panic!("a malicious Verdict");
        };
        assert_eq!(reason, "see here now");
        assert_eq!(
            verdict_of_value(&serde_json::json!({"verdict": "maybe"})),
            None
        );
    }

    /// Spec section 4.6.6: compaction drops what no installed engine and
    /// model gave under the prompt version in force, and what does not
    /// verify, keeps the rest, and anchors the file in the Event Log with one
    /// `verdicts-compacted` event. With nothing to drop it writes nothing.
    #[test]
    fn compaction_keeps_the_installed_models_and_anchors_the_file() {
        use crate::eventlog::{Action, EventLog};

        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let cache = VerdictCache::in_data_directory(&data);
        {
            let mut writer = VerdictCacheWriter::open(&cache, &keys).expect("the cache opens");
            for (hash, model) in [("r1", "qwen3:8b"), ("r2", "llama-gone:1b")] {
                writer
                    .append(&CachedVerdict::of(
                        hash,
                        "ollama",
                        model,
                        moment(),
                        &Verdict::Benign,
                    ))
                    .expect("a record is written");
            }
            let mut old = CachedVerdict::of("r3", "ollama", "qwen3:8b", moment(), &Verdict::Unsure);
            old.prompt_version = "0".to_string();
            writer.append(&old).expect("a record is written");
        }
        let installed = [InstalledModel::new("ollama", "qwen3:8b")];

        let done = compact(&data, &keys, &installed)
            .expect("the compaction runs")
            .expect("something was dropped");
        assert_eq!((done.before, done.after), (3, 1));
        let bytes = std::fs::read(cache.path()).expect("the cache is readable");
        assert_eq!(done.hash, sha256_hex(&bytes));
        let view = cache.read(&keys).expect("the cache reads");
        assert_eq!(view.len(), 1);
        assert_eq!(
            view.lookup("r1", "ollama", "qwen3:8b"),
            Some(Verdict::Benign)
        );
        assert_eq!(view.dropped, 0);

        let log = EventLog::in_data_directory(&data)
            .read(&keys)
            .expect("the log reads");
        assert_eq!(log.events.len(), 1);
        let event = &log.events[0].event;
        assert_eq!(event.action, Action::VerdictsCompacted);
        assert_eq!(
            event.detail.get("old_records").map(String::as_str),
            Some("3")
        );
        assert_eq!(
            event.detail.get("new_records").map(String::as_str),
            Some("1")
        );
        assert_eq!(event.detail.get("hash"), Some(&done.hash));

        assert_eq!(compact(&data, &keys, &installed).expect("it runs"), None);
        let log = EventLog::in_data_directory(&data)
            .read(&keys)
            .expect("the log reads");
        assert_eq!(log.events.len(), 1, "nothing to drop, nothing written");
    }
}
