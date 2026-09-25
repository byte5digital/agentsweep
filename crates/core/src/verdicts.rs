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
//! The file stays empty until AI Judgement exists. What is here is the
//! envelope, the key it is sealed under, the read that drops what does not
//! verify, and the lookup by request key; the shape of a Verdict itself
//! belongs to the AI Judgement milestone, so a record's payload is carried as
//! it was written. The cache key is the one spec section 4.4 fixes: the hash
//! of the full redacted Judgement Request together with the engine, the model
//! id and the prompt version.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

// Sealing is the daemon's alone; any process may verify.
#[cfg(feature = "daemon")]
use crate::envelope::hmac_sha256_hex;
use crate::envelope::{Timestamp, canonical, hex_to_bytes, hmac_sha256_verify};
use crate::keychain::{ChainKey, KeyError, KeySource};
use crate::paths::DataDirectory;

/// The name the file carries in every record, so a record of another store
/// cannot be read as a Verdict.
const STORE: &str = "verdicts";

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
    /// The answer itself, as AI Judgement writes it. Nothing here reads it.
    pub verdict: Value,
}

impl CachedVerdict {
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
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheError::Io(error) => write!(f, "the Verdict cache could not be used: {error}"),
            CacheError::Key(error) => write!(f, "{error}"),
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

    /// Every cached Verdict, by request key.
    pub fn verdicts(&self) -> impl Iterator<Item = &CachedVerdict> {
        self.verdicts.values()
    }

    /// How many Verdicts the cache holds.
    pub fn len(&self) -> usize {
        self.verdicts.len()
    }

    /// True when the cache holds nothing, which is what it holds until AI
    /// Judgement exists.
    pub fn is_empty(&self) -> bool {
        self.verdicts.is_empty()
    }
}

#[cfg(feature = "daemon")]
pub use writer::VerdictCacheWriter;

#[cfg(feature = "daemon")]
mod writer {
    use std::fs::{File, OpenOptions};
    use std::io::Write as _;

    use super::{CacheError, CachedVerdict, SealedRecord, VerdictCache};

    use crate::keychain::{ChainKey, KeySource};

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
}
