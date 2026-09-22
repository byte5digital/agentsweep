//! The data directory AgentSweep keeps its stores in.
//!
//! One directory under Application Support holds every store the daemon owns
//! (spec section 6.9): the Event Log, the Baseline chain, the Verdict cache,
//! the state file, the quarantine store, the fetched Rule Pack and the user's
//! own rules. Nothing else writes there.
//!
//! [`DataDirectory::at`] takes any root, which is how every test works on a
//! temporary copy instead of the real home.

use std::io;
use std::path::{Path, PathBuf};

use crate::BUNDLE_ID;

/// Where AgentSweep keeps its stores.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataDirectory(PathBuf);

impl DataDirectory {
    /// The directory for the user running this process:
    /// `~/Library/Application Support/de.byte5.agentsweep`. `None` when the
    /// home directory is not known.
    pub fn for_user() -> Option<DataDirectory> {
        let home = std::env::var_os("HOME")?;
        if home.is_empty() {
            return None;
        }
        Some(DataDirectory::under_home(Path::new(&home)))
    }

    /// The data directory under a given home directory. Tests name the home
    /// rather than change the environment of the running process.
    pub fn under_home(home: &Path) -> DataDirectory {
        DataDirectory(
            home.join("Library")
                .join("Application Support")
                .join(BUNDLE_ID),
        )
    }

    /// A data directory rooted anywhere. Tests run on a temporary directory,
    /// never on the real one.
    pub fn at(root: impl Into<PathBuf>) -> DataDirectory {
        DataDirectory(root.into())
    }

    /// The directory itself.
    pub fn root(&self) -> &Path {
        &self.0
    }

    /// The Event Log: the single append-only hash-chained source of truth.
    pub fn event_log(&self) -> PathBuf {
        self.0.join("events.jsonl")
    }

    /// The Baseline chain, which shares the Event Log's record envelope, key
    /// and verification routine.
    pub fn baseline(&self) -> PathBuf {
        self.0.join("baseline.jsonl")
    }

    /// The Verdict cache.
    pub fn verdicts(&self) -> PathBuf {
        self.0.join("verdicts.jsonl")
    }

    /// The state file the daemon writes atomically with a whole-file MAC.
    pub fn state_file(&self) -> PathBuf {
        self.0.join("state.json")
    }

    /// The quarantine store, one directory per Receipt id.
    pub fn quarantine(&self) -> PathBuf {
        self.0.join("quarantine")
    }

    /// The payload of one quarantined Item.
    pub fn quarantine_payload(&self, receipt_id: &str) -> PathBuf {
        self.quarantine().join(receipt_id).join("payload")
    }

    /// The Rule Pack fetched from the Rule Feed.
    pub fn rules(&self) -> PathBuf {
        self.0.join("rules")
    }

    /// The user's own rules.
    pub fn user_rules(&self) -> PathBuf {
        self.0.join("rules.d")
    }

    /// Creates the directory and the quarantine store if they are absent.
    pub fn create(&self) -> io::Result<()> {
        std::fs::create_dir_all(self.quarantine())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_store_sits_under_the_one_data_directory() {
        let dir = DataDirectory::at("/tmp/agentsweep-test");
        for path in [
            dir.event_log(),
            dir.baseline(),
            dir.verdicts(),
            dir.state_file(),
            dir.quarantine(),
            dir.rules(),
            dir.user_rules(),
        ] {
            assert!(path.starts_with(dir.root()), "{}", path.display());
        }
        assert_eq!(dir.event_log().file_name().unwrap(), "events.jsonl");
        assert_eq!(dir.baseline().file_name().unwrap(), "baseline.jsonl");
    }

    #[test]
    fn the_users_directory_is_the_bundle_id_under_application_support() {
        let dir = DataDirectory::under_home(Path::new("/Users/nobody"));
        assert_eq!(
            dir.root(),
            Path::new("/Users/nobody/Library/Application Support/de.byte5.agentsweep")
        );
    }

    #[test]
    fn a_payload_sits_under_its_receipt_id() {
        let dir = DataDirectory::at("/tmp/agentsweep-test");
        assert_eq!(
            dir.quarantine_payload("r-1"),
            Path::new("/tmp/agentsweep-test/quarantine/r-1/payload")
        );
    }
}
