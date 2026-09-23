//! What Codex itself records about the projects it has been used in: the trust
//! table and the session logs.
//!
//! Codex has no project registry file of its own. What it has is the
//! `[projects."<absolute path>"]` table in the user `config.toml`, written when
//! someone answers the trust question, and a directory of session logs, each of
//! which names the working directory it was recorded in. Between them they are
//! the Inventory this adapter reports: the trust table says which roots Codex
//! would load a `.codex` layer from, the session logs say which roots it has
//! actually been run in, and neither is ever found by crawling for folders.
//!
//! Three things are read off it. The **project list** (`projects` on the
//! trait), the **registered flag** of every Item at a root, and the
//! **Activation** of everything a project layer holds: a `.codex` directory
//! whose own path, project root or git repository root is not `trusted` is
//! loaded but disabled, so its config values, hooks and execution policy never
//! take effect (`docs/research/codex-surfaces.md` section 2). No entry at all
//! means untrusted, which is why an existing table answers `false` rather than
//! nothing.
//!
//! The trust table is Codex's own bookkeeping and never becomes an Item: its
//! keys are absolute paths, and a content hash that carried one could not be
//! carried from one machine to the next.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use agentsweep_core::host::Host;
use serde_json::Value;

use crate::document::Document;

/// The directories under the config directory that hold session logs, in the
/// order they are read.
pub const SESSION_DIRECTORIES: [&str; 2] = ["sessions", "archived_sessions"];

/// How many session logs are opened at most. A machine that has run Codex
/// daily for a year has thousands of them and they are read for one field, so
/// the newest ones by path order are the ones that are read.
pub const SESSION_LOG_LIMIT: usize = 4096;

/// How much of a session log is read. The working directory is in the first
/// record, and nothing further in is wanted: a transcript is the user's
/// conversation.
const SESSION_LOG_PREFIX: usize = 64 * 1024;

/// The trust level Codex writes for a project it was told to trust.
pub const TRUSTED: &str = "trusted";

/// What Codex records about the projects it knows.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    /// True when a layer that may carry the trust table was readable at all.
    /// A Folder Scan has none, and then nothing can be said about trust.
    present: bool,
    /// The trust level recorded per absolute path.
    levels: BTreeMap<PathBuf, String>,
    /// The working directories the session logs name.
    sessions: BTreeSet<PathBuf>,
}

impl Registry {
    /// The registry read from the layers that may carry a trust table and from
    /// the session logs beside them.
    ///
    /// Every non-project layer takes part in the trust decision at its normal
    /// precedence, so the user layer, the profile layers and the managed ones
    /// are all read; the higher layer wins on a path both name, which is the
    /// order the caller hands them in, low to high.
    pub fn read(host: &Host, config_dir: Option<&Path>, layers: &[Document]) -> Registry {
        let mut registry = Registry {
            present: !layers.is_empty(),
            ..Registry::default()
        };
        for layer in layers {
            for (path, record) in layer.members("projects") {
                let level = record
                    .get("trust_level")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                registry.levels.insert(PathBuf::from(path), level);
            }
        }
        if let Some(config_dir) = config_dir {
            registry.sessions = working_directories(host, config_dir);
        }
        registry
    }

    /// Every root Codex knows, in a stable order: the ones the trust table
    /// names and the ones a session log was recorded in.
    pub fn roots(&self) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = self
            .levels
            .keys()
            .chain(self.sessions.iter())
            .cloned()
            .collect();
        roots.sort();
        roots.dedup();
        roots
    }

    /// The trust level recorded for one root, empty when the table does not
    /// name it. The lookup follows Codex's: the directory itself, then the git
    /// repository root above it.
    pub fn native_trust(&self, host: &Host, root: &Path) -> String {
        self.recorded(host, root).unwrap_or_default().to_string()
    }

    /// Whether Codex would load a `.codex` layer at this root, absent when
    /// there is no layer to ask.
    pub fn trusted(&self, host: &Host, root: &Path) -> Option<bool> {
        if !self.present {
            return None;
        }
        Some(self.recorded(host, root) == Some(TRUSTED))
    }

    /// True when Codex has been run in this root, which is what
    /// `settings.trust_has_sessions` reports.
    pub fn has_sessions(&self, root: &Path) -> bool {
        self.sessions.contains(root)
    }

    /// True when Codex knows this root at all, from the trust table or from a
    /// session log. An Item at a root its own Agent does not know carries
    /// `registered: false`.
    pub fn knows(&self, host: &Host, root: &Path) -> bool {
        self.recorded(host, root).is_some() || self.has_sessions(root)
    }

    /// Which of Codex's own records the root was found in, for the project
    /// list. The trust table is named first because it is the one that decides
    /// whether a project layer is loaded.
    pub fn registered_in(&self, host: &Host, root: &Path) -> &'static str {
        if self.recorded(host, root).is_some() {
            "~/.codex/config.toml#projects"
        } else {
            "~/.codex/sessions"
        }
    }

    fn recorded(&self, host: &Host, root: &Path) -> Option<&str> {
        if let Some(level) = self.levels.get(root) {
            return Some(level.as_str());
        }
        let repository = git_root(host, root)?;
        self.levels.get(&repository).map(String::as_str)
    }
}

/// The nearest ancestor of a path that holds a `.git` entry, which is what
/// Codex resolves a trust lookup up to. A linked worktree's `.git` is a file
/// rather than a directory and still marks the checkout.
fn git_root(host: &Host, root: &Path) -> Option<PathBuf> {
    let mut current = Some(root);
    while let Some(directory) = current {
        if host.symlink_metadata(&directory.join(".git")).is_ok() {
            return Some(directory.to_path_buf());
        }
        current = directory.parent();
    }
    None
}

/// The working directories the session logs name.
fn working_directories(host: &Host, config_dir: &Path) -> BTreeSet<PathBuf> {
    let mut logs = Vec::new();
    for directory in SESSION_DIRECTORIES {
        collect_logs(host, &config_dir.join(directory), &mut logs);
    }
    logs.sort();
    let newest = logs.len().saturating_sub(SESSION_LOG_LIMIT);
    logs[newest..]
        .iter()
        .filter_map(|path| working_directory(host, path))
        .collect()
}

/// Every session log under one directory, in a stable order.
fn collect_logs(host: &Host, directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = host.read_dir(directory) else {
        return;
    };
    for entry in entries {
        if entry.is_dir() {
            collect_logs(host, &entry, found);
        } else if entry.extension().is_some_and(|kind| kind == "jsonl") {
            found.push(entry);
        }
    }
}

/// The working directory one session log was recorded in, from its first
/// record. Nothing further into the file is read: the rest is the user's
/// conversation.
fn working_directory(host: &Host, path: &Path) -> Option<PathBuf> {
    let prefix = host.read_prefix(path, SESSION_LOG_PREFIX).ok()?;
    let text = String::from_utf8_lossy(&prefix);
    let first = text.lines().next()?;
    let record: Value = serde_json::from_str(first).ok()?;
    let named = record
        .get("cwd")
        .or_else(|| record.pointer("/payload/cwd"))
        .and_then(Value::as_str)?;
    Some(PathBuf::from(named))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use super::*;

    fn layer(value: Value) -> Document {
        Document::inline(
            PathBuf::from("/home/u/.codex/config.toml"),
            "~/.codex/config.toml".to_string(),
            value,
        )
    }

    fn host() -> Host {
        Host::new(PathBuf::from("/home/u"), Vec::new())
    }

    #[test]
    fn a_trusted_path_is_trusted_and_one_the_table_does_not_name_is_not() {
        let registry = Registry::read(
            &host(),
            None,
            &[layer(json!({"projects": {
                "/src/demo": {"trust_level": "trusted"},
                "/src/other": {"trust_level": "untrusted"},
            }}))],
        );
        assert_eq!(
            registry.trusted(&host(), Path::new("/src/demo")),
            Some(true)
        );
        assert_eq!(
            registry.trusted(&host(), Path::new("/src/other")),
            Some(false)
        );
        assert_eq!(
            registry.trusted(&host(), Path::new("/src/unknown")),
            Some(false)
        );
        assert!(!registry.knows(&host(), Path::new("/src/unknown")));
        assert_eq!(
            registry.native_trust(&host(), Path::new("/src/demo")),
            TRUSTED
        );
    }

    /// A Folder Scan has no layer to ask, so nothing is claimed about trust.
    #[test]
    fn without_a_layer_to_ask_trust_is_not_determined() {
        let registry = Registry::read(&host(), None, &[]);
        assert_eq!(registry.trusted(&host(), Path::new("/src/demo")), None);
    }

    /// The higher layer wins on a path two of them name, and the caller hands
    /// them over low to high.
    #[test]
    fn the_higher_layer_wins_on_a_path_both_name() {
        let registry = Registry::read(
            &host(),
            None,
            &[
                layer(json!({"projects": {"/src/demo": {"trust_level": "untrusted"}}})),
                layer(json!({"projects": {"/src/demo": {"trust_level": "trusted"}}})),
            ],
        );
        assert_eq!(
            registry.trusted(&host(), Path::new("/src/demo")),
            Some(true)
        );
    }

    /// Codex resolves a trust lookup up to the git repository root, so a
    /// trusted checkout carries a directory below it.
    #[test]
    fn a_trusted_checkout_carries_a_directory_inside_it() {
        let root =
            std::env::temp_dir().join(format!("agentsweep-codex-registry-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("checkout/.git")).expect("a fake checkout");
        fs::create_dir_all(root.join("checkout/packages/app")).expect("a fake package");

        let host = Host::new(root.clone(), Vec::new());
        let registry = Registry::read(
            &host,
            None,
            &[layer(json!({"projects": {
                root.join("checkout").display().to_string(): {"trust_level": "trusted"},
            }}))],
        );
        assert_eq!(
            registry.trusted(&host, &root.join("checkout/packages/app")),
            Some(true)
        );
        fs::remove_dir_all(&root).expect("the fake checkout goes away");
    }

    #[test]
    fn a_session_log_names_a_root_codex_knows_without_a_trust_entry() {
        let root =
            std::env::temp_dir().join(format!("agentsweep-codex-sessions-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let sessions = root.join(".codex/sessions/2026/09/22");
        fs::create_dir_all(&sessions).expect("a fake session directory");
        fs::write(
            sessions.join("rollout-one.jsonl"),
            "{\"type\":\"session_meta\",\"payload\":{\"cwd\":\"/src/seen\"}}\n{\"x\":1}\n",
        )
        .expect("a fake session log");
        fs::write(sessions.join("notes.txt"), b"not a log").expect("a decoy");

        let host = Host::new(root.clone(), Vec::new());
        let registry = Registry::read(&host, Some(&root.join(".codex")), &[layer(json!({}))]);

        assert!(registry.has_sessions(Path::new("/src/seen")));
        assert!(registry.knows(&host, Path::new("/src/seen")));
        assert_eq!(registry.roots(), [PathBuf::from("/src/seen")]);
        fs::remove_dir_all(&root).expect("the fake session directory goes away");
    }
}
