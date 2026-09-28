//! The settings file: the choices the user made, kept apart from the state.
//!
//! The state file is a cache the daemon can throw away: a file that is
//! missing or does not verify is rebuilt by the next Full Scan (spec section
//! 6.5). A choice the user made cannot be derived again from the logs, so it
//! does not live there. It lives in `settings.json` beside it, plain JSON
//! without a MAC, which a rebuilt state file leaves alone.
//!
//! The only choice in v1 is the Rule Feed toggle (spec section 9.4). The app
//! update check, the Gate switch and the Posture join it in their milestones.
//!
//! A missing settings file means every default. A settings file that cannot
//! be read back is reported rather than repaired: the daemon runs with the
//! defaults and says so in Health, and it does not write over the file, so a
//! user's "off" is never silently turned back on by the daemon itself.
//!
//! The file holds no sensitive value and no path: nothing but the choices.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::paths::DataDirectory;

/// The key the Rule Feed toggle is kept under.
const RULE_FEED: &str = "rule_feed";

/// Every choice the user made, each at its default until they make it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// The Rule Feed toggle (spec section 9.4). On by default; off means no
    /// request at all and the bundled Rule Pack only.
    pub rule_feed: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { rule_feed: true }
    }
}

impl Settings {
    /// The settings as the file carries them.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(RULE_FEED.to_string(), Value::from(self.rule_feed));
        Value::Object(map)
    }

    /// Reads back what [`Settings::to_value`] wrote.
    ///
    /// A choice the file does not name is at its default, which is how a file
    /// written before a later choice existed reads. A key this version does
    /// not know is passed over. A choice of the wrong type is not read as its
    /// default: the whole file is unreadable, so a mistyped "off" is reported
    /// rather than taken for "on".
    pub fn from_value(value: &Value) -> Option<Settings> {
        let map = value.as_object()?;
        let mut settings = Settings::default();
        if let Some(rule_feed) = map.get(RULE_FEED) {
            settings.rule_feed = rule_feed.as_bool()?;
        }
        Some(settings)
    }
}

/// Why the settings file could not be read or written.
#[derive(Debug)]
pub enum SettingsError {
    /// There is no settings file, which means every default.
    Missing,
    /// The file could not be read or written.
    Io(io::Error),
    /// The file is there and is not a settings file.
    Malformed(String),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SettingsError::Missing => f.write_str("there is no settings file yet"),
            SettingsError::Io(error) => write!(f, "the settings file could not be used: {error}"),
            SettingsError::Malformed(detail) => {
                write!(f, "the settings file is malformed: {detail}")
            }
        }
    }
}

impl std::error::Error for SettingsError {}

impl From<io::Error> for SettingsError {
    fn from(error: io::Error) -> SettingsError {
        SettingsError::Io(error)
    }
}

/// The settings file, `settings.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettingsFile {
    path: PathBuf,
}

impl SettingsFile {
    /// The settings file at this path.
    pub fn at(path: impl Into<PathBuf>) -> SettingsFile {
        SettingsFile { path: path.into() }
    }

    /// The settings file of a data directory.
    pub fn in_data_directory(directory: &DataDirectory) -> SettingsFile {
        SettingsFile::at(directory.settings_file())
    }

    /// Where it is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the file. A missing file and an unreadable one are reported
    /// rather than repaired.
    pub fn read(&self) -> Result<Settings, SettingsError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(SettingsError::Missing);
            }
            Err(error) => return Err(SettingsError::Io(error)),
        };
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|error| SettingsError::Malformed(error.to_string()))?;
        Settings::from_value(&document)
            .ok_or_else(|| SettingsError::Malformed("the settings are not readable".to_string()))
    }
}

#[cfg(feature = "daemon")]
pub use writer::SettingsWriter;

#[cfg(feature = "daemon")]
mod writer {
    use super::{Settings, SettingsError, SettingsFile};

    use std::io::Write as _;

    /// The write side of the settings file.
    ///
    /// The daemon is the only writer, which this type carries the way
    /// [`crate::state::StateWriter`] does: it exists only in a build with the
    /// `daemon` feature, so the application and the command line interface
    /// cannot compile a call that writes `settings.json`. They move a choice
    /// by asking the daemon.
    #[derive(Debug)]
    pub struct SettingsWriter;

    impl SettingsWriter {
        /// Writes the settings atomically: a temporary file beside the real
        /// one, flushed to the disk, then renamed over it. The file is created
        /// 0600 and is plain, indented JSON a person can read.
        pub fn write(file: &SettingsFile, settings: &Settings) -> Result<(), SettingsError> {
            let mut bytes = serde_json::to_vec_pretty(&settings.to_value())
                .map_err(|error| SettingsError::Malformed(error.to_string()))?;
            bytes.push(b'\n');

            let path = file.path();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
            let mut handle = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                handle.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            handle.write_all(&bytes)?;
            handle.sync_all()?;
            drop(handle);
            std::fs::rename(&temporary, path)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use tempfile::TempDir;

    fn a_file() -> (TempDir, SettingsFile) {
        let temporary = TempDir::new().expect("a temporary directory");
        let file = SettingsFile::in_data_directory(&DataDirectory::at(temporary.path()));
        (temporary, file)
    }

    #[test]
    fn the_rule_feed_is_on_by_default() {
        assert!(Settings::default().rule_feed);
    }

    #[test]
    fn a_missing_settings_file_is_reported_rather_than_invented() {
        let (_temporary, file) = a_file();
        assert!(matches!(file.read(), Err(SettingsError::Missing)));
    }

    #[test]
    fn the_settings_round_trip_through_the_file() {
        let (_temporary, file) = a_file();
        let off = Settings { rule_feed: false };
        SettingsWriter::write(&file, &off).expect("a written settings file");
        assert_eq!(file.read().expect("a readable settings file"), off);
        let text = std::fs::read_to_string(file.path()).expect("the file");
        assert!(text.ends_with('\n'), "{text}");
    }

    /// The file is the choices and nothing else: no sensitive value, no path.
    /// A new choice changes this set on purpose.
    #[test]
    fn the_settings_file_holds_exactly_the_choices() {
        let (_temporary, file) = a_file();
        SettingsWriter::write(&file, &Settings::default()).expect("a written settings file");
        let written: Value = serde_json::from_slice(&std::fs::read(file.path()).expect("the file"))
            .expect("plain JSON");
        let keys: BTreeSet<&str> = written
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, BTreeSet::from(["rule_feed"]));
        for value in written.as_object().expect("an object").values() {
            assert!(value.is_boolean(), "only switches: {value}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_settings_file_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt;
        let (_temporary, file) = a_file();
        SettingsWriter::write(&file, &Settings::default()).expect("a written settings file");
        let mode = std::fs::metadata(file.path())
            .expect("the file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_settings_file_with_a_syntax_error_is_malformed() {
        let (_temporary, file) = a_file();
        std::fs::write(file.path(), b"{\"rule_feed\": false,,}").expect("a broken file");
        assert!(matches!(file.read(), Err(SettingsError::Malformed(_))));
    }

    /// A mistyped "off" is not read as "on".
    #[test]
    fn a_choice_of_the_wrong_type_makes_the_file_malformed() {
        let (_temporary, file) = a_file();
        std::fs::write(file.path(), b"{\"rule_feed\": \"off\"}").expect("a mistyped file");
        assert!(matches!(file.read(), Err(SettingsError::Malformed(_))));
        std::fs::write(file.path(), b"[false]").expect("not an object");
        assert!(matches!(file.read(), Err(SettingsError::Malformed(_))));
    }

    /// A file that names no choice, or names one this version does not know,
    /// reads as the defaults for what it leaves out.
    #[test]
    fn a_choice_the_file_does_not_name_is_at_its_default() {
        assert_eq!(
            Settings::from_value(&serde_json::json!({})),
            Some(Settings::default())
        );
        assert_eq!(
            Settings::from_value(&serde_json::json!({"rule_feed": false, "later": 1})),
            Some(Settings { rule_feed: false })
        );
    }
}
