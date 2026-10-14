//! The settings file: the choices the user made, kept apart from the state.
//!
//! The state file is a cache the daemon can throw away: a file that is
//! missing or does not verify is rebuilt by the next Full Scan (spec section
//! 6.5). A choice the user made cannot be derived again from the logs, so it
//! does not live there. It lives in `settings.json` beside it, plain JSON
//! without a MAC, which a rebuilt state file leaves alone.
//!
//! The choices are the Rule Feed toggle (spec section 9.4) and the AI
//! Judgement choices of spec section 4.4: the active Judgement Engine, the
//! Ollama address and model, the Claude model id override and the three cloud
//! caps. The app update check, the Gate switch and the Posture join them in
//! their milestones.
//!
//! A missing settings file means every default. A settings file that cannot
//! be read back is reported rather than repaired: the daemon runs with the
//! defaults and says so in Health, and it does not write over the file, so a
//! user's "off" is never silently turned back on by the daemon itself.
//!
//! The file holds no sensitive value and no path: nothing but the choices.
//! The Claude API key above all is never here; it lives in the login Keychain
//! and only the daemon touches it (spec section 4.4).

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::paths::DataDirectory;

/// The key the Rule Feed toggle is kept under.
const RULE_FEED: &str = "rule_feed";
/// The key the active Judgement Engine is kept under.
pub const JUDGEMENT_ENGINE: &str = "judgement_engine";
/// The key the Ollama address is kept under.
pub const OLLAMA_ADDRESS: &str = "ollama_address";
/// The key the Ollama model is kept under.
pub const OLLAMA_MODEL: &str = "ollama_model";
/// The key the Claude model id override is kept under.
pub const CLAUDE_MODEL: &str = "claude_model";
/// The key the cloud cap per Scan is kept under.
pub const CLOUD_ITEMS_PER_SCAN: &str = "cloud_items_per_scan";
/// The key the cloud cap per day is kept under.
pub const CLOUD_ITEMS_PER_DAY: &str = "cloud_items_per_day";
/// The key the cloud cap per month, in US cents, is kept under.
pub const CLOUD_CENTS_PER_MONTH: &str = "cloud_cents_per_month";

/// The Ollama address AgentSweep asks unless the user names another loopback
/// one (spec section 4.4).
pub const DEFAULT_OLLAMA_ADDRESS: &str = "127.0.0.1:11434";

/// The Claude model AI Judgement asks when no override is set (spec section
/// 4.4). An empty override means this one.
pub const DEFAULT_CLAUDE_MODEL: &str = "claude-sonnet-5";

/// The longest model id the settings take. Real ids are far shorter; the bound
/// keeps a pasted paragraph out of the file.
const MODEL_ID_MAX: usize = 128;

/// Which Judgement Engine runs AI Judgement: exactly one, or none at all
/// (spec section 4.4, ADR 0005). Nothing in the daemon switches it on its own;
/// only the user's choice moves it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum JudgementEngine {
    /// AI Judgement is off. The default until onboarding turns an engine on.
    #[default]
    Off,
    /// Apple on-device, Foundation Models through the Swift sidecar.
    Apple,
    /// Ollama on this Mac, on a loopback address only.
    Ollama,
    /// The Claude API, under the user's own key.
    Claude,
}

impl JudgementEngine {
    /// Every engine, and off.
    pub const ALL: [JudgementEngine; 4] = [
        JudgementEngine::Off,
        JudgementEngine::Apple,
        JudgementEngine::Ollama,
        JudgementEngine::Claude,
    ];

    /// The spelling the settings file, the Event Log and the wire carry.
    pub fn as_str(self) -> &'static str {
        match self {
            JudgementEngine::Off => "off",
            JudgementEngine::Apple => "apple",
            JudgementEngine::Ollama => "ollama",
            JudgementEngine::Claude => "claude",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<JudgementEngine> {
        JudgementEngine::ALL
            .into_iter()
            .find(|engine| engine.as_str() == text)
    }

    /// True for every engine, false for off.
    pub fn is_on(self) -> bool {
        self != JudgementEngine::Off
    }
}

impl fmt::Display for JudgementEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a choice was not taken. The settings file is left as it was.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChoiceRefused {
    /// Which choice, by its settings key.
    pub choice: &'static str,
    /// The sentence a person reads. It never repeats the value refused.
    pub reason: String,
}

impl ChoiceRefused {
    /// A refusal of one choice, with the sentence a person reads.
    pub fn new(choice: &'static str, reason: impl Into<String>) -> ChoiceRefused {
        ChoiceRefused {
            choice,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ChoiceRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.choice, self.reason)
    }
}

impl std::error::Error for ChoiceRefused {}

/// The address Ollama is asked at: a loopback host and a port, nothing else
/// (spec section 4.4). `OLLAMA_HOST` is never read; this setting is the only
/// way to move it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OllamaAddress(String);

impl Default for OllamaAddress {
    fn default() -> OllamaAddress {
        OllamaAddress(DEFAULT_OLLAMA_ADDRESS.to_string())
    }
}

impl OllamaAddress {
    /// Takes `host:port`, where the host is a loopback IP address (any address
    /// in `127.0.0.0/8`, or `[::1]`) or the name `localhost`, and the port is
    /// not zero. Anything else is refused, a host name above all: a name other
    /// than `localhost` could resolve to another machine.
    pub fn parse(text: &str) -> Result<OllamaAddress, ChoiceRefused> {
        let refused = |reason: &str| ChoiceRefused::new(OLLAMA_ADDRESS, reason);
        let off_this_mac = "Ollama is asked on this Mac only: a loopback address or localhost";
        let (host, port) = text.trim().rsplit_once(':').ok_or_else(|| {
            refused("the Ollama address is a host and a port, such as 127.0.0.1:11434")
        })?;
        let port: u16 = port
            .parse()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| refused("the Ollama address needs a port from 1 to 65535"))?;
        let host = if host.eq_ignore_ascii_case("localhost") {
            "localhost".to_string()
        } else {
            let bare = host
                .strip_prefix('[')
                .and_then(|inner| inner.strip_suffix(']'))
                .unwrap_or(host);
            let address: IpAddr = bare.parse().map_err(|_| refused(off_this_mac))?;
            if !address.is_loopback() {
                return Err(refused(off_this_mac));
            }
            match address {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => format!("[{v6}]"),
            }
        };
        Ok(OllamaAddress(format!("{host}:{port}")))
    }

    /// The address as `host:port`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OllamaAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks a model id the user typed: empty, or a short name of letters,
/// digits and `.`, `-`, `_`, `:`, `/`, `@`. A path is refused, and so is
/// anything that looks like an API key pasted into the wrong field, so the
/// settings file never holds one.
pub fn model_id(choice: &'static str, text: &str) -> Result<String, ChoiceRefused> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(String::new());
    }
    if text.len() > MODEL_ID_MAX {
        return Err(ChoiceRefused::new(
            choice,
            "a model id is at most 128 characters",
        ));
    }
    if text.starts_with("sk-") {
        return Err(ChoiceRefused::new(
            choice,
            "this looks like an API key, which goes in the key field and never in a setting",
        ));
    }
    if text.starts_with(['/', '~', '.']) || text.contains("..") {
        return Err(ChoiceRefused::new(
            choice,
            "a model id is a name, not a path",
        ));
    }
    let allowed =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '/' | '@');
    if !text.chars().all(allowed) {
        return Err(ChoiceRefused::new(
            choice,
            "a model id holds letters, digits and . - _ : / @ only",
        ));
    }
    Ok(text.to_string())
}

/// The three caps on what goes to the Claude API (spec section 4.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloudCaps {
    /// Items sent per Scan. 25 by default.
    pub items_per_scan: u32,
    /// Items sent per day. 200 by default.
    pub items_per_day: u32,
    /// What a month may cost, in US cents, tracked from the API's returned
    /// usage. 500, five dollars, by default.
    pub cents_per_month: u32,
}

impl Default for CloudCaps {
    fn default() -> CloudCaps {
        CloudCaps {
            items_per_scan: 25,
            items_per_day: 200,
            cents_per_month: 500,
        }
    }
}

/// The AI Judgement choices (spec sections 4.4 and 8.10).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JudgementSettings {
    /// The one active engine, off by default.
    pub engine: JudgementEngine,
    /// Where Ollama is asked, loopback only.
    pub ollama_address: OllamaAddress,
    /// The Ollama model, empty until the user names one. AgentSweep never
    /// pulls a model.
    pub ollama_model: String,
    /// The Claude model id override, empty for [`DEFAULT_CLAUDE_MODEL`].
    pub claude_model: String,
    /// The caps on the cloud engine.
    pub caps: CloudCaps,
}

impl JudgementSettings {
    /// The Claude model id AI Judgement asks: the override, or the default
    /// when there is none.
    pub fn claude_model_in_use(&self) -> &str {
        match self.claude_model.is_empty() {
            true => DEFAULT_CLAUDE_MODEL,
            false => &self.claude_model,
        }
    }

    /// The model id an engine runs, as the Event Log names it: the Ollama
    /// model, the Claude model in use, and nothing for Apple on-device, whose
    /// model is the operating system's, or for off.
    pub fn model_of(&self, engine: JudgementEngine) -> &str {
        match engine {
            JudgementEngine::Ollama => &self.ollama_model,
            JudgementEngine::Claude => self.claude_model_in_use(),
            JudgementEngine::Apple | JudgementEngine::Off => "",
        }
    }
}

/// Every choice the user made, each at its default until they make it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    /// The Rule Feed toggle (spec section 9.4). On by default; off means no
    /// request at all and the bundled Rule Pack only.
    pub rule_feed: bool,
    /// The AI Judgement choices (spec section 4.4).
    pub judgement: JudgementSettings,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            rule_feed: true,
            judgement: JudgementSettings::default(),
        }
    }
}

impl Settings {
    /// The settings as the file carries them.
    pub fn to_value(&self) -> Value {
        let judgement = &self.judgement;
        let mut map = Map::new();
        map.insert(RULE_FEED.to_string(), Value::from(self.rule_feed));
        map.insert(
            JUDGEMENT_ENGINE.to_string(),
            Value::from(judgement.engine.as_str()),
        );
        map.insert(
            OLLAMA_ADDRESS.to_string(),
            Value::from(judgement.ollama_address.as_str()),
        );
        map.insert(
            OLLAMA_MODEL.to_string(),
            Value::from(judgement.ollama_model.as_str()),
        );
        map.insert(
            CLAUDE_MODEL.to_string(),
            Value::from(judgement.claude_model.as_str()),
        );
        map.insert(
            CLOUD_ITEMS_PER_SCAN.to_string(),
            Value::from(judgement.caps.items_per_scan),
        );
        map.insert(
            CLOUD_ITEMS_PER_DAY.to_string(),
            Value::from(judgement.caps.items_per_day),
        );
        map.insert(
            CLOUD_CENTS_PER_MONTH.to_string(),
            Value::from(judgement.caps.cents_per_month),
        );
        Value::Object(map)
    }

    /// Reads back what [`Settings::to_value`] wrote.
    ///
    /// A choice the file does not name is at its default, which is how a file
    /// written before a later choice existed reads. A key this version does
    /// not know is passed over. A choice of the wrong type is not read as its
    /// default: the whole file is unreadable, so a mistyped "off" is reported
    /// rather than taken for "on". So is a choice the daemon refuses at write,
    /// an Ollama address off this Mac above all: it is never honoured because
    /// someone wrote it into the file by hand.
    pub fn from_value(value: &Value) -> Option<Settings> {
        let map = value.as_object()?;
        let mut settings = Settings::default();
        if let Some(rule_feed) = map.get(RULE_FEED) {
            settings.rule_feed = rule_feed.as_bool()?;
        }
        let judgement = &mut settings.judgement;
        if let Some(engine) = map.get(JUDGEMENT_ENGINE) {
            judgement.engine = JudgementEngine::parse(engine.as_str()?)?;
        }
        if let Some(address) = map.get(OLLAMA_ADDRESS) {
            judgement.ollama_address = OllamaAddress::parse(address.as_str()?).ok()?;
        }
        if let Some(model) = map.get(OLLAMA_MODEL) {
            judgement.ollama_model = model_id(OLLAMA_MODEL, model.as_str()?).ok()?;
        }
        if let Some(model) = map.get(CLAUDE_MODEL) {
            judgement.claude_model = model_id(CLAUDE_MODEL, model.as_str()?).ok()?;
        }
        let cap = |key: &str, into: &mut u32| -> Option<()> {
            if let Some(value) = map.get(key) {
                *into = u32::try_from(value.as_u64()?).ok()?;
            }
            Some(())
        };
        cap(CLOUD_ITEMS_PER_SCAN, &mut judgement.caps.items_per_scan)?;
        cap(CLOUD_ITEMS_PER_DAY, &mut judgement.caps.items_per_day)?;
        cap(CLOUD_CENTS_PER_MONTH, &mut judgement.caps.cents_per_month)?;
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
        let off = Settings {
            rule_feed: false,
            ..Settings::default()
        };
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
        assert_eq!(
            keys,
            BTreeSet::from([
                "claude_model",
                "cloud_cents_per_month",
                "cloud_items_per_day",
                "cloud_items_per_scan",
                "judgement_engine",
                "ollama_address",
                "ollama_model",
                "rule_feed",
            ])
        );
        for value in written.as_object().expect("an object").values() {
            assert!(
                value.is_boolean() || value.is_u64() || value.is_string(),
                "only switches, numbers and short names: {value}"
            );
        }
    }

    /// Whatever the user chose, the file holds no path and nothing that is a
    /// key: the Claude API key lives in the login Keychain alone.
    #[test]
    fn no_choice_carries_a_path_or_a_key() {
        let (_temporary, file) = a_file();
        let chosen = Settings {
            rule_feed: false,
            judgement: JudgementSettings {
                engine: JudgementEngine::Claude,
                ollama_address: OllamaAddress::parse("localhost:11500").expect("loopback"),
                ollama_model: model_id(OLLAMA_MODEL, "qwen3:8b").expect("a model"),
                claude_model: model_id(CLAUDE_MODEL, "claude-opus-5").expect("a model"),
                caps: CloudCaps {
                    items_per_scan: 5,
                    items_per_day: 50,
                    cents_per_month: 100,
                },
            },
        };
        SettingsWriter::write(&file, &chosen).expect("a written settings file");
        let text = std::fs::read_to_string(file.path()).expect("the file");
        let written: Value = serde_json::from_str(&text).expect("plain JSON");
        for (key, value) in written.as_object().expect("an object") {
            if let Some(text) = value.as_str() {
                assert!(!text.starts_with(['/', '~']), "{key} is a path: {text}");
                assert!(!text.starts_with("sk-"), "{key} is a key: {text}");
            }
        }
        assert!(!text.contains("key"), "{text}");
        assert_eq!(file.read().expect("a readable settings file"), chosen);
    }

    /// A settings file written before the AI Judgement choices existed reads
    /// with every one of them at its default.
    #[test]
    fn a_file_from_before_the_judgement_choices_reads_them_at_their_defaults() {
        let (_temporary, file) = a_file();
        std::fs::write(file.path(), b"{\n  \"rule_feed\": false\n}\n").expect("an older file");
        let read = file.read().expect("a readable settings file");
        assert!(!read.rule_feed);
        let judgement = &read.judgement;
        assert_eq!(judgement.engine, JudgementEngine::Off);
        assert_eq!(judgement.ollama_address.as_str(), "127.0.0.1:11434");
        assert_eq!(judgement.ollama_model, "");
        assert_eq!(judgement.claude_model, "");
        assert_eq!(judgement.claude_model_in_use(), "claude-sonnet-5");
        assert_eq!(judgement.caps.items_per_scan, 25);
        assert_eq!(judgement.caps.items_per_day, 200);
        assert_eq!(judgement.caps.cents_per_month, 500);
    }

    #[test]
    fn the_engine_is_off_by_default_and_spelled_one_way() {
        assert_eq!(Settings::default().judgement.engine, JudgementEngine::Off);
        for engine in JudgementEngine::ALL {
            assert_eq!(JudgementEngine::parse(engine.as_str()), Some(engine));
        }
        assert_eq!(JudgementEngine::parse("Claude"), None);
        assert!(!JudgementEngine::Off.is_on());
        assert!(JudgementEngine::Apple.is_on());
    }

    #[test]
    fn a_loopback_ollama_address_is_taken() {
        for (typed, kept) in [
            ("127.0.0.1:11434", "127.0.0.1:11434"),
            ("127.0.0.2:8080", "127.0.0.2:8080"),
            ("localhost:11434", "localhost:11434"),
            ("LocalHost:11434", "localhost:11434"),
            ("[::1]:11434", "[::1]:11434"),
            (" 127.0.0.1:11434 ", "127.0.0.1:11434"),
        ] {
            let address = OllamaAddress::parse(typed).expect(typed);
            assert_eq!(address.as_str(), kept);
        }
    }

    #[test]
    fn an_ollama_address_off_this_mac_is_refused() {
        for typed in [
            "192.0.2.10:11434",
            "0.0.0.0:11434",
            "[2001:db8::1]:11434",
            "ollama.example.invalid:11434",
            "localhost.example.invalid:11434",
            "my-mac.local:11434",
            "127.0.0.1",
            "127.0.0.1:0",
            "127.0.0.1:99999",
            "http://127.0.0.1:11434",
            "",
        ] {
            let refused = OllamaAddress::parse(typed).expect_err(typed);
            assert_eq!(refused.choice, OLLAMA_ADDRESS);
        }
    }

    /// An address someone wrote into the file by hand is never honoured: the
    /// whole file is unreadable, which means every default and a Health note.
    #[test]
    fn a_file_with_an_ollama_address_off_this_mac_is_malformed() {
        let (_temporary, file) = a_file();
        std::fs::write(
            file.path(),
            b"{\"ollama_address\": \"ollama.example.invalid:11434\"}",
        )
        .expect("a hand-edited file");
        assert!(matches!(file.read(), Err(SettingsError::Malformed(_))));
    }

    #[test]
    fn a_model_id_is_a_short_name_and_never_a_path_or_a_key() {
        assert_eq!(model_id(CLAUDE_MODEL, "").expect("empty"), "");
        assert_eq!(
            model_id(OLLAMA_MODEL, "hf.co/example/model:Q4_K_M").expect("a name"),
            "hf.co/example/model:Q4_K_M"
        );
        for typed in [
            "/Users/example/model.gguf",
            "~/models/x",
            "../x",
            "sk-ant-api03-not-a-real-key",
            "two words",
            "x\u{202e}y",
        ] {
            assert!(model_id(CLAUDE_MODEL, typed).is_err(), "{typed}");
        }
        assert!(model_id(CLAUDE_MODEL, &"a".repeat(129)).is_err());
    }

    #[test]
    fn the_model_an_engine_runs_is_named_for_the_event_log() {
        let mut judgement = JudgementSettings::default();
        assert_eq!(
            judgement.model_of(JudgementEngine::Claude),
            "claude-sonnet-5"
        );
        assert_eq!(judgement.model_of(JudgementEngine::Apple), "");
        assert_eq!(judgement.model_of(JudgementEngine::Off), "");
        judgement.claude_model = "claude-opus-5".to_string();
        judgement.ollama_model = "qwen3:8b".to_string();
        assert_eq!(judgement.model_of(JudgementEngine::Claude), "claude-opus-5");
        assert_eq!(judgement.model_of(JudgementEngine::Ollama), "qwen3:8b");
    }

    #[test]
    fn a_cap_of_the_wrong_type_makes_the_file_malformed() {
        for document in [
            serde_json::json!({"cloud_items_per_scan": -1}),
            serde_json::json!({"cloud_items_per_day": "200"}),
            serde_json::json!({"cloud_cents_per_month": 5_000_000_000u64}),
            serde_json::json!({"judgement_engine": "typesafe"}),
        ] {
            assert_eq!(Settings::from_value(&document), None, "{document}");
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
            Some(Settings {
                rule_feed: false,
                ..Settings::default()
            })
        );
    }
}
