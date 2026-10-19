//! **Show me how to fix this** on an Exposure Finding (spec section 8.5).
//!
//! An Exposure is the user's own setup and is never quarantined, so what it
//! offers instead is a how-to: the short text its Rule or Heuristic carries
//! in the Rule Pack (the `fix` meta key, which the daemon sends beside the
//! Finding), the file the Finding concerns, and **Open the file**. The
//! Simple Posture names that file by its name, the Developer Posture by its
//! path.
//!
//! **Open the file** hands that one path to an [`Opener`] and nothing else:
//! the app never reads the file, so no value in it ever reaches the window
//! (spec section 3.3). The path is the one the daemon sent with the Finding,
//! never one the window names. The Opener is a seam: the shell's
//! [`SystemOpener`] asks macOS to open the file in the user's default text
//! editor, and the tests pass a fake that only records the path, so no test
//! ever opens an editor.

use std::path::{Path, PathBuf};

use agentsweep_core::finding::Category;
use agentsweep_core::settings::Posture;
use agentsweep_core::state::RecordedFinding;
use serde_json::{Value, json};

/// What the button that shows the how-to says.
pub const SHOW_HOW_TO: &str = "Show me how to fix this";

/// What the button that opens the file says.
pub const OPEN_THE_FILE: &str = "Open the file";

/// Opens a file in the user's editor.
pub trait Opener {
    /// Asks the operating system to open `path` in the default editor; true
    /// when that worked.
    fn open(&self, path: &Path) -> bool;
}

/// macOS's default text editor, through `open -t`, never through a shell.
#[derive(Debug, Default)]
pub struct SystemOpener;

impl Opener for SystemOpener {
    fn open(&self, path: &Path) -> bool {
        std::process::Command::new("/usr/bin/open")
            .arg("-t")
            .arg(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

/// The how-to of one Exposure Finding as the window shows it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HowTo {
    /// What to change, from the Rule Pack, in the Simple Posture's words.
    pub steps: String,
    /// The file the Finding concerns: its name in the Simple Posture, its
    /// path in the Developer Posture.
    pub file: String,
}

impl HowTo {
    /// The how-to as the window receives it.
    pub fn to_value(&self) -> Value {
        json!({
            "label": SHOW_HOW_TO,
            "steps": self.steps,
            "file": self.file,
            "open": OPEN_THE_FILE,
        })
    }
}

/// The file an Exposure Finding concerns: the path the daemon sent with it,
/// when it sent an absolute one.
pub fn file_of(finding: &RecordedFinding) -> Option<PathBuf> {
    let path = Path::new(&finding.facts.path);
    path.is_absolute().then(|| path.to_path_buf())
}

/// How a Posture names a file: by its name in Simple, by its path in
/// Developer.
fn named(path: &Path, posture: Posture) -> String {
    match posture {
        Posture::Simple => path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        Posture::Developer => path.display().to_string(),
    }
}

/// The how-to an open Exposure Finding offers in a Posture, or none: a
/// Threat offers Quarantine instead, a Finding that is no longer open has
/// nothing left to fix, and a Finding whose Rule carries no how-to or whose
/// file is not known (a Problem, a Rule the pack no longer holds) has none
/// to show.
pub fn how_to(finding: &RecordedFinding, posture: Posture) -> Option<HowTo> {
    if finding.category != Category::Exposure || !finding.is_open() {
        return None;
    }
    let steps = finding.facts.fix.trim();
    if steps.is_empty() {
        return None;
    }
    let path = file_of(finding)?;
    Some(HowTo {
        steps: steps.to_string(),
        file: named(&path, posture),
    })
}

/// **Open the file** on an Exposure Finding: refused unless the Finding
/// offers its how-to, then hands the file it concerns to `opener`. The file
/// is never read here. Answers with the sentence the window shows.
pub fn open_the_file(
    finding: &RecordedFinding,
    posture: Posture,
    opener: &dyn Opener,
) -> Result<String, String> {
    if how_to(finding, posture).is_none() {
        return Err("Only something worth fixing has a file to open.".to_string());
    }
    let path = file_of(finding).ok_or_else(|| "The file is not known.".to_string())?;
    let file = named(&path, posture);
    match opener.open(&path) {
        true => Ok(format!("Opened {file} in your editor.")),
        false => Err(format!("{file} could not be opened.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;

    use agentsweep_core::finding::FindingState;
    use agentsweep_core::item::Kind;

    use crate::findings::tests::recorded;

    /// An Opener that records what it was asked to open and opens nothing.
    #[derive(Default)]
    struct FakeOpener {
        opened: RefCell<Vec<PathBuf>>,
    }

    impl Opener for FakeOpener {
        fn open(&self, path: &Path) -> bool {
            self.opened.borrow_mut().push(path.to_path_buf());
            true
        }
    }

    const SETTINGS: &str = "claude-code/user/settings/~/.claude/settings.json#/permissions/allow/0";
    const SETTINGS_FILE: &str = "/home/u/.claude/settings.json";
    const HOW_TO: &str = "Open the file and take the entry out.";
    /// A made-up value standing for what a sensitive field held.
    const SENSITIVE: &str = "hunter2hunter2-how-to";

    fn exposure() -> RecordedFinding {
        let mut finding = recorded(
            SETTINGS,
            Kind::SettingsEntry,
            "rule 0018",
            Category::Exposure,
            FindingState::Open,
        );
        finding.facts.fix = HOW_TO.to_string();
        finding.facts.path = SETTINGS_FILE.to_string();
        finding.facts.excerpt = format!("sha256:{SENSITIVE}");
        finding.file = SENSITIVE.to_string();
        finding
    }

    #[test]
    fn the_how_to_names_the_file_by_its_name_in_simple_and_its_path_in_developer() {
        let finding = exposure();
        assert_eq!(
            how_to(&finding, Posture::Simple),
            Some(HowTo {
                steps: HOW_TO.to_string(),
                file: "settings.json".to_string(),
            })
        );
        assert_eq!(
            how_to(&finding, Posture::Developer).map(|how_to| how_to.file),
            Some(SETTINGS_FILE.to_string())
        );
        let value = how_to(&finding, Posture::Simple).unwrap().to_value();
        assert_eq!(value["label"], SHOW_HOW_TO);
        assert_eq!(value["open"], OPEN_THE_FILE);
    }

    #[test]
    fn the_how_to_shows_no_sensitive_value() {
        for posture in Posture::ALL {
            let shown = how_to(&exposure(), posture).unwrap().to_value().to_string();
            assert!(!shown.contains(SENSITIVE), "{shown}");
            assert!(!shown.contains("sha256:"), "{shown}");
        }
    }

    #[test]
    fn only_an_open_exposure_with_its_how_to_and_its_file_offers_one() {
        let mut threat = exposure();
        threat.category = Category::Threat;
        let mut trusted = exposure();
        trusted.state = FindingState::Trusted;
        let mut no_how_to = exposure();
        no_how_to.facts.fix = "  ".to_string();
        let mut no_file = exposure();
        no_file.facts.path = String::new();
        let mut relative = exposure();
        relative.facts.path = "settings.json".to_string();
        for finding in [threat, trusted, no_how_to, no_file, relative] {
            for posture in Posture::ALL {
                assert_eq!(how_to(&finding, posture), None, "{finding:?}");
            }
        }
    }

    /// The path the daemon sent is what the operating system is asked to
    /// open, exactly; it does not exist here, which shows the app neither
    /// reads nor looks at the file before handing it on.
    #[test]
    fn open_the_file_asks_the_operating_system_to_open_exactly_that_file() {
        assert!(!Path::new(SETTINGS_FILE).exists());
        for (posture, named) in [
            (Posture::Simple, "settings.json"),
            (Posture::Developer, SETTINGS_FILE),
        ] {
            let opener = FakeOpener::default();
            let answer = open_the_file(&exposure(), posture, &opener);
            assert_eq!(answer, Ok(format!("Opened {named} in your editor.")));
            assert_eq!(*opener.opened.borrow(), vec![PathBuf::from(SETTINGS_FILE)]);
        }
    }

    #[test]
    fn open_the_file_opens_nothing_where_no_how_to_is_offered() {
        let opener = FakeOpener::default();
        let mut threat = exposure();
        threat.category = Category::Threat;
        assert!(open_the_file(&threat, Posture::Developer, &opener).is_err());
        let mut no_file = exposure();
        no_file.facts.path = String::new();
        assert!(open_the_file(&no_file, Posture::Simple, &opener).is_err());
        assert!(opener.opened.borrow().is_empty());
    }

    #[test]
    fn an_opener_that_fails_says_so() {
        struct Refusing;
        impl Opener for Refusing {
            fn open(&self, _path: &Path) -> bool {
                false
            }
        }
        assert_eq!(
            open_the_file(&exposure(), Posture::Simple, &Refusing),
            Err("settings.json could not be opened.".to_string())
        );
    }
}
