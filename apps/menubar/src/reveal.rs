//! **Reveal in Finder** for a quarantined Item's payload (spec sections 5.1
//! and 8.5), in the Developer Posture only.
//!
//! The app never builds a path into the quarantine store: it asks the daemon
//! through the reveal-receipt request, takes the payload path of the Receipt
//! that stopped the Finding from the answer, and hands that path to a
//! [`Finder`]. The Finder is a seam: the shell's [`SystemFinder`] asks the
//! macOS workspace to select the payload in a Finder window, and the tests
//! pass a fake that only records the path, so no test ever opens Finder.

use std::path::{Path, PathBuf};

use agentsweep_core::settings::Posture;
use agentsweep_core::state::RecordedFinding;
use agentsweep_ipc::ClientError;
use agentsweep_ipc::protocol::RevealedReceipt;

use crate::asking::refusal;
use crate::developer::offers_reveal;

/// Shows a path in the file viewer.
pub trait Finder {
    /// Selects `path` in a file viewer window; true when that worked.
    fn reveal(&self, path: &Path) -> bool;
}

/// The macOS Finder, through the shared workspace.
#[derive(Debug, Default)]
pub struct SystemFinder;

impl Finder for SystemFinder {
    #[cfg(target_os = "macos")]
    fn reveal(&self, path: &Path) -> bool {
        use objc2_app_kit::NSWorkspace;
        use objc2_foundation::NSString;

        let workspace = NSWorkspace::sharedWorkspace();
        let full = NSString::from_str(&path.display().to_string());
        workspace.selectFile_inFileViewerRootedAtPath(Some(&full), &NSString::from_str(""))
    }

    /// Anywhere but macOS there is no file viewer to ask yet (spec section
    /// 6.1).
    #[cfg(not(target_os = "macos"))]
    fn reveal(&self, _path: &Path) -> bool {
        false
    }
}

/// The payload of the Receipt `receipt_id` in a reveal-receipt answer, or the
/// sentence saying why there is none to show.
pub fn payload_of(receipts: &[RevealedReceipt], receipt_id: &str) -> Result<PathBuf, String> {
    let receipt = receipts
        .iter()
        .find(|receipt| receipt.receipt_id == receipt_id)
        .ok_or_else(|| "AgentSweep holds no Receipt for this Item any more.".to_string())?;
    match receipt.payload_path.is_empty() {
        true => Err(
            "Nothing was moved into quarantine for this Item, so there is nothing to \
                     show in Finder."
                .to_string(),
        ),
        false => Ok(PathBuf::from(&receipt.payload_path)),
    }
}

/// Reveals the payload of a stopped Finding: refused unless the Posture and
/// the Finding offer it, then asks the daemon for its Receipts with `ask`
/// and hands the payload path it names to `finder`. Answers with the
/// sentence the window shows.
pub fn reveal_in_finder(
    finding: &RecordedFinding,
    posture: Posture,
    ask: impl FnOnce() -> Result<Vec<RevealedReceipt>, ClientError>,
    finder: &dyn Finder,
) -> Result<String, String> {
    if !offers_reveal(finding, posture) {
        return Err(
            "Reveal in Finder is offered on a quarantined Item in the Developer Posture \
                    only."
                .to_string(),
        );
    }
    let receipts = ask().map_err(|error| refusal(&error))?;
    let payload = payload_of(&receipts, &finding.receipt_id)?;
    match finder.reveal(&payload) {
        true => Ok(format!("Shown in Finder: {}", payload.display())),
        false => Err(format!(
            "Finder could not be asked to show {}.",
            payload.display()
        )),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::cell::RefCell;

    use agentsweep_core::envelope::Timestamp;
    use agentsweep_core::eventlog::Actor;
    use agentsweep_core::finding::{Category, FindingState};
    use agentsweep_core::item::{ItemId, Kind};

    use crate::findings::tests::recorded;

    /// A Finder that records what it was asked to show and opens nothing.
    #[derive(Default)]
    pub(crate) struct FakeFinder {
        pub(crate) shown: RefCell<Vec<PathBuf>>,
    }

    impl Finder for FakeFinder {
        fn reveal(&self, path: &Path) -> bool {
            self.shown.borrow_mut().push(path.to_path_buf());
            true
        }
    }

    const RECEIPT: &str = "q-0123456789abcdef0123456789abcdef";
    const SKILL: &str = "claude-code/user/skill/~/.claude/skills/pdf-helper";

    fn receipt(id: &str, payload: &str) -> RevealedReceipt {
        RevealedReceipt {
            receipt_id: id.to_string(),
            item_id: ItemId::from_recorded(SKILL),
            kind: Some(Kind::Skill),
            original_path: "/home/u/.claude/skills/pdf-helper".to_string(),
            payload_path: payload.to_string(),
            actor: Actor::Auto,
            quarantined_at: Timestamp::parse("2026-10-15T08:00:00.000Z").expect("a moment"),
            finding_id: String::new(),
            rule_id: 1,
            re_enforced: 0,
        }
    }

    fn stopped() -> RecordedFinding {
        recorded(
            SKILL,
            Kind::Skill,
            "rule 0001",
            Category::Threat,
            FindingState::Stopped,
        )
    }

    #[test]
    fn the_payload_the_daemon_names_is_what_finder_is_asked_to_show() {
        let finder = FakeFinder::default();
        let payload = "/data/quarantine/q-0123456789abcdef0123456789abcdef/payload";
        let asked = RefCell::new(0);
        let answer = reveal_in_finder(
            &stopped(),
            Posture::Developer,
            || {
                *asked.borrow_mut() += 1;
                Ok(vec![
                    receipt("q-other", "/data/other"),
                    receipt(RECEIPT, payload),
                ])
            },
            &finder,
        );
        assert_eq!(answer, Ok(format!("Shown in Finder: {payload}")));
        assert_eq!(*asked.borrow(), 1, "one reveal-receipt request");
        assert_eq!(*finder.shown.borrow(), vec![PathBuf::from(payload)]);
    }

    #[test]
    fn nothing_is_asked_or_shown_in_simple_or_on_an_open_finding() {
        let finder = FakeFinder::default();
        let never =
            || -> Result<Vec<RevealedReceipt>, ClientError> { panic!("the daemon is not asked") };
        assert!(reveal_in_finder(&stopped(), Posture::Simple, never, &finder).is_err());
        let mut open = stopped();
        open.state = FindingState::Open;
        assert!(reveal_in_finder(&open, Posture::Developer, never, &finder).is_err());
        assert!(finder.shown.borrow().is_empty());
    }

    #[test]
    fn a_receipt_without_a_payload_or_one_not_held_shows_nothing() {
        assert!(payload_of(&[receipt(RECEIPT, "")], RECEIPT).is_err());
        assert!(payload_of(&[receipt("q-other", "/p")], RECEIPT).is_err());
        let finder = FakeFinder::default();
        let answer = reveal_in_finder(
            &stopped(),
            Posture::Developer,
            || Ok(vec![receipt(RECEIPT, "")]),
            &finder,
        );
        assert!(answer.is_err());
        assert!(finder.shown.borrow().is_empty());
    }
}
