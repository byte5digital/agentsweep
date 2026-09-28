//! Health: every state AgentSweep can be in, in one struct.
//!
//! Spec section 6.6 asks for one `Health` struct with every state as a field
//! and one precedence that decides which of them a person is shown. The
//! precedence lives here rather than in the daemon, the app or the command
//! line interface, so the three of them say the same sentence about the same
//! machine.
//!
//! The states of that list answered so far are Protection off, the two chain
//! states, the projects that need permission, the two Rule Pack notices, a
//! Scan in flight and all clear. The Gate lines arrive with their own
//! milestone; their place in the order is kept here so that adding one is a
//! field and a line rather than a rewrite.
//!
//! Beside the states, Health says which Rule Pack is in force and when it was
//! released, which is the "Rules updated <date>" line: the date is read off the
//! pack's signed manifest, never off the clock of the machine that fetched it.

use std::fmt;

use crate::chain::ChainState;
use crate::envelope::Timestamp;
use crate::pack::released_day;
use crate::packs::PackOrigin;
use crate::state::IgnoredPack;

/// How long the Rule Feed may go unanswered before Health says so: thirty
/// days (spec section 6.6, notice 6).
pub const FEED_UNREACHABLE_AFTER_MS: i64 = 30 * 24 * 3_600_000;

/// The notice an unreadable settings file raises. The file is left as it is,
/// so the choice in it comes back once it reads again.
pub const SETTINGS_UNREADABLE: &str = "The settings file could not be read, so every setting \
     is at its default until it is fixed. AgentSweep leaves the file as it is.";

/// Whether AgentSweep is working in the background at all.
///
/// The app and the command line interface answer this by whether the daemon
/// replies; the daemon itself is running, so it answers [`Protection::On`].
/// There is no pause switch in v1: off is either an unreachable daemon or a
/// registration the user has not approved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Protection {
    /// The daemon is running and watching.
    On,
    /// The daemon is not running, or its registration needs approval. The
    /// string is the reason, for the Developer Posture.
    Off(String),
}

impl Protection {
    /// True when nothing is protecting the machine.
    pub fn is_off(&self) -> bool {
        matches!(self, Protection::Off(_))
    }

    /// Why Protection is off, empty when it is on.
    pub fn reason(&self) -> &str {
        match self {
            Protection::On => "",
            Protection::Off(reason) => reason,
        }
    }
}

/// What the state file was found to be at daemon start.
///
/// A missing or MAC-failed file is not an error the user has to act on: it is
/// rebuilt from the logs by the next Full Scan (spec section 6.5). It is a
/// note beside the headline rather than a state of its own, because nothing
/// about the machine is wrong.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StateFileHealth {
    /// The file was read and its whole-file MAC verified.
    #[default]
    Loaded,
    /// There was no file, which is every first start.
    Missing,
    /// The file was there and did not verify, or could not be read back.
    Rebuilt,
}

impl StateFileHealth {
    /// The spelling the status output carries.
    pub fn as_str(self) -> &'static str {
        match self {
            StateFileHealth::Loaded => "loaded",
            StateFileHealth::Missing => "missing",
            StateFileHealth::Rebuilt => "rebuilt",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<StateFileHealth> {
        match text {
            "loaded" => Some(StateFileHealth::Loaded),
            "missing" => Some(StateFileHealth::Missing),
            "rebuilt" => Some(StateFileHealth::Rebuilt),
            _ => None,
        }
    }

    /// The note this state adds under the headline, empty when there is none.
    pub fn note(self) -> &'static str {
        match self {
            StateFileHealth::Loaded => "",
            StateFileHealth::Missing => "The cached state was not there and was rebuilt.",
            StateFileHealth::Rebuilt => "The cached state did not verify and was rebuilt.",
        }
    }
}

/// Every state AgentSweep can be in, at one moment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Health {
    /// Whether anything is protecting the machine at all.
    pub protection: Protection,
    /// What verifying the Event Log found.
    pub events: ChainState,
    /// What verifying the Baseline found.
    pub baseline: ChainState,
    /// How many registered projects the operating system will not let
    /// AgentSweep read.
    pub projects_need_permission: usize,
    /// What the state file was found to be.
    pub state_file: StateFileHealth,
    /// True when the settings file is there and cannot be read back: the
    /// daemon runs with every default and leaves the file as it is.
    pub settings_unreadable: bool,
    /// True while a Scan is running.
    pub scanning: bool,
    /// When the last Full Scan finished, absent before the first one.
    pub last_full_scan: Option<Timestamp>,
    /// How many Items the last Full Scan saw.
    pub items: usize,
    /// How many Findings are open right now.
    pub open_findings: usize,
    /// The version of the Rule Pack in force, zero when nothing is known.
    pub rule_pack: u64,
    /// Where the Rule Pack in force came from.
    pub rule_pack_origin: PackOrigin,
    /// When the Rule Pack in force was released, RFC 3339, as its signed
    /// manifest states it. Empty when nothing is known.
    pub rules_released_at: String,
    /// Whether the Rule Feed toggle is on.
    pub rule_feed: bool,
    /// A newer Rule Pack that was ignored because it needs a newer
    /// AgentSweep.
    pub ignored_pack: Option<IgnoredPack>,
    /// Set once the Rule Feed has not answered for over thirty days: the
    /// moment it first failed to.
    pub feed_unreachable: Option<Timestamp>,
}

impl Default for Health {
    /// A machine nothing is known about yet: Protection off, because silence
    /// is never an all-clear.
    fn default() -> Health {
        Health {
            protection: Protection::Off("no daemon answered".to_string()),
            events: ChainState::Intact,
            baseline: ChainState::Intact,
            projects_need_permission: 0,
            state_file: StateFileHealth::Loaded,
            settings_unreadable: false,
            scanning: false,
            last_full_scan: None,
            items: 0,
            open_findings: 0,
            rule_pack: 0,
            rule_pack_origin: PackOrigin::Bundled,
            rules_released_at: String::new(),
            rule_feed: true,
            ignored_pack: None,
            feed_unreachable: None,
        }
    }
}

impl Health {
    /// The health of a running daemon with nothing wrong with it.
    pub fn running() -> Health {
        Health {
            protection: Protection::On,
            ..Health::default()
        }
    }

    /// The health a client reports when no daemon answered.
    pub fn unreachable(reason: &str) -> Health {
        Health {
            protection: Protection::Off(reason.to_string()),
            ..Health::default()
        }
    }

    /// True when either chain does not verify while the key is in hand, which
    /// is the "records tampered" state and freezes automatic Quarantine.
    pub fn records_tampered(&self) -> bool {
        self.events.freezes_automatic_quarantine() || self.baseline.freezes_automatic_quarantine()
    }

    /// True when a chain is well formed but no key can vouch for it, which is
    /// the "protection state was reset" state.
    pub fn state_was_reset(&self) -> bool {
        self.events == ChainState::KeyMissing || self.baseline == ChainState::KeyMissing
    }

    /// The date "Rules updated <date>" shows, `YYYY-MM-DD`, absent when no
    /// Rule Pack is known.
    pub fn rules_updated(&self) -> Option<String> {
        released_day(&self.rules_released_at)
    }

    /// The moment the Rule Feed first failed to answer, when that is over
    /// thirty days before `now`, which is when Health says so.
    pub fn feed_unreachable_at(since: Option<Timestamp>, now: Timestamp) -> Option<Timestamp> {
        since.filter(|since| now.as_unix_ms() - since.as_unix_ms() > FEED_UNREACHABLE_AFTER_MS)
    }

    /// The one sentence a person is shown, by the precedence of spec section
    /// 6.6.
    ///
    /// The order is Protection off, records tampered, protection state reset,
    /// projects that need permission, then the Gate lines once they exist, then
    /// the Rule Pack notices (a newer pack ignored because it needs a newer
    /// AgentSweep, the Rule Feed unreachable for over thirty days), then a
    /// Scan in flight, then all clear with the last-checked time.
    pub fn headline(&self) -> String {
        if self.protection.is_off() {
            return "Protection is off.".to_string();
        }
        if self.records_tampered() {
            return "Records tampered.".to_string();
        }
        if self.state_was_reset() {
            return "Protection state was reset.".to_string();
        }
        if self.projects_need_permission > 0 {
            return match self.projects_need_permission {
                1 => "1 project needs permission.".to_string(),
                many => format!("{many} projects need permission."),
            };
        }
        if self.ignored_pack.is_some() {
            return "Newer rules need a newer AgentSweep.".to_string();
        }
        if self.feed_unreachable.is_some() {
            return "The rule feed has not been reachable for over 30 days.".to_string();
        }
        if self.scanning {
            return "Checking now.".to_string();
        }
        match self.last_full_scan {
            Some(at) => format!("All clear, last checked {at}."),
            None => "All clear, nothing checked yet.".to_string(),
        }
    }

    /// What is said under the headline: the reason Protection is off, the note
    /// a rebuilt state file leaves, the notice an unreadable settings file
    /// raises, and how many Findings are open.
    pub fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if let Protection::Off(reason) = &self.protection
            && !reason.is_empty()
        {
            notes.push(reason.clone());
        }
        let rebuilt = self.state_file.note();
        if !rebuilt.is_empty() {
            notes.push(rebuilt.to_string());
        }
        if self.settings_unreadable {
            notes.push(SETTINGS_UNREADABLE.to_string());
        }
        if let Some(ignored) = &self.ignored_pack {
            notes.push(format!(
                "Rule Pack {} needs AgentSweep {} or later. The rules in use stay in force \
                 until AgentSweep is updated.",
                ignored.pack_version, ignored.minimum_engine_version
            ));
        }
        if let Some(since) = self.feed_unreachable {
            notes.push(format!(
                "The rule feed has not answered since {}. The rules in use stay in force.",
                since.day()
            ));
        }
        match self.open_findings {
            0 => {}
            1 => notes.push("1 Finding is open.".to_string()),
            many => notes.push(format!("{many} Findings are open.")),
        }
        if let Some(day) = self.rules_updated() {
            notes.push(format!(
                "Rules updated {day} (Rule Pack {}, {}).",
                self.rule_pack, self.rule_pack_origin
            ));
            if !self.rule_feed {
                notes.push(
                    "The rule feed is off, so the rules bundled with AgentSweep are in force."
                        .to_string(),
                );
            }
        }
        notes
    }
}

impl fmt::Display for Health {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.headline())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::chain::BreakReason;

    fn broken() -> ChainState {
        ChainState::Broken {
            sequence: 3,
            reason: BreakReason::MacFailed,
        }
    }

    #[test]
    fn a_daemon_that_does_not_answer_reads_protection_off() {
        let health = Health::unreachable("no daemon answered");
        assert_eq!(health.headline(), "Protection is off.");
        assert!(health.notes().contains(&"no daemon answered".to_string()));
    }

    /// The whole point of a precedence is that the worse state wins, so every
    /// rung is checked against the one above it.
    #[test]
    fn the_precedence_is_the_one_the_specification_fixes() {
        let mut health = Health::running();
        health.events = broken();
        health.baseline = ChainState::KeyMissing;
        health.projects_need_permission = 2;
        health.scanning = true;
        assert_eq!(health.headline(), "Records tampered.");

        health.protection = Protection::Off("not registered".to_string());
        assert_eq!(health.headline(), "Protection is off.");

        health.protection = Protection::On;
        health.events = ChainState::Intact;
        assert_eq!(health.headline(), "Protection state was reset.");

        health.baseline = ChainState::Intact;
        assert_eq!(health.headline(), "2 projects need permission.");

        health.projects_need_permission = 1;
        assert_eq!(health.headline(), "1 project needs permission.");

        health.projects_need_permission = 0;
        assert_eq!(health.headline(), "Checking now.");

        health.scanning = false;
        assert_eq!(health.headline(), "All clear, nothing checked yet.");

        let at = Timestamp::parse("2026-09-24T10:00:00.000Z").expect("a readable moment");
        health.last_full_scan = Some(at);
        assert_eq!(
            health.headline(),
            "All clear, last checked 2026-09-24T10:00:00.000Z."
        );
    }

    /// A broken Baseline is as much "records tampered" as a broken Event Log:
    /// the precedence names either chain.
    #[test]
    fn either_broken_chain_reads_records_tampered() {
        let mut health = Health::running();
        health.baseline = broken();
        assert!(health.records_tampered());
        assert_eq!(health.headline(), "Records tampered.");
    }

    /// A rebuilt state file is a note, never a state: nothing about the
    /// machine is wrong and the next Full Scan puts it back.
    #[test]
    fn a_rebuilt_state_file_is_a_note_under_an_all_clear_headline() {
        let mut health = Health::running();
        health.state_file = StateFileHealth::Rebuilt;
        assert!(health.headline().starts_with("All clear"));
        assert!(
            health
                .notes()
                .iter()
                .any(|note| note.contains("did not verify")),
            "{:?}",
            health.notes()
        );
    }

    /// An unreadable settings file is a notice under the headline: the
    /// defaults are in force, and the person is told why their choice is not.
    #[test]
    fn an_unreadable_settings_file_raises_a_notice() {
        let mut health = Health::running();
        assert!(!health.notes().contains(&SETTINGS_UNREADABLE.to_string()));
        health.settings_unreadable = true;
        assert!(health.headline().starts_with("All clear"));
        assert!(
            health.notes().contains(&SETTINGS_UNREADABLE.to_string()),
            "{:?}",
            health.notes()
        );
    }

    #[test]
    fn open_findings_are_counted_under_the_headline() {
        let mut health = Health::running();
        health.open_findings = 3;
        assert!(health.notes().contains(&"3 Findings are open.".to_string()));
        health.open_findings = 1;
        assert!(health.notes().contains(&"1 Finding is open.".to_string()));
    }

    #[test]
    fn the_state_file_health_reads_back_the_spelling_it_writes() {
        for state in [
            StateFileHealth::Loaded,
            StateFileHealth::Missing,
            StateFileHealth::Rebuilt,
        ] {
            assert_eq!(StateFileHealth::parse(state.as_str()), Some(state));
        }
    }

    /// The Rule Pack notices sit below the projects that need permission and
    /// above a Scan in flight, the ignored pack first.
    #[test]
    fn the_rule_pack_notices_sit_at_their_rung_of_the_precedence() {
        let mut health = Health::running();
        health.scanning = true;
        health.projects_need_permission = 1;
        health.ignored_pack = Some(IgnoredPack {
            pack_version: 9,
            minimum_engine_version: "0.3.0".to_string(),
        });
        let since = Timestamp::parse("2026-08-01T10:00:00.000Z").expect("a moment");
        health.feed_unreachable = Some(since);
        assert_eq!(health.headline(), "1 project needs permission.");

        health.projects_need_permission = 0;
        assert_eq!(health.headline(), "Newer rules need a newer AgentSweep.");
        assert!(
            health.notes().iter().any(|note| note.contains("0.3.0")),
            "{:?}",
            health.notes()
        );

        health.ignored_pack = None;
        assert_eq!(
            health.headline(),
            "The rule feed has not been reachable for over 30 days."
        );
        assert!(
            health
                .notes()
                .iter()
                .any(|note| note.contains("2026-08-01")),
            "{:?}",
            health.notes()
        );

        health.feed_unreachable = None;
        assert_eq!(health.headline(), "Checking now.");
    }

    #[test]
    fn the_feed_is_unreachable_only_after_thirty_days() {
        let since = Timestamp::parse("2026-08-01T10:00:00.000Z").expect("a moment");
        let day = 24 * 3_600_000;
        let at = |days: i64| Timestamp::from_unix_ms(since.as_unix_ms() + days * day);
        assert_eq!(Health::feed_unreachable_at(Some(since), at(29)), None);
        assert_eq!(Health::feed_unreachable_at(Some(since), at(30)), None);
        assert_eq!(
            Health::feed_unreachable_at(Some(since), at(31)),
            Some(since)
        );
        assert_eq!(Health::feed_unreachable_at(None, at(400)), None);
    }

    /// "Rules updated <date>" is the signed release moment's date, and a
    /// Health that knows no pack says nothing about rules.
    #[test]
    fn the_rules_updated_line_reads_the_release_date() {
        let mut health = Health::running();
        assert!(health.rules_updated().is_none());
        assert!(
            !health
                .notes()
                .iter()
                .any(|note| note.starts_with("Rules updated"))
        );

        health.rule_pack = 4;
        health.rule_pack_origin = PackOrigin::Fetched;
        health.rules_released_at = "2026-10-01T09:30:00Z".to_string();
        assert_eq!(health.rules_updated().as_deref(), Some("2026-10-01"));
        assert!(
            health
                .notes()
                .contains(&"Rules updated 2026-10-01 (Rule Pack 4, fetched).".to_string()),
            "{:?}",
            health.notes()
        );
        assert!(health.headline().starts_with("All clear"));

        health.rule_feed = false;
        assert!(
            health
                .notes()
                .iter()
                .any(|note| note.starts_with("The rule feed is off")),
            "{:?}",
            health.notes()
        );
    }
}
