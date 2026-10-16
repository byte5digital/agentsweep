//! Health: every state AgentSweep can be in, in one struct.
//!
//! Spec section 6.6 asks for one `Health` struct with every state as a field
//! and one precedence that decides which of them a person is shown. The
//! precedence lives here rather than in the daemon, the app or the command
//! line interface, so the three of them say the same sentence about the same
//! machine.
//!
//! The states of that list answered so far are Protection off, the two chain
//! states, the projects that need permission, the Gate lines each Full Scan's
//! registration check leaves, a Scan in flight, the open Findings that need
//! the user's decision, the two Rule Pack notices and all clear. The Gate
//! lines are the ones of spec section 6.6 that come in a pair, a sentence for
//! the Simple Posture and one for the Developer Posture.
//!
//! Beside the states, Health says which Rule Pack is in force and when it was
//! released, which is the "Rules updated <date>" line: the date is read off the
//! pack's signed manifest, never off the clock of the machine that fetched it.

use std::fmt;

use crate::chain::ChainState;
use crate::envelope::Timestamp;
use crate::finding::Category;
use crate::pack::released_day;
use crate::packs::PackOrigin;
use crate::settings::Posture;
use crate::spend::CapNotice;
use crate::state::{IgnoredPack, State};

/// The note a reset nobody answered leaves while an open Threat holds the
/// headline: the rung stays until "Start a fresh record" is pressed, ranked
/// below every Threat rung (the owner's decision of 2026-10-14).
pub const STATE_RESET_NOTE: &str = "Protection state was reset. AgentSweep started a fresh record \
     because the key it keeps in your Keychain was missing.";

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

/// Why the Gate cannot stand in one Agent, as the registration check of a
/// Full Scan found it (spec sections 6.6 and 7.6).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GateTrouble {
    /// The daemon could not write the Gate's entries: the file kept changing,
    /// could not be written, or does not parse and is never written over.
    RegistrationFailed,
    /// Managed policy drops the user's hooks, so nothing is written.
    ManagedPolicy,
    /// The user switched the Agent's hooks off in their own settings, which
    /// AgentSweep never writes back (spec section 7.6 as amended on
    /// 2026-10-14).
    SwitchedOffByUser,
}

impl GateTrouble {
    /// The spelling the wire carries.
    pub fn as_str(self) -> &'static str {
        match self {
            GateTrouble::RegistrationFailed => "registration-failed",
            GateTrouble::ManagedPolicy => "managed-policy",
            GateTrouble::SwitchedOffByUser => "switched-off-by-user",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<GateTrouble> {
        match text {
            "registration-failed" => Some(GateTrouble::RegistrationFailed),
            "managed-policy" => Some(GateTrouble::ManagedPolicy),
            "switched-off-by-user" => Some(GateTrouble::SwitchedOffByUser),
            _ => None,
        }
    }
}

/// One Gate line: an Agent and why the Gate cannot stand there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateLine {
    /// The Agent, by adapter id.
    pub agent: String,
    /// The Agent's name as a person reads it, such as "Claude Code".
    pub name: String,
    /// Why the Gate cannot stand there.
    pub trouble: GateTrouble,
}

impl GateLine {
    /// The line in one Posture: the wording pairs of spec section 6.6.
    pub fn wording(&self, posture: Posture) -> String {
        let name = &self.name;
        match (self.trouble, posture) {
            (GateTrouble::RegistrationFailed, Posture::Simple) => {
                format!("The check could not be added to {name}.")
            }
            (GateTrouble::RegistrationFailed, Posture::Developer) => {
                format!("Gate registration failed: {name}.")
            }
            (GateTrouble::ManagedPolicy, Posture::Simple) => {
                "Your organisation's policy blocks the check.".to_string()
            }
            (GateTrouble::ManagedPolicy, Posture::Developer) => {
                "Gate blocked by managed policy.".to_string()
            }
            (GateTrouble::SwitchedOffByUser, Posture::Simple) => format!(
                "Hooks are switched off in your {name} settings, so the check cannot run there."
            ),
            (GateTrouble::SwitchedOffByUser, Posture::Developer) => {
                format!("Gate off: hooks disabled in the {name} user settings.")
            }
        }
    }
}

/// The rungs of the Health precedence (spec section 6.6), the worst first:
/// a rung compares below every rung it outranks.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Rung {
    /// Protection is off.
    ProtectionOff,
    /// Either chain is broken while the key is in hand.
    RecordsTampered,
    /// A chain is well formed but no key can vouch for it.
    StateReset,
    /// Registered projects the operating system will not let AgentSweep read.
    NeedsPermission,
    /// The Gate cannot stand in a detected Agent: its registration failed,
    /// managed policy blocks it, or the user switched hooks off there; or a
    /// project switched the check off for itself.
    GateLine,
    /// A Scan is running.
    CheckingNow,
    /// Open Threat or Exposure Findings wait for the user's decision.
    NeedsDecision,
    /// A newer Rule Pack was ignored because it needs a newer AgentSweep.
    IgnoredPack,
    /// The Rule Feed has not answered for over thirty days.
    FeedUnreachable,
    /// Nothing asks anything of the user.
    AllClear,
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
    /// The Gate lines the last Full Scan's registration check left, one per
    /// detected Agent where the Gate cannot stand, worst first. Empty when
    /// every check passed.
    pub gate_lines: Vec<GateLine>,
    /// How many pooled projects switch the check off for at least one Agent
    /// with their own settings: "Gate off in this project" (spec section
    /// 7.6). A state of those projects, never a Finding.
    pub projects_gate_off: usize,
    /// Whether the Gate switch is on (spec sections 7 and 8.10). Off means the
    /// Gate's entries were taken away and nothing registers them again, so a
    /// client says "off" rather than implying the Gate stands. Not a rung.
    pub gate_hooks: bool,
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
    /// How many Threat Findings are open right now.
    pub open_threats: usize,
    /// How many Exposure Findings are open right now.
    pub open_exposures: usize,
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
    /// The cap notice: a cap of AI Judgement held Items back and this many
    /// are waiting for the next Scan (spec section 4.4). Absent while nothing
    /// waits. Not a rung: the Developer Posture shows it as a notice and the
    /// Simple one as a line in Settings.
    pub judgement_cap: Option<CapNotice>,
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
            gate_lines: Vec::new(),
            projects_gate_off: 0,
            gate_hooks: true,
            state_file: StateFileHealth::Loaded,
            settings_unreadable: false,
            scanning: false,
            last_full_scan: None,
            items: 0,
            open_threats: 0,
            open_exposures: 0,
            rule_pack: 0,
            rule_pack_origin: PackOrigin::Bundled,
            rules_released_at: String::new(),
            rule_feed: true,
            ignored_pack: None,
            feed_unreachable: None,
            judgement_cap: None,
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
    /// the "protection state was reset" state. A chain that started again
    /// under a new key stays in it until the user answers "Start a fresh
    /// record".
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

    /// Takes the counts of open Threat and Exposure Findings from the state.
    pub fn count_open(&mut self, state: &State) {
        self.open_threats = state.open_count_of(Category::Threat);
        self.open_exposures = state.open_count_of(Category::Exposure);
    }

    /// How many Findings are open right now, Threat and Exposure together.
    pub fn open_findings(&self) -> usize {
        self.open_threats + self.open_exposures
    }

    /// The rung of the precedence of spec section 6.6 this Health stands on.
    ///
    /// The order is Protection off, records tampered, protection state reset
    /// (unless a Threat Finding is open: the reset ranks below every Threat
    /// rung and is a note meanwhile), projects that need permission, then the
    /// Gate lines, then a Scan in flight, then the open Findings that need the user's
    /// decision, then the Rule Pack notices (a newer pack ignored because it
    /// needs a newer AgentSweep, the Rule Feed unreachable for over thirty
    /// days), then all clear with the last-checked time.
    pub fn rung(&self) -> Rung {
        if self.protection.is_off() {
            Rung::ProtectionOff
        } else if self.records_tampered() {
            Rung::RecordsTampered
        } else if self.state_was_reset() && self.open_threats == 0 {
            Rung::StateReset
        } else if self.projects_need_permission > 0 {
            Rung::NeedsPermission
        } else if !self.gate_lines.is_empty() || self.projects_gate_off > 0 {
            Rung::GateLine
        } else if self.scanning {
            Rung::CheckingNow
        } else if self.open_findings() > 0 {
            Rung::NeedsDecision
        } else if self.ignored_pack.is_some() {
            Rung::IgnoredPack
        } else if self.feed_unreachable.is_some() {
            Rung::FeedUnreachable
        } else {
            Rung::AllClear
        }
    }

    /// The one sentence a person is shown in the Simple Posture, by the
    /// precedence of spec section 6.6 (see [`Health::rung`]).
    pub fn headline(&self) -> String {
        self.headline_in(Posture::Simple)
    }

    /// The one sentence in a Posture. Only the Gate lines have a sentence of
    /// their own in each Posture; every other rung reads the same in both.
    /// The command line interface is a developer surface and prints the
    /// Developer one (the owner's decision of 2026-10-14).
    pub fn headline_in(&self, posture: Posture) -> String {
        match self.rung() {
            Rung::GateLine => self
                .gate_sentences(posture)
                .into_iter()
                .next()
                .unwrap_or_default(),
            Rung::ProtectionOff => "Protection is off.".to_string(),
            Rung::RecordsTampered => "Records tampered.".to_string(),
            Rung::StateReset => "Protection state was reset.".to_string(),
            Rung::NeedsPermission => match self.projects_need_permission {
                1 => "1 project needs permission.".to_string(),
                many => format!("{many} projects need permission."),
            },
            Rung::CheckingNow => "Checking now.".to_string(),
            Rung::NeedsDecision => self.needs_decision(),
            Rung::IgnoredPack => "Newer rules need a newer AgentSweep.".to_string(),
            Rung::FeedUnreachable => {
                "The rule feed has not been reachable for over 30 days.".to_string()
            }
            Rung::AllClear => match self.last_full_scan {
                Some(at) => format!("All clear, last checked {at}."),
                None => "All clear, nothing checked yet.".to_string(),
            },
        }
    }

    /// Every sentence of the Gate rung in a Posture, in the order of spec
    /// section 6.6: the projects that switched the check off first, then the
    /// Gate lines of the registration check.
    fn gate_sentences(&self, posture: Posture) -> Vec<String> {
        let projects = match (self.projects_gate_off, posture) {
            (0, _) => None,
            (1, Posture::Simple) => Some("1 project switched off the check.".to_string()),
            (many, Posture::Simple) => Some(format!("{many} projects switched off the check.")),
            (1, Posture::Developer) => Some("Gate off in 1 project.".to_string()),
            (many, Posture::Developer) => Some(format!("Gate off in {many} projects.")),
        };
        projects
            .into_iter()
            .chain(self.gate_lines.iter().map(|line| line.wording(posture)))
            .collect()
    }

    /// "N things need your decision", with the open Threat and Exposure
    /// Findings counted separately.
    fn needs_decision(&self) -> String {
        let total = match self.open_findings() {
            1 => "1 thing needs your decision".to_string(),
            many => format!("{many} things need your decision"),
        };
        let counted = |n: usize, one: &str| match n {
            0 => None,
            1 => Some(format!("1 {one}")),
            many => Some(format!("{many} {one}s")),
        };
        let parts: Vec<String> = [
            counted(self.open_threats, "Threat"),
            counted(self.open_exposures, "Exposure"),
        ]
        .into_iter()
        .flatten()
        .collect();
        format!("{total}: {}.", parts.join(" and "))
    }

    /// What is said under the headline in the Simple Posture: the reason
    /// Protection is off, the Gate lines the headline does not say, the note a
    /// rebuilt state file leaves, the notice an unreadable settings file
    /// raises, and how many Findings are open.
    pub fn notes(&self) -> Vec<String> {
        self.notes_in(Posture::Simple)
    }

    /// The same, in a Posture.
    pub fn notes_in(&self, posture: Posture) -> Vec<String> {
        let mut notes = Vec::new();
        if let Protection::Off(reason) = &self.protection
            && !reason.is_empty()
        {
            notes.push(reason.clone());
        }
        // Every Gate line is said once: the first is the headline while the
        // Gate rung holds it, and the rest, or all of them under a worse
        // rung, are notes.
        let headline = self.headline_in(posture);
        for line in self.gate_sentences(posture) {
            if line != headline && !notes.contains(&line) {
                notes.push(line);
            }
        }
        let rebuilt = self.state_file.note();
        if !rebuilt.is_empty() {
            notes.push(rebuilt.to_string());
        }
        if self.settings_unreadable {
            notes.push(SETTINGS_UNREADABLE.to_string());
        }
        if self.state_was_reset() && self.rung() > Rung::StateReset {
            notes.push(STATE_RESET_NOTE.to_string());
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
        // The count of open Findings is a note only while a rung above it
        // takes the headline; otherwise the headline says it already.
        match (self.rung() < Rung::NeedsDecision, self.open_findings()) {
            (false, _) | (_, 0) => {}
            (true, 1) => notes.push("1 Finding is open.".to_string()),
            (true, many) => notes.push(format!("{many} Findings are open.")),
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

    /// A reset nobody answered stays, ranked below every Threat rung, so an
    /// open Threat is never hidden behind it; while a Threat holds the
    /// headline the reset is a note (the owner's decision of 2026-10-14).
    #[test]
    fn a_reset_nobody_answered_ranks_below_every_open_threat() {
        let mut health = Health::running();
        health.baseline = ChainState::KeyMissing;
        assert_eq!(health.rung(), Rung::StateReset);
        assert!(!health.notes().contains(&STATE_RESET_NOTE.to_string()));

        health.open_exposures = 1;
        assert_eq!(health.rung(), Rung::StateReset, "an Exposure is no Threat");

        health.open_threats = 1;
        assert_eq!(health.rung(), Rung::NeedsDecision);
        assert!(
            health.notes().contains(&STATE_RESET_NOTE.to_string()),
            "{:?}",
            health.notes()
        );

        health.events = broken();
        assert_eq!(health.rung(), Rung::RecordsTampered);
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

    /// Open Findings take the headline when nothing above them does, with
    /// Threat and Exposure counted separately in the sentence; with none open
    /// Health is all clear again.
    #[test]
    fn open_findings_are_the_things_that_need_your_decision() {
        let mut health = Health::running();
        health.open_threats = 1;
        health.open_exposures = 1;
        assert_eq!(health.rung(), Rung::NeedsDecision);
        assert_eq!(
            health.headline(),
            "2 things need your decision: 1 Threat and 1 Exposure."
        );
        assert!(
            !health.notes().iter().any(|note| note.contains("open")),
            "the headline says it already: {:?}",
            health.notes()
        );

        health.open_threats = 3;
        health.open_exposures = 0;
        assert_eq!(health.headline(), "3 things need your decision: 3 Threats.");
        health.open_threats = 0;
        health.open_exposures = 1;
        assert_eq!(
            health.headline(),
            "1 thing needs your decision: 1 Exposure."
        );
        health.open_threats = 1;
        health.open_exposures = 2;
        assert_eq!(
            health.headline(),
            "3 things need your decision: 1 Threat and 2 Exposures."
        );

        health.open_threats = 0;
        health.open_exposures = 0;
        assert!(health.headline().starts_with("All clear"));
    }

    /// Protection off, records tampered and a Scan in flight outrank the
    /// open Findings, which then stay a note under the headline; the Rule
    /// Pack notices sit below them.
    #[test]
    fn open_findings_sit_between_checking_now_and_the_rule_pack_notices() {
        let mut health = Health::running();
        health.open_threats = 2;
        health.open_exposures = 1;
        health.ignored_pack = Some(IgnoredPack {
            pack_version: 9,
            minimum_engine_version: "0.3.0".to_string(),
        });
        health.feed_unreachable =
            Some(Timestamp::parse("2026-08-01T10:00:00.000Z").expect("a moment"));
        assert!(health.headline().starts_with("3 things need your decision"));

        health.scanning = true;
        assert_eq!(health.headline(), "Checking now.");
        assert!(health.notes().contains(&"3 Findings are open.".to_string()));

        health.events = broken();
        assert_eq!(health.headline(), "Records tampered.");
        assert!(health.notes().contains(&"3 Findings are open.".to_string()));

        health.protection = Protection::Off("not registered".to_string());
        assert_eq!(health.headline(), "Protection is off.");

        health.open_threats = 1;
        health.open_exposures = 0;
        health.protection = Protection::On;
        health.events = ChainState::Intact;
        health.scanning = false;
        assert_eq!(health.headline(), "1 thing needs your decision: 1 Threat.");
    }

    fn line(agent: &str, name: &str, trouble: GateTrouble) -> GateLine {
        GateLine {
            agent: agent.to_string(),
            name: name.to_string(),
            trouble,
        }
    }

    /// Spec section 6.6, rung 5: the Gate lines sit below the projects that
    /// need permission and above a Scan in flight and the open Findings.
    #[test]
    fn the_gate_lines_sit_between_permission_and_checking_now() {
        let mut health = Health::running();
        health.gate_lines = vec![line(
            "claude-code",
            "Claude Code",
            GateTrouble::RegistrationFailed,
        )];
        health.scanning = true;
        health.open_threats = 1;
        health.projects_need_permission = 1;
        assert_eq!(health.rung(), Rung::NeedsPermission);
        assert!(
            health
                .notes()
                .contains(&"The check could not be added to Claude Code.".to_string()),
            "{:?}",
            health.notes()
        );

        health.projects_need_permission = 0;
        assert_eq!(health.rung(), Rung::GateLine);
        assert_eq!(
            health.headline(),
            "The check could not be added to Claude Code."
        );
        assert_eq!(
            health.headline_in(Posture::Developer),
            "Gate registration failed: Claude Code."
        );
        assert!(health.notes().contains(&"1 Finding is open.".to_string()));

        health.gate_lines.clear();
        assert_eq!(health.headline(), "Checking now.");
    }

    /// Spec sections 6.6 and 7.6: the projects that switched the check off
    /// are counted on the Gate rung, in the pair of sentences of rung 5, and
    /// come first among the Gate sentences.
    #[test]
    fn the_projects_that_switched_off_the_check_are_counted_on_the_gate_rung() {
        let mut health = Health::running();
        health.projects_gate_off = 1;
        health.open_threats = 1;
        assert_eq!(health.rung(), Rung::GateLine);
        assert_eq!(health.headline(), "1 project switched off the check.");
        assert_eq!(
            health.headline_in(Posture::Developer),
            "Gate off in 1 project."
        );

        health.projects_gate_off = 2;
        assert_eq!(health.headline(), "2 projects switched off the check.");
        assert_eq!(
            health.headline_in(Posture::Developer),
            "Gate off in 2 projects."
        );

        // Beside a Gate line, both are said once.
        health.gate_lines = vec![line(
            "claude-code",
            "Claude Code",
            GateTrouble::RegistrationFailed,
        )];
        assert_eq!(health.headline(), "2 projects switched off the check.");
        assert!(
            health
                .notes()
                .contains(&"The check could not be added to Claude Code.".to_string())
        );

        // Under a worse rung the count is a note.
        health.projects_need_permission = 1;
        assert!(
            health
                .notes_in(Posture::Developer)
                .contains(&"Gate off in 2 projects.".to_string())
        );

        health.projects_need_permission = 0;
        health.gate_lines.clear();
        health.projects_gate_off = 0;
        assert_eq!(health.rung(), Rung::NeedsDecision);
    }

    /// Every line has its pair of sentences, and a second line is a note.
    #[test]
    fn each_gate_line_reads_in_both_postures_and_the_second_is_a_note() {
        let mut health = Health::running();
        health.gate_lines = vec![
            line("claude-code", "Claude Code", GateTrouble::ManagedPolicy),
            line("codex", "Codex", GateTrouble::SwitchedOffByUser),
        ];
        assert_eq!(
            health.headline(),
            "Your organisation's policy blocks the check."
        );
        assert_eq!(
            health.headline_in(Posture::Developer),
            "Gate blocked by managed policy."
        );
        assert!(
            health.notes().contains(
                &"Hooks are switched off in your Codex settings, so the check cannot run there."
                    .to_string()
            ),
            "{:?}",
            health.notes()
        );
        assert!(
            health
                .notes_in(Posture::Developer)
                .contains(&"Gate off: hooks disabled in the Codex user settings.".to_string()),
            "{:?}",
            health.notes_in(Posture::Developer)
        );
        assert!(
            !health
                .notes()
                .contains(&"Your organisation's policy blocks the check.".to_string()),
            "the headline is not said twice"
        );
        for trouble in [
            GateTrouble::RegistrationFailed,
            GateTrouble::ManagedPolicy,
            GateTrouble::SwitchedOffByUser,
        ] {
            assert_eq!(GateTrouble::parse(trouble.as_str()), Some(trouble));
        }
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

    /// The Rule Pack notices sit below the projects that need permission, a
    /// Scan in flight and the open Findings, the ignored pack first.
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
        assert_eq!(health.headline(), "Checking now.");

        health.scanning = false;
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
        assert!(health.headline().starts_with("All clear"));
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
