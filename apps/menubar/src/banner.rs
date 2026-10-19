//! The coloured banners of spec section 8.6, which replace the status
//! sentence in the popover and on the Overview for the integrity and
//! Protection states.
//!
//! [`choose`] is the one pure function that decides which banner stands, from
//! the Health and from what the app knows about the daemon beside it; the
//! banner's words and buttons in a Posture are [`Banner::shown`]. Four states
//! have a banner, in the order of the Health precedence (spec section 6.6):
//!
//! - Protection off: the registration waits for approval, is not there, or
//!   no daemon answers where nothing is registered to start one. The way
//!   back is always Login Items; no pause switch exists (spec section 10).
//! - Not watching right now: the daemon's registration is enabled and no
//!   daemon answers. Amber, with **Start it**.
//! - Records tampered: a chain broke while the key was in hand. The two
//!   buttons are "Show what changed" and "Scan again, trusting nothing".
//! - Protection state was reset: the key in the Keychain went missing. The
//!   two buttons are "Start a fresh record" and "Look at the records". It
//!   stands only while its rung holds the headline: an open Threat outranks
//!   it, and it is a note meanwhile (the owner's decision of 2026-10-14).
//!
//! The Developer Posture adds one line to two of them: the LaunchAgent label
//! to "Not watching right now", and that a reset cannot rule out tampering
//! to the key missing banner (ADR 0003). The Protection off banner carries
//! the reason in the Developer Posture.

use agentsweep_core::DAEMON_LABEL;
use agentsweep_core::health::{Health, Rung};
use agentsweep_core::settings::Posture;
use serde_json::{Value, json};

/// What the app knows about the daemon beside the Health it last sent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Daemon {
    /// A daemon answers, and the Health is its own.
    Answering,
    /// The daemon's registration is enabled and no daemon answers.
    NotRunning,
    /// Protection is off for a reason the registration or the socket gives.
    Off,
}

/// The banner that stands, when one does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Banner {
    /// "Protection is off", with the reason the Developer Posture shows.
    ProtectionOff {
        /// Why, as far as the app can tell.
        reason: String,
    },
    /// "Not watching right now".
    NotWatching,
    /// The records were changed by something else.
    ChainBroken,
    /// The key the records are checked with is missing.
    KeyMissing,
}

/// The colour a banner is shown in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tone {
    /// Something is wrong that the user has to put right.
    Red,
    /// Something is paused that one click starts again.
    Amber,
}

impl Tone {
    /// The spelling the frontend reads.
    pub fn as_str(self) -> &'static str {
        match self {
            Tone::Red => "red",
            Tone::Amber => "amber",
        }
    }
}

/// One button on a banner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Button {
    /// Opens System Settings at Login Items.
    OpenLoginItems,
    /// Asks launchd to start the registered daemon job.
    StartIt,
    /// "Start a fresh record": the acknowledge-key-missing request.
    StartFreshRecord,
    /// "Look at the records": the records request on the Event Log.
    LookAtRecords,
    /// "Show what changed": the records request from the break.
    ShowWhatChanged,
    /// "Scan again, trusting nothing": the acknowledge-chain-broken request.
    ScanAgainTrustingNothing,
}

impl Button {
    /// The words on it.
    pub fn label(self) -> &'static str {
        match self {
            Button::OpenLoginItems => "Open Login Items",
            Button::StartIt => "Start it",
            Button::StartFreshRecord => "Start a fresh record",
            Button::LookAtRecords => "Look at the records",
            Button::ShowWhatChanged => "Show what changed",
            Button::ScanAgainTrustingNothing => "Scan again, trusting nothing",
        }
    }

    /// The app command a click calls.
    pub fn command(self) -> &'static str {
        match self {
            Button::OpenLoginItems => "open_login_items",
            Button::StartIt => "start_daemon",
            Button::StartFreshRecord => "start_fresh_record",
            Button::LookAtRecords => "look_at_records",
            Button::ShowWhatChanged => "show_what_changed",
            Button::ScanAgainTrustingNothing => "scan_again_trusting_nothing",
        }
    }

    /// True for the four buttons of the integrity states, which open the
    /// Activity pane after their request.
    pub fn opens_activity(self) -> bool {
        matches!(
            self,
            Button::StartFreshRecord
                | Button::LookAtRecords
                | Button::ShowWhatChanged
                | Button::ScanAgainTrustingNothing
        )
    }
}

/// A banner as it is shown in one Posture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shown {
    /// Its colour.
    pub tone: Tone,
    /// The bold first line.
    pub title: &'static str,
    /// The plain sentences under it.
    pub body: &'static str,
    /// What the Developer Posture adds, absent in the Simple Posture.
    pub developer: Option<String>,
    /// Its buttons, the first one the primary.
    pub buttons: Vec<Button>,
}

impl Shown {
    /// The value the frontend receives.
    pub fn to_value(&self) -> Value {
        json!({
            "tone": self.tone.as_str(),
            "title": self.title,
            "body": self.body,
            "developer": self.developer,
            "buttons": self
                .buttons
                .iter()
                .map(|button| json!({ "label": button.label(), "command": button.command() }))
                .collect::<Vec<_>>(),
        })
    }
}

/// The title of the Protection off banner.
pub const PROTECTION_OFF: &str = "Protection is off";

/// The title of the banner of a registered daemon that is not running.
pub const NOT_WATCHING: &str = "Not watching right now";

/// The title of the key missing banner.
pub const KEY_MISSING: &str = "AgentSweep cannot check its own records.";

/// The title of the chain broken banner.
pub const CHAIN_BROKEN: &str = "AgentSweep's records were changed by something else.";

/// What the Developer Posture adds to the key missing banner (ADR 0003).
pub const RESET_CANNOT_RULE_OUT_TAMPERING: &str = "A reset cannot rule out tampering: no key in \
     hand can check the records written before it.";

/// Which banner stands for this Health and this daemon, if any.
pub fn choose(health: &Health, daemon: &Daemon) -> Option<Banner> {
    let off = || Banner::ProtectionOff {
        reason: health.protection.reason().to_string(),
    };
    match daemon {
        Daemon::NotRunning => Some(Banner::NotWatching),
        Daemon::Off => Some(off()),
        Daemon::Answering => match health.rung() {
            Rung::ProtectionOff => Some(off()),
            Rung::RecordsTampered => Some(Banner::ChainBroken),
            Rung::StateReset => Some(Banner::KeyMissing),
            _ => None,
        },
    }
}

impl Banner {
    /// The banner's words and buttons in a Posture.
    pub fn shown(&self, posture: Posture) -> Shown {
        let developer = posture == Posture::Developer;
        let only = |line: String| (developer && !line.is_empty()).then_some(line);
        match self {
            Banner::ProtectionOff { reason } => Shown {
                tone: Tone::Red,
                title: PROTECTION_OFF,
                body: "Nothing is checking your agents' setup right now. Allow AgentSweep in \
                       Login Items to turn protection back on.",
                developer: only(reason.clone()),
                buttons: vec![Button::OpenLoginItems],
            },
            Banner::NotWatching => Shown {
                tone: Tone::Amber,
                title: NOT_WATCHING,
                body: "The background helper is not running, so new add-ons are not being \
                       checked.",
                developer: only(format!(
                    "The LaunchAgent {DAEMON_LABEL} is registered but not running."
                )),
                buttons: vec![Button::StartIt],
            },
            Banner::KeyMissing => Shown {
                tone: Tone::Red,
                title: KEY_MISSING,
                body: "The key it keeps in your Keychain is missing, for example after moving \
                       to a new Mac. Your quarantine and trust decisions are still there but \
                       unverified.",
                developer: only(RESET_CANNOT_RULE_OUT_TAMPERING.to_string()),
                buttons: vec![Button::StartFreshRecord, Button::LookAtRecords],
            },
            Banner::ChainBroken => Shown {
                tone: Tone::Red,
                title: CHAIN_BROKEN,
                body: "One of its records no longer matches. Something on this Mac may have \
                       tampered with AgentSweep. Decisions made after that point are set aside, \
                       and nothing is stopped automatically until you answer.",
                developer: None,
                buttons: vec![Button::ShowWhatChanged, Button::ScanAgainTrustingNothing],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::chain::{BreakReason, ChainState};

    fn broken() -> ChainState {
        ChainState::Broken {
            sequence: 7,
            reason: BreakReason::MacFailed,
        }
    }

    /// Each of the four states has its banner, its colour and its buttons.
    #[test]
    fn each_of_the_four_states_has_its_banner_and_buttons() {
        let off =
            choose(&Health::unreachable("no daemon answered"), &Daemon::Off).expect("a banner");
        let shown = off.shown(Posture::Simple);
        assert_eq!(shown.title, PROTECTION_OFF);
        assert_eq!(shown.tone, Tone::Red);
        assert_eq!(shown.buttons, vec![Button::OpenLoginItems]);

        let silent = choose(&Health::unreachable("gone"), &Daemon::NotRunning).expect("a banner");
        assert_eq!(silent, Banner::NotWatching);
        let shown = silent.shown(Posture::Simple);
        assert_eq!(shown.title, NOT_WATCHING);
        assert_eq!(shown.tone, Tone::Amber);
        assert_eq!(shown.buttons, vec![Button::StartIt]);

        let tampered = Health {
            events: broken(),
            ..Health::running()
        };
        let shown = choose(&tampered, &Daemon::Answering)
            .expect("a banner")
            .shown(Posture::Simple);
        assert_eq!(shown.title, CHAIN_BROKEN);
        assert_eq!(shown.tone, Tone::Red);
        assert_eq!(
            shown.buttons,
            vec![Button::ShowWhatChanged, Button::ScanAgainTrustingNothing]
        );

        let reset = Health {
            baseline: ChainState::KeyMissing,
            ..Health::running()
        };
        let shown = choose(&reset, &Daemon::Answering)
            .expect("a banner")
            .shown(Posture::Simple);
        assert_eq!(shown.title, KEY_MISSING);
        assert_eq!(shown.tone, Tone::Red);
        assert_eq!(
            shown.buttons,
            vec![Button::StartFreshRecord, Button::LookAtRecords]
        );
    }

    /// Records tampered outranks a reset, Protection off outranks both, and
    /// every other rung has no banner.
    #[test]
    fn the_banner_follows_the_health_precedence() {
        let both = Health {
            events: ChainState::KeyMissing,
            baseline: broken(),
            ..Health::running()
        };
        assert_eq!(choose(&both, &Daemon::Answering), Some(Banner::ChainBroken));
        assert!(matches!(
            choose(&Health::unreachable("x"), &Daemon::Answering),
            Some(Banner::ProtectionOff { .. })
        ));
        for health in [
            Health::running(),
            Health {
                open_threats: 2,
                ..Health::running()
            },
            Health {
                scanning: true,
                ..Health::running()
            },
            Health {
                projects_need_permission: 1,
                ..Health::running()
            },
        ] {
            assert_eq!(choose(&health, &Daemon::Answering), None, "{health:?}");
        }
    }

    /// An open Threat outranks the reset, which is then a note and no banner.
    #[test]
    fn an_open_threat_outranks_the_reset_banner() {
        let health = Health {
            events: ChainState::KeyMissing,
            open_threats: 1,
            ..Health::running()
        };
        assert_eq!(choose(&health, &Daemon::Answering), None);
    }

    /// The LaunchAgent label, the tampering sentence and the reason are the
    /// Developer Posture's alone.
    #[test]
    fn the_developer_additions_appear_only_in_developer() {
        let banners = [
            Banner::ProtectionOff {
                reason: "no daemon answered".to_string(),
            },
            Banner::NotWatching,
            Banner::KeyMissing,
            Banner::ChainBroken,
        ];
        for banner in &banners {
            assert_eq!(banner.shown(Posture::Simple).developer, None, "{banner:?}");
            let simple = banner.shown(Posture::Simple).to_value().to_string();
            assert!(!simple.contains(DAEMON_LABEL), "{simple}");
            assert!(!simple.contains("rule out tampering"), "{simple}");
        }
        let developer = Banner::NotWatching.shown(Posture::Developer).developer;
        assert!(
            developer
                .as_deref()
                .is_some_and(|line| line.contains(DAEMON_LABEL)),
            "{developer:?}"
        );
        assert_eq!(
            Banner::KeyMissing
                .shown(Posture::Developer)
                .developer
                .as_deref(),
            Some(RESET_CANNOT_RULE_OUT_TAMPERING)
        );
        assert_eq!(
            banners[0].shown(Posture::Developer).developer.as_deref(),
            Some("no daemon answered")
        );
    }

    #[test]
    fn the_integrity_buttons_open_the_activity_pane_and_the_others_do_not() {
        assert!(!Button::OpenLoginItems.opens_activity());
        assert!(!Button::StartIt.opens_activity());
        for button in [
            Button::StartFreshRecord,
            Button::LookAtRecords,
            Button::ShowWhatChanged,
            Button::ScanAgainTrustingNothing,
        ] {
            assert!(button.opens_activity(), "{button:?}");
        }
    }

    #[test]
    fn no_banner_carries_an_em_dash() {
        for banner in [
            Banner::ProtectionOff {
                reason: String::new(),
            },
            Banner::NotWatching,
            Banner::KeyMissing,
            Banner::ChainBroken,
        ] {
            for posture in [Posture::Simple, Posture::Developer] {
                let value = banner.shown(posture).to_value().to_string();
                assert!(!value.contains('\u{2014}'), "{value}");
            }
        }
    }
}
