//! What the popover shows (spec section 8.1): the status orb, one Health
//! sentence by precedence, the last check time, and for the integrity and
//! Protection states the coloured banner that replaces the sentence
//! ([`crate::banner`]). Nothing else: no Finding list, no Finding action and
//! no progress count in either Posture; while a Scan runs the sentence is
//! "Checking now." and nothing more.
//!
//! The sentence is [`Health::headline`], the one the command line interface
//! prints, so the app and the terminal say the same thing about the same
//! machine.

use agentsweep_core::health::{Health, Rung};
use agentsweep_core::settings::Posture;
use serde_json::{Value, json};

use crate::banner::{self, Banner, Daemon};
use crate::supervision::Stale;

/// The state the orb and the menu bar glyph show.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Orb {
    /// Nothing asks anything of the user: a tick.
    Clear,
    /// Something does: an exclamation mark.
    Attention,
    /// Protection is off: a dash.
    Off,
    /// The app and the daemon are of different versions for a moment: a
    /// dash, and a sentence that says it is passing.
    Updating,
}

impl Orb {
    /// The spelling the frontend reads.
    pub fn as_str(self) -> &'static str {
        match self {
            Orb::Clear => "clear",
            Orb::Attention => "attention",
            Orb::Off => "off",
            Orb::Updating => "updating",
        }
    }
}

/// Why Protection is off, as far as the app can tell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Off {
    /// The daemon's registration waits for the user's approval in Login Items.
    NeedsApproval,
    /// The daemon is not registered at all.
    NotRegistered,
    /// No daemon answered on the socket.
    Unreachable(String),
    /// A daemon answered and refused the app.
    Refused(String),
}

impl Off {
    /// The reason, as the Developer Posture will show it. Placeholder wording.
    pub fn reason(&self) -> String {
        match self {
            Off::NeedsApproval => {
                "the background item waits for approval in Login Items".to_string()
            }
            Off::NotRegistered => "the background item is not registered".to_string(),
            Off::Unreachable(why) | Off::Refused(why) => why.clone(),
        }
    }
}

/// Everything the popover renders, in one value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct View {
    /// The orb, and the menu bar glyph with it.
    pub orb: Orb,
    /// The one sentence.
    pub sentence: String,
    /// When the last Full Scan finished, RFC 3339, absent before the first.
    pub last_check: Option<String>,
    /// True when no daemon is there to answer: Protection is off, or the
    /// registered daemon is not running. The popover then offers nothing but
    /// its banner and Quit (spec section 6.2).
    pub protection_off: bool,
    /// True when the popover offers the button that opens Login Items.
    pub login_items: bool,
    /// A line under the sentence for whoever wants the reason.
    pub detail: String,
    /// The banner that replaces the sentence, when one stands.
    pub banner: Option<Banner>,
}

impl View {
    /// The view of a daemon that answered with this Health.
    pub fn of(health: &Health) -> View {
        if health.protection.is_off() {
            return View::off(&Off::Unreachable(health.protection.reason().to_string()));
        }
        let asks_something = health.records_tampered()
            || health.state_was_reset()
            || health.projects_need_permission > 0
            || !health.gate_lines.is_empty()
            || health.ignored_pack.is_some()
            || health.feed_unreachable.is_some()
            || health.open_findings() > 0;
        View {
            banner: banner::choose(health, &Daemon::Answering),
            orb: match asks_something {
                true => Orb::Attention,
                false => Orb::Clear,
            },
            sentence: health.headline(),
            last_check: health.last_full_scan.map(|at| at.to_string()),
            protection_off: false,
            login_items: false,
            // The sentence counts the open Findings once they take it; a rung
            // above them leaves the count to this line.
            detail: match (health.rung(), health.open_findings()) {
                (Rung::NeedsDecision, _) | (_, 0) => String::new(),
                (_, 1) => "1 Finding is open.".to_string(),
                (_, many) => format!("{many} Findings are open."),
            },
        }
    }

    /// The view when Protection is off. The sentence is the one Health gives
    /// Protection off, and the way back is always Login Items: approval
    /// missing, approval revoked or a daemon that does not answer (spec
    /// section 8.6).
    pub fn off(why: &Off) -> View {
        let health = Health::unreachable(&why.reason());
        View {
            orb: Orb::Off,
            sentence: health.headline(),
            last_check: None,
            protection_off: true,
            login_items: true,
            detail: why.reason(),
            banner: banner::choose(&health, &Daemon::Off),
        }
    }

    /// The view when the daemon's registration is enabled and no daemon
    /// answers: the amber "Not watching right now" with **Start it**, never
    /// Login Items, since nothing waits for approval there (spec section
    /// 8.6). The Health sentence is still Protection off, which the tooltip
    /// and the command line interface say.
    pub fn not_watching(reason: &str) -> View {
        let health = Health::unreachable(reason);
        View {
            orb: Orb::Off,
            sentence: health.headline(),
            last_check: None,
            protection_off: true,
            login_items: false,
            detail: reason.to_string(),
            banner: banner::choose(&health, &Daemon::NotRunning),
        }
    }

    /// The view while the app and the daemon are of different versions: a
    /// passing state, never Protection off (spec section 6.6).
    pub fn updating() -> View {
        View {
            orb: Orb::Updating,
            sentence: "AgentSweep is updating.".to_string(),
            last_check: None,
            protection_off: false,
            login_items: false,
            detail: String::new(),
            banner: None,
        }
    }

    /// The view after the app registered a stale job again: what it did, and
    /// why, while the daemon it started comes up. A passing state like an
    /// update, so the orb shows a dash and no Login Items button.
    pub fn registered_again(stale: &Stale) -> View {
        View {
            orb: Orb::Updating,
            sentence: "AgentSweep registered its background item again.".to_string(),
            last_check: None,
            protection_off: false,
            login_items: false,
            detail: match stale {
                Stale::Version { registered } => {
                    format!("The background item was registered by version {registered}.")
                }
                Stale::CannotSpawn => {
                    "launchd could not start the background item as registered.".to_string()
                }
            },
            banner: None,
        }
    }

    /// The view before anything is known: Protection off, because silence is
    /// never an all-clear.
    pub fn unknown() -> View {
        View::off(&Off::Unreachable("no daemon answered yet".to_string()))
    }

    /// The value the frontend receives in a Posture. A banner replaces the
    /// sentence and the line under it, so neither is sent beside one.
    pub fn to_value(&self, posture: Posture) -> Value {
        let banner = self.banner.as_ref().map(|banner| banner.shown(posture));
        let replaced = banner.is_some();
        json!({
            "orb": self.orb.as_str(),
            "sentence": (!replaced).then_some(self.sentence.as_str()),
            "lastCheck": self.last_check,
            "protectionOff": self.protection_off,
            "loginItems": self.login_items,
            "detail": match replaced {
                true => "",
                false => self.detail.as_str(),
            },
            "banner": banner.map(|banner| banner.to_value()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::chain::{BreakReason, ChainState};
    use agentsweep_core::envelope::Timestamp;

    use crate::glyph::Mark;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a moment")
    }

    #[test]
    fn a_quiet_machine_shows_a_tick_all_clear_and_the_last_check() {
        let health = Health {
            last_full_scan: Some(at("2026-09-25T08:00:00.000Z")),
            ..Health::running()
        };
        let view = View::of(&health);
        assert_eq!(view.orb, Orb::Clear);
        assert_eq!(view.sentence, health.headline());
        assert!(view.sentence.starts_with("All clear"), "{}", view.sentence);
        assert_eq!(view.last_check.as_deref(), Some("2026-09-25T08:00:00.000Z"));
        assert!(!view.protection_off);
        assert!(!view.login_items);
    }

    /// The popover says what the command line interface says: the sentence is
    /// the Health precedence, rung by rung.
    #[test]
    fn the_sentence_follows_the_health_precedence() {
        let mut health = Health::running();
        health.projects_need_permission = 2;
        health.events = ChainState::Broken {
            sequence: 1,
            reason: BreakReason::MacFailed,
        };
        let view = View::of(&health);
        assert_eq!(view.orb, Orb::Attention);
        assert_eq!(view.sentence, "Records tampered.");

        health.events = ChainState::Intact;
        assert_eq!(View::of(&health).sentence, "2 projects need permission.");

        health.projects_need_permission = 0;
        health.scanning = true;
        let checking = View::of(&health);
        assert_eq!(checking.sentence, "Checking now.");
        assert_eq!(checking.orb, Orb::Clear);
    }

    /// Two open Findings and nothing else wrong: the sentence is the rung
    /// that asks for the user's decision and the menu bar glyph is the
    /// exclamation mark; with none open it is all clear and a tick.
    #[test]
    fn open_findings_are_things_that_need_your_decision_under_an_exclamation_mark() {
        let health = Health {
            open_threats: 1,
            open_exposures: 1,
            ..Health::running()
        };
        let view = View::of(&health);
        assert_eq!(
            view.sentence,
            "2 things need your decision: 1 Threat and 1 Exposure."
        );
        assert_eq!(view.orb, Orb::Attention);
        assert_eq!(Mark::of(view.orb), Mark::Exclamation);
        assert_eq!(view.detail, "", "the sentence counts them already");

        let quiet = View::of(&Health::running());
        assert!(
            quiet.sentence.starts_with("All clear"),
            "{}",
            quiet.sentence
        );
        assert_eq!(Mark::of(quiet.orb), Mark::Tick);
    }

    /// While a Scan runs the sentence is "Checking now." and the open
    /// Findings are counted under it, still behind an exclamation mark.
    #[test]
    fn checking_now_outranks_the_open_findings() {
        let health = Health {
            open_threats: 1,
            scanning: true,
            ..Health::running()
        };
        let view = View::of(&health);
        assert_eq!(view.sentence, "Checking now.");
        assert_eq!(view.orb, Orb::Attention);
        assert_eq!(view.detail, "1 Finding is open.");
    }

    /// Approval missing, not registered, a daemon that does not answer: each
    /// is Protection is off, with the button to Login Items.
    #[test]
    fn protection_off_always_offers_login_items() {
        for why in [
            Off::NeedsApproval,
            Off::NotRegistered,
            Off::Unreachable("no daemon answered".to_string()),
            Off::Refused("AgentSweep answers only its own signed programs".to_string()),
        ] {
            let view = View::off(&why);
            assert_eq!(view.orb, Orb::Off);
            assert_eq!(view.sentence, "Protection is off.");
            assert!(view.protection_off);
            assert!(view.login_items);
            assert!(!view.detail.is_empty());
        }
        assert!(View::unknown().protection_off);
        assert!(View::of(&Health::unreachable("gone")).protection_off);
    }

    #[test]
    fn a_version_mismatch_is_updating_rather_than_off() {
        let view = View::updating();
        assert_eq!(view.orb, Orb::Updating);
        assert!(!view.protection_off);
        assert!(!view.login_items);
    }

    #[test]
    fn the_frontend_receives_every_field_by_name() {
        let value = View::off(&Off::NeedsApproval).to_value(Posture::Simple);
        assert_eq!(value["orb"], "off");
        assert_eq!(value["banner"]["title"], "Protection is off");
        assert_eq!(value["lastCheck"], Value::Null);
        assert_eq!(value["protectionOff"], true);
        assert_eq!(value["loginItems"], true);
    }

    /// Each integrity and Protection state replaces the sentence and the
    /// line under it with its banner; every other rung keeps the sentence.
    #[test]
    fn a_banner_replaces_the_sentence() {
        let tampered = Health {
            events: ChainState::Broken {
                sequence: 3,
                reason: BreakReason::MacFailed,
            },
            ..Health::running()
        };
        let reset = Health {
            events: ChainState::KeyMissing,
            ..Health::running()
        };
        let views = [
            (View::off(&Off::NeedsApproval), "Protection is off"),
            (
                View::not_watching("no daemon answered"),
                "Not watching right now",
            ),
            (
                View::of(&tampered),
                "AgentSweep's records were changed by something else.",
            ),
            (View::of(&reset), "AgentSweep cannot check its own records."),
        ];
        for (view, title) in views {
            for posture in [Posture::Simple, Posture::Developer] {
                let value = view.to_value(posture);
                assert_eq!(value["banner"]["title"], title, "{value}");
                assert!(value["sentence"].is_null(), "{value}");
                assert_eq!(value["detail"], "", "{value}");
            }
        }
        let value = View::of(&Health::running()).to_value(Posture::Simple);
        assert!(value["banner"].is_null(), "{value}");
        assert!(
            value["sentence"]
                .as_str()
                .is_some_and(|s| s.starts_with("All clear")),
            "{value}"
        );
    }

    /// A registered daemon that is not running is the amber banner with
    /// Start it, a dash in the menu bar and no Login Items button.
    #[test]
    fn not_watching_offers_start_it_and_no_login_items() {
        let view = View::not_watching("no daemon answered");
        assert_eq!(view.orb, Orb::Off);
        assert_eq!(Mark::of(view.orb), Mark::Dash);
        assert!(view.protection_off);
        assert!(!view.login_items);
        let value = view.to_value(Posture::Simple);
        assert_eq!(value["banner"]["tone"], "amber");
        assert_eq!(value["banner"]["buttons"][0]["label"], "Start it");
        assert_eq!(value["banner"]["buttons"][0]["command"], "start_daemon");
        assert_eq!(value["loginItems"], false);
    }

    /// The popover carries no Finding list, no Finding action and no
    /// progress count in either Posture: its value has these fields and no
    /// others, and its page listens to nothing but its own view.
    #[test]
    fn the_popover_shows_no_finding_and_no_progress_in_either_posture() {
        let health = Health {
            open_threats: 2,
            open_exposures: 1,
            scanning: true,
            ..Health::running()
        };
        for posture in [Posture::Simple, Posture::Developer] {
            for view in [View::of(&health), View::not_watching("x")] {
                let value = view.to_value(posture);
                let mut keys: Vec<&str> = value
                    .as_object()
                    .expect("an object")
                    .keys()
                    .map(String::as_str)
                    .collect();
                keys.sort_unstable();
                assert_eq!(
                    keys,
                    [
                        "banner",
                        "detail",
                        "lastCheck",
                        "loginItems",
                        "orb",
                        "protectionOff",
                        "sentence"
                    ]
                );
            }
            assert_eq!(
                View::of(&health).to_value(posture)["sentence"],
                "Checking now."
            );
        }
        let page = include_str!("../ui/index.html");
        let script = include_str!("../ui/popover.js");
        for word in ["finding", "progress", "quarantine", "restore", "trust"] {
            assert!(!page.to_lowercase().contains(word), "the page names {word}");
        }
        assert!(!script.contains("agentsweep://findings"));
        assert!(!script.to_lowercase().contains("progress"));
        let listened: Vec<&str> = script
            .lines()
            .filter_map(|line| line.split("listen(\"").nth(1))
            .filter_map(|rest| rest.split('"').next())
            .collect();
        assert_eq!(listened, ["agentsweep://view"]);
    }

    /// Placeholder wording still keeps the house style: no em-dashes.
    #[test]
    fn no_string_carries_an_em_dash() {
        let views = [
            View::of(&Health::running()),
            View::off(&Off::NeedsApproval),
            View::off(&Off::NotRegistered),
            View::updating(),
        ];
        for view in views {
            assert!(!view.sentence.contains('\u{2014}'));
            assert!(!view.detail.contains('\u{2014}'));
        }
    }
}
