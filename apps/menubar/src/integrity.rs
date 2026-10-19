//! The four buttons of the integrity banners (spec section 8.6): each sends
//! the daemon's matching request and opens the Activity pane at the record
//! that matters.
//!
//! - **Start a fresh record** sends acknowledge-key-missing and opens the
//!   pane at the restart record, where the records started again under a new
//!   key.
//! - **Look at the records** reads the Event Log from that restart record
//!   with the records request and opens the pane there.
//! - **Show what changed** reads the broken chain from its break with the
//!   records request and opens the pane at the break point.
//! - **Scan again, trusting nothing** sends acknowledge-chain-broken, which
//!   starts a Full Scan, and opens the pane at the break point.
//!
//! The Activity pane lists the Event Log, so a break or a restart only the
//! Baseline has opens the pane without a record to point at. The requests go
//! through [`Records`], which [`Asking`] is and which a test stands in for.

use agentsweep_core::chain::ChainState;
use agentsweep_core::envelope::ChainId;
use agentsweep_core::health::Health;
use agentsweep_ipc::ClientError;
use agentsweep_ipc::integrity::{ChainRecords, IntegrityAnswer};

use crate::activity::Activity;
use crate::asking::{Asking, refusal};
use crate::banner::Button;

/// The three requests behind the four buttons.
pub trait Records {
    /// One page of a chain's records from one sequence on.
    fn records(&self, chain: ChainId, from: u64) -> Result<ChainRecords, ClientError>;
    /// "Start a fresh record".
    fn acknowledge_key_missing(&self) -> Result<IntegrityAnswer, ClientError>;
    /// "Scan again, trusting nothing".
    fn acknowledge_chain_broken(&self) -> Result<IntegrityAnswer, ClientError>;
}

impl Records for Asking {
    fn records(&self, chain: ChainId, from: u64) -> Result<ChainRecords, ClientError> {
        Asking::records(self, chain, from)
    }
    fn acknowledge_key_missing(&self) -> Result<IntegrityAnswer, ClientError> {
        Asking::acknowledge_key_missing(self)
    }
    fn acknowledge_chain_broken(&self) -> Result<IntegrityAnswer, ClientError> {
        Asking::acknowledge_chain_broken(self)
    }
}

/// What a press did: the line the banner says, and the Event Log record
/// the Activity pane opens at, absent when there is none to point at.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pressed {
    /// The line under the buttons.
    pub line: String,
    /// The sequence the Activity pane opens at.
    pub focus: Option<u64>,
}

/// The record kind of a chain restart, as the Activity and the records name
/// it.
const CHAIN_RESTART: &str = "chain-restart";

/// The latest restart record of the Event Log the Activity holds.
pub fn restart_record(activity: &Activity) -> Option<u64> {
    activity
        .lines()
        .iter()
        .filter(|line| line.action == CHAIN_RESTART)
        .filter_map(|line| line.sequence)
        .max()
}

/// Where a chain stops being trustworthy, when it is broken.
fn break_of(state: &ChainState) -> Option<u64> {
    match state {
        ChainState::Broken { sequence, .. } => Some(*sequence),
        ChainState::Intact | ChainState::KeyMissing => None,
    }
}

/// The break point of the Event Log, which the Activity pane can open at.
pub fn break_point(health: &Health) -> Option<u64> {
    break_of(&health.events)
}

/// Carries out one integrity button against the daemon, from the Health and
/// the Activity the window holds. Any other button is refused here: it is
/// not an integrity button.
pub fn press(
    button: Button,
    health: &Health,
    activity: &Activity,
    daemon: &dyn Records,
) -> Result<Pressed, String> {
    let failed = |error: ClientError| refusal(&error);
    match button {
        Button::StartFreshRecord => {
            daemon.acknowledge_key_missing().map_err(failed)?;
            Ok(Pressed {
                line: "AgentSweep started a fresh record.".to_string(),
                focus: restart_record(activity),
            })
        }
        Button::LookAtRecords => {
            let restart = restart_record(activity);
            let page = daemon
                .records(ChainId::Events, restart.unwrap_or(0))
                .map_err(failed)?;
            let found = page
                .records
                .iter()
                .filter(|record| record.record == CHAIN_RESTART)
                .map(|record| record.sequence)
                .next_back();
            Ok(Pressed {
                line: "The records since the reset are in Activity.".to_string(),
                focus: found.or(restart),
            })
        }
        Button::ShowWhatChanged => {
            let (chain, from) = match (break_of(&health.events), break_of(&health.baseline)) {
                (Some(at), _) => (ChainId::Events, at),
                (None, Some(at)) => (ChainId::Baseline, at),
                (None, None) => {
                    return Err("No record was changed by something else.".to_string());
                }
            };
            let page = daemon.records(chain, from).map_err(failed)?;
            Ok(Pressed {
                line: "What changed is shown in Activity.".to_string(),
                focus: match chain {
                    ChainId::Events => break_of(&page.state).or(Some(from)),
                    ChainId::Baseline => None,
                },
            })
        }
        Button::ScanAgainTrustingNothing => {
            let focus = break_point(health);
            let answer = daemon.acknowledge_chain_broken().map_err(failed)?;
            Ok(Pressed {
                line: match answer.scan_started {
                    true => "AgentSweep is scanning again, trusting nothing.",
                    false => "AgentSweep will scan again, trusting nothing, with the check already waiting.",
                }
                .to_string(),
                focus,
            })
        }
        Button::OpenLoginItems | Button::StartIt => {
            Err("That is not an answer to the records.".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use agentsweep_core::chain::BreakReason;
    use agentsweep_core::envelope::Timestamp;
    use agentsweep_ipc::integrity::RecordLine;
    use agentsweep_ipc::protocol::{ActivityLine, Status};

    /// A daemon that records every request and answers with what a test set.
    #[derive(Default)]
    struct Recorded {
        asked: Mutex<Vec<String>>,
        page: Vec<RecordLine>,
        state: Option<ChainState>,
        scan_started: bool,
    }

    impl Recorded {
        fn asked(&self) -> Vec<String> {
            self.asked.lock().expect("the requests").clone()
        }
        fn answer(&self, acknowledgement: &str) -> IntegrityAnswer {
            IntegrityAnswer {
                acknowledgement: acknowledgement.to_string(),
                chains: vec![ChainId::Events],
                scan_started: self.scan_started,
            }
        }
    }

    impl Records for Recorded {
        fn records(&self, chain: ChainId, from: u64) -> Result<ChainRecords, ClientError> {
            self.asked
                .lock()
                .expect("the requests")
                .push(format!("records {} from {from}", chain.as_str()));
            Ok(ChainRecords {
                chain,
                state: self.state.clone().unwrap_or(ChainState::Intact),
                records: self.page.clone(),
                next: None,
            })
        }
        fn acknowledge_key_missing(&self) -> Result<IntegrityAnswer, ClientError> {
            self.asked
                .lock()
                .expect("the requests")
                .push("acknowledge-key-missing".to_string());
            Ok(self.answer("key-missing"))
        }
        fn acknowledge_chain_broken(&self) -> Result<IntegrityAnswer, ClientError> {
            self.asked
                .lock()
                .expect("the requests")
                .push("acknowledge-chain-broken".to_string());
            Ok(self.answer("chain-broken"))
        }
    }

    fn line(sequence: u64, action: &str) -> ActivityLine {
        ActivityLine {
            sequence: Some(sequence),
            recorded_at: Timestamp::from_unix_ms(sequence as i64 * 1000),
            action: action.to_string(),
            ..ActivityLine::default()
        }
    }

    fn activity(lines: Vec<ActivityLine>) -> Activity {
        let mut status = Status::unreachable("");
        status.activity = lines;
        let mut activity = Activity::default();
        activity.load(&status);
        activity
    }

    fn broken_at(sequence: u64) -> ChainState {
        ChainState::Broken {
            sequence,
            reason: BreakReason::MacFailed,
        }
    }

    fn record(sequence: u64, kind: &str) -> RecordLine {
        RecordLine {
            sequence,
            record: kind.to_string(),
            ..RecordLine::default()
        }
    }

    #[test]
    fn start_a_fresh_record_answers_the_reset_and_opens_at_the_restart_record() {
        let daemon = Recorded::default();
        let held = activity(vec![
            line(0, "quarantine"),
            line(4, CHAIN_RESTART),
            line(5, "trust"),
        ]);
        let health = Health {
            events: ChainState::KeyMissing,
            ..Health::running()
        };
        let pressed = press(Button::StartFreshRecord, &health, &held, &daemon).expect("pressed");
        assert_eq!(daemon.asked(), vec!["acknowledge-key-missing"]);
        assert_eq!(pressed.focus, Some(4));
    }

    #[test]
    fn look_at_the_records_reads_the_event_log_from_the_restart_record() {
        let daemon = Recorded {
            page: vec![record(4, CHAIN_RESTART), record(5, "entry")],
            state: Some(ChainState::KeyMissing),
            ..Recorded::default()
        };
        let held = activity(vec![line(4, CHAIN_RESTART)]);
        let health = Health {
            events: ChainState::KeyMissing,
            ..Health::running()
        };
        let pressed = press(Button::LookAtRecords, &health, &held, &daemon).expect("pressed");
        assert_eq!(daemon.asked(), vec!["records events from 4"]);
        assert_eq!(pressed.focus, Some(4));
    }

    #[test]
    fn show_what_changed_reads_the_broken_chain_from_its_break() {
        let daemon = Recorded {
            state: Some(broken_at(9)),
            ..Recorded::default()
        };
        let health = Health {
            events: broken_at(9),
            ..Health::running()
        };
        let held = activity(Vec::new());
        let pressed = press(Button::ShowWhatChanged, &health, &held, &daemon).expect("pressed");
        assert_eq!(daemon.asked(), vec!["records events from 9"]);
        assert_eq!(pressed.focus, Some(9));

        // A break only the Baseline has is read there, and the pane opens
        // with no Event Log record to point at.
        let daemon = Recorded {
            state: Some(broken_at(30)),
            ..Recorded::default()
        };
        let health = Health {
            baseline: broken_at(30),
            ..Health::running()
        };
        let pressed = press(Button::ShowWhatChanged, &health, &held, &daemon).expect("pressed");
        assert_eq!(daemon.asked(), vec!["records baseline from 30"]);
        assert_eq!(pressed.focus, None);
    }

    #[test]
    fn scan_again_trusting_nothing_answers_the_break_and_opens_at_the_break_point() {
        let daemon = Recorded {
            scan_started: true,
            ..Recorded::default()
        };
        let health = Health {
            events: broken_at(12),
            ..Health::running()
        };
        let pressed = press(
            Button::ScanAgainTrustingNothing,
            &health,
            &activity(Vec::new()),
            &daemon,
        )
        .expect("pressed");
        assert_eq!(daemon.asked(), vec!["acknowledge-chain-broken"]);
        assert_eq!(pressed.focus, Some(12));
        assert_eq!(
            pressed.line,
            "AgentSweep is scanning again, trusting nothing."
        );
    }

    #[test]
    fn the_other_buttons_send_nothing_here() {
        let daemon = Recorded::default();
        for button in [Button::OpenLoginItems, Button::StartIt] {
            assert!(
                press(button, &Health::running(), &Activity::default(), &daemon).is_err(),
                "{button:?}"
            );
        }
        assert!(daemon.asked().is_empty());
    }
}
