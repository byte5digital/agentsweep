//! The first check after onboarding (spec sections 6.8 and 8.3, screen 6).
//!
//! The wizard closes as soon as screen 5 registered the daemon; the first
//! Full Scan runs in the background. [`FirstCheck`] waits for the first Full
//! Scan that finished after the registration and then holds its result: the
//! Item count, that everything present was recorded as the Baseline, what
//! was stopped, and the Health's one sentence. The Findings window shows that
//! result until the user closes it.
//!
//! One notification says the result is ready. It goes through the app's
//! ordinary notifications ([`Notifications::raise_summary`]): while the first
//! check waits, the daemon's un-notified changes are held back, and once it
//! is ready the one notice stands for all of them and confirms them to the
//! daemon as told, so the Items the first Scan stopped or flagged do not each
//! raise one of their own. The notice is raised once: after the first try,
//! raised or refused by the operating system, the first check never asks
//! again. With notifications refused, the window shows the result the next
//! time it opens. A click on the notice opens the window on the Overview.
//!
//! Everything here lives in the app's memory. The app writes nothing, so an
//! app quit before the first Scan ended shows no result; the daemon's
//! ordinary notifications then follow as on any later launch.

use std::sync::Mutex;

use agentsweep_core::envelope::Timestamp;
use agentsweep_core::finding::{Category, FindingState};
use agentsweep_core::scan_pass::ScanKind;
use agentsweep_core::settings::Posture;
use agentsweep_ipc::protocol::{StateEvent, Status};
use serde_json::{Value, json};

use crate::asking::Asking;
use crate::frame::Pane;
use crate::notifications::{Notice, Notifications};

/// The result's heading, in the window and on the notice.
pub const FIRST_CHECK_TITLE: &str = "First check finished";
/// The Baseline sentence (spec section 8.3).
pub const BASELINE_LINE: &str = "Everything present was recorded as the Baseline.";
/// What the result says when nothing was stopped.
pub const NOTHING_STOPPED: &str = "Nothing was stopped.";
/// The button that closes the result.
pub const OK: &str = "OK";

/// What the first check found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checked {
    /// How many Items the first Full Scan enumerated.
    pub items: usize,
    /// The Items that were stopped, as the Simple Posture names them.
    pub stopped: Vec<String>,
    /// How many open Threat Findings need a decision.
    pub decide: usize,
    /// The result: the Health's one sentence in the Posture chosen.
    pub result: String,
}

impl Checked {
    /// "AgentSweep checked 42 items."
    fn items_line(&self) -> String {
        match self.items {
            1 => "AgentSweep checked 1 item.".to_string(),
            n => format!("AgentSweep checked {n} items."),
        }
    }

    /// The line over the stopped Items.
    fn stopped_line(&self) -> String {
        match self.stopped.len() {
            0 => NOTHING_STOPPED.to_string(),
            1 => "AgentSweep stopped 1 item:".to_string(),
            n => format!("AgentSweep stopped {n} items:"),
        }
    }

    /// The notice that says the result is ready.
    pub fn notice(&self) -> Notice {
        let checked = match (self.items, self.stopped.len()) {
            (1, 0) => format!("AgentSweep checked 1 item. {NOTHING_STOPPED}"),
            (n, 0) => format!("AgentSweep checked {n} items. {NOTHING_STOPPED}"),
            (1, s) => format!("AgentSweep checked 1 item and stopped {s}."),
            (n, s) => format!("AgentSweep checked {n} items and stopped {s}."),
        };
        let body = match self.decide {
            0 => checked,
            1 => format!("{checked} 1 item needs your decision."),
            n => format!("{checked} {n} items need your decision."),
        };
        Notice {
            title: FIRST_CHECK_TITLE.to_string(),
            body,
        }
    }
}

/// Where the first check stands.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum FirstCheck {
    /// No first check: an ordinary launch, or its result was closed.
    #[default]
    None,
    /// Waiting for the first Full Scan that finished after `since`, the
    /// moment the daemon was registered.
    Waiting {
        /// When the daemon was registered.
        since: Timestamp,
    },
    /// The result is ready and shows until the user closes it.
    Ready {
        /// What was found.
        checked: Checked,
        /// True once the notice was tried, so it is raised once.
        told: bool,
    },
}

impl FirstCheck {
    /// The wizard closed after registering the daemon at `since`: the first
    /// check waits. Only once: a first check under way stays as it is.
    pub fn start(&mut self, since: Timestamp) {
        if *self == FirstCheck::None {
            *self = FirstCheck::Waiting { since };
        }
    }

    /// True while it waits: the daemon's un-notified changes are held back
    /// until the one notice stands for them.
    pub fn holds_notifications(&self) -> bool {
        matches!(self, FirstCheck::Waiting { .. })
    }

    /// Whether to ask the daemon for its status after `event`: while it
    /// waits, on a Full Scan's ScanFinished, and on the Health every
    /// subscription opens with, in case that Scan finished before the app
    /// was listening.
    pub fn wants_status(&self, event: &StateEvent) -> bool {
        if !self.holds_notifications() {
            return false;
        }
        match event {
            StateEvent::ScanFinished { summary } => summary.kind == ScanKind::Full,
            StateEvent::HealthChanged { .. } => true,
            _ => false,
        }
    }

    /// Takes the daemon's status while it waits: once it carries a Full
    /// Scan that finished after the registration, the result is that Scan's
    /// Item count, the Items standing stopped, the open Threats and the
    /// Health's one sentence in `posture`. True when this made the result
    /// ready.
    pub fn take_status(&mut self, status: &Status, posture: Posture) -> bool {
        let FirstCheck::Waiting { since } = *self else {
            return false;
        };
        let Some(scan) = &status.scan else {
            return false;
        };
        if scan.kind != ScanKind::Full || scan.finished_at() < since {
            return false;
        }
        let stopped = status
            .findings
            .iter()
            .filter(|finding| finding.state == FindingState::Stopped)
            .map(|finding| crate::wording::simple(finding).title)
            .collect();
        let decide = status
            .findings
            .iter()
            .filter(|finding| finding.is_open() && finding.category == Category::Threat)
            .count();
        *self = FirstCheck::Ready {
            checked: Checked {
                items: scan.items,
                stopped,
                decide,
                result: status.health.headline_in(posture),
            },
            told: false,
        };
        true
    }

    /// The notice to raise: once the result is ready, until it was tried.
    pub fn to_tell(&self) -> Option<Notice> {
        match self {
            FirstCheck::Ready {
                checked,
                told: false,
            } => Some(checked.notice()),
            _ => None,
        }
    }

    /// The notice was tried; it is never raised again.
    pub fn told(&mut self) {
        if let FirstCheck::Ready { told, .. } = self {
            *told = true;
        }
    }

    /// The user closed the result in the window.
    pub fn seen(&mut self) {
        if matches!(self, FirstCheck::Ready { .. }) {
            *self = FirstCheck::None;
        }
    }

    /// The result as the window shows it, or null while there is none.
    pub fn to_value(&self) -> Value {
        let FirstCheck::Ready { checked, .. } = self else {
            return Value::Null;
        };
        json!({
            "title": FIRST_CHECK_TITLE,
            "items": checked.items_line(),
            "baseline": BASELINE_LINE,
            "stoppedLine": checked.stopped_line(),
            "stopped": checked.stopped,
            "result": checked.result,
            "button": OK,
        })
    }
}

/// Follows the first check on one stream event, or, with no event, looks
/// at once: asks the daemon for its status when the first check wants it,
/// takes the result, and raises its one notice through `notifications`,
/// which opens the window on the Overview when clicked. Answers true when
/// the result just became ready, so the window can show it.
///
/// A daemon that does not answer leaves the first check waiting, or its
/// notice untried, for the next event.
pub fn follow(
    first: &Mutex<FirstCheck>,
    asking: &Asking,
    notifications: Option<&Notifications>,
    posture: Posture,
    event: Option<&StateEvent>,
) -> bool {
    let wants = {
        let held = first.lock().expect("the first check is not poisoned");
        match event {
            Some(event) => held.wants_status(event),
            None => held.holds_notifications(),
        }
    };
    let mut ready = false;
    if wants && let Ok(status) = asking.status() {
        ready = first
            .lock()
            .expect("the first check is not poisoned")
            .take_status(&status, posture);
    }
    let notice = first
        .lock()
        .expect("the first check is not poisoned")
        .to_tell();
    if let (Some(notice), Some(notifications)) = (notice, notifications)
        && notifications
            .raise_summary(asking, &notice, Pane::Overview)
            .is_ok()
    {
        first
            .lock()
            .expect("the first check is not poisoned")
            .told();
    }
    ready
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::health::Health;
    use agentsweep_core::item::Kind;
    use agentsweep_core::state::{ScanSummary, Trigger};

    fn moment(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a readable moment")
    }

    fn summary(kind: ScanKind, started_at: &str, items: usize) -> ScanSummary {
        ScanSummary {
            kind,
            trigger: Trigger::DaemonStart,
            started_at: moment(started_at),
            duration_ms: 1_200,
            items,
            threats: 0,
            exposures: 0,
            clear: items,
            ambiguous: 0,
            suspicious: 0,
            rule_pack: 1,
            engine: String::new(),
        }
    }

    fn waiting() -> FirstCheck {
        let mut first = FirstCheck::default();
        first.start(moment("2026-10-19T10:00:00.000Z"));
        first
    }

    /// An ordinary launch has no first check: it holds nothing back, asks
    /// for nothing, raises nothing and shows nothing.
    #[test]
    fn an_ordinary_launch_has_no_first_check() {
        let first = FirstCheck::default();
        assert!(!first.holds_notifications());
        assert!(!first.wants_status(&StateEvent::HealthChanged {
            health: Box::new(Health::running()),
        }));
        assert_eq!(first.to_tell(), None);
        assert_eq!(first.to_value(), Value::Null);
    }

    /// The first check waits for the first Full Scan after the registration,
    /// holding the ordinary notifications back meanwhile, then reports its
    /// Item count, the Baseline sentence, what was stopped and the result; a
    /// Scan from before the registration does not count.
    #[test]
    fn it_waits_for_the_first_full_scan_and_reports_what_was_stopped() {
        let mut first = waiting();
        assert!(first.holds_notifications());
        assert_eq!(first.to_value(), Value::Null, "nothing to show yet");
        assert_eq!(first.to_tell(), None);

        let finished = StateEvent::ScanFinished {
            summary: Box::new(summary(ScanKind::Full, "2026-10-19T10:00:05.000Z", 42)),
        };
        let change = StateEvent::ScanFinished {
            summary: Box::new(summary(ScanKind::Change, "2026-10-19T10:00:05.000Z", 1)),
        };
        assert!(first.wants_status(&finished));
        assert!(!first.wants_status(&change));
        assert!(first.wants_status(&StateEvent::HealthChanged {
            health: Box::new(Health::running()),
        }));

        let stopped = crate::findings::tests::recorded(
            "claude-code/user/skill/~/.claude/skills/setup",
            Kind::Skill,
            "rule 0001",
            Category::Threat,
            FindingState::Stopped,
        );
        let open = crate::findings::tests::recorded(
            "claude-code/user/mcp-server/~/.claude.json#tracker",
            Kind::McpServer,
            "score 7",
            Category::Threat,
            FindingState::Open,
        );
        let mut status = crate::findings::tests::status_of(vec![stopped.clone(), open]);

        // No Scan yet, and then one from before the registration.
        assert!(!first.take_status(&status, Posture::Simple));
        status.scan = Some(summary(ScanKind::Full, "2026-10-19T09:00:00.000Z", 7));
        assert!(!first.take_status(&status, Posture::Simple));
        assert!(first.holds_notifications());

        status.scan = Some(summary(ScanKind::Full, "2026-10-19T10:00:05.000Z", 42));
        assert!(first.take_status(&status, Posture::Simple));
        assert!(!first.holds_notifications(), "done waiting");
        assert!(!first.wants_status(&finished));
        assert!(!first.take_status(&status, Posture::Simple), "taken once");

        let view = first.to_value();
        assert_eq!(view["title"], FIRST_CHECK_TITLE);
        assert_eq!(view["items"], "AgentSweep checked 42 items.");
        assert_eq!(view["baseline"], BASELINE_LINE);
        assert_eq!(view["stoppedLine"], "AgentSweep stopped 1 item:");
        assert_eq!(
            view["stopped"][0],
            crate::wording::simple(&stopped).title.as_str()
        );
        assert_eq!(view["result"], status.health.headline());
        assert_eq!(view["button"], OK);
    }

    /// One notice says the result is ready, and it is tried once.
    #[test]
    fn one_notice_says_the_result_is_ready_and_is_tried_once() {
        let mut first = waiting();
        let mut status = crate::findings::tests::status_of(vec![
            crate::findings::tests::recorded(
                "claude-code/user/skill/~/.claude/skills/setup",
                Kind::Skill,
                "rule 0001",
                Category::Threat,
                FindingState::Stopped,
            ),
            crate::findings::tests::recorded(
                "claude-code/user/mcp-server/~/.claude.json#tracker",
                Kind::McpServer,
                "score 7",
                Category::Threat,
                FindingState::Open,
            ),
        ]);
        status.scan = Some(summary(ScanKind::Full, "2026-10-19T10:00:05.000Z", 42));
        first.take_status(&status, Posture::Simple);
        assert_eq!(
            first.to_tell(),
            Some(Notice {
                title: FIRST_CHECK_TITLE.to_string(),
                body: "AgentSweep checked 42 items and stopped 1. 1 item needs your decision."
                    .to_string(),
            })
        );
        first.told();
        assert_eq!(first.to_tell(), None, "once");
        // The result still shows until the user closes it.
        assert_ne!(first.to_value(), Value::Null);
        first.seen();
        assert_eq!(first.to_value(), Value::Null);
        assert_eq!(first.to_tell(), None);

        // A start after that is a new first check; one under way stays.
        let mut again = waiting();
        again.start(moment("2026-10-19T11:00:00.000Z"));
        assert_eq!(
            again,
            FirstCheck::Waiting {
                since: moment("2026-10-19T10:00:00.000Z")
            }
        );
    }

    #[test]
    fn the_result_says_so_when_nothing_was_stopped() {
        let mut first = waiting();
        let mut status = crate::findings::tests::status_of(Vec::new());
        status.health = Health::running();
        status.scan = Some(summary(ScanKind::Full, "2026-10-19T10:00:01.000Z", 1));
        assert!(first.take_status(&status, Posture::Simple));
        let view = first.to_value();
        assert_eq!(view["items"], "AgentSweep checked 1 item.");
        assert_eq!(view["stoppedLine"], NOTHING_STOPPED);
        assert_eq!(view["stopped"], json!([]));
        assert_eq!(
            first.to_tell().expect("a notice").body,
            "AgentSweep checked 1 item. Nothing was stopped."
        );
    }

    /// Every text is short, and the notice carries no id or path.
    #[test]
    fn the_texts_are_short_and_name_no_path() {
        let checked = Checked {
            items: 1_234,
            stopped: vec!["Stopped: the skill 'setup'".to_string(); 3],
            decide: 2,
            result: String::new(),
        };
        let notice = checked.notice();
        assert!(notice.title.len() <= 30, "{}", notice.title);
        assert!(notice.body.len() <= 90, "{}", notice.body);
        assert!(!notice.body.contains('/'));
        for line in [BASELINE_LINE, NOTHING_STOPPED] {
            assert!(line.len() <= 60, "{line}");
        }
    }

    /// The window's page shows the result in a dialog of its own, fetched on
    /// load and followed from its event, and closing it tells the app.
    #[test]
    fn the_window_shows_the_result_until_it_is_closed() {
        let page = include_str!("../ui/window.html");
        assert!(page.contains(r#"<script type="module" src="first_check.js"></script>"#));
        assert!(page.contains(r#"<dialog id="first-check">"#));
        let script = include_str!("../ui/first_check.js");
        assert!(script.contains(r#"invoke("first_check")"#));
        assert!(script.contains(r#"invoke("first_check_seen")"#));
        assert!(script.contains(r#"listen("agentsweep://first-check""#));
    }
}
