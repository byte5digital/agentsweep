//! The app's half of the notifications (spec sections 6.7 and 8.7).
//!
//! Only the app can notify; the daemon decides what there is to tell. On
//! every launch and on every stream event that may carry something new, the
//! app asks the daemon for the un-notified changes, raises one notification
//! per change and confirms what it raised, so the daemon writes `notified_at`
//! and nothing fires twice, also across a restart of either side.
//!
//! A notification follows the Finding's state, never the Tier, and reads the
//! same in both Postures: it carries no id, path, Score or threshold, which
//! is all the Simple Posture hides (spec section 8.2). A "needs you" for a
//! late malicious Verdict reads like every other one, with no AI wording.
//!
//! The notification plugin has no click callbacks on desktop (spec section
//! 6.1). A click activates the app through the operating system, and the
//! app's reopen and activation handling opens the window on Needs your
//! decision when a notification was raised since the user last looked
//! ([`Attention`]).
//!
//! Every notification goes through the [`Notifier`] seam, so the suite never
//! posts a real one.

use std::sync::Mutex;

use agentsweep_core::eventlog::SessionsRunning;
use agentsweep_ipc::ClientError;
use agentsweep_ipc::notifications::{NotificationClass, Unnotified};
use agentsweep_ipc::protocol::StateEvent;

use crate::asking::Asking;
use crate::frame::Pane;
use crate::wording::{capitalised, noun};

/// One notification as it is raised: a title and a body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notice {
    /// The first line, in bold.
    pub title: String,
    /// The sentences under it.
    pub body: String,
}

/// The body of a "needs you" notification, whatever raised the Finding.
pub const NEEDS_YOU_BODY: &str =
    "Nothing was changed. Open AgentSweep to decide what happens to it.";

/// The body of a "keeps coming back" notification.
pub const KEEPS_COMING_BACK_BODY: &str = "AgentSweep removed it three times in the last hour and \
     it came back each time, most likely from an agent session that is still open. Open \
     AgentSweep to see what to do.";

/// The title of a "records changed" notification.
pub const RECORDS_CHANGED_TITLE: &str = "AgentSweep's records were changed";

/// The body of a "records changed" notification.
pub const RECORDS_CHANGED_BODY: &str =
    "Something other than AgentSweep changed its records. Open AgentSweep to see what changed.";

/// The body of a permission notification.
pub const PERMISSION_BODY: &str =
    "macOS has not let AgentSweep look there yet. Open AgentSweep and choose Check now.";

/// What one un-notified change says when it is raised.
pub fn notice(change: &Unnotified) -> Notice {
    match change.class {
        NotificationClass::StoppedAutomatically => Notice {
            title: format!("Stopped: {}", item(change)),
            body: format!(
                "AgentSweep moved it out of the way by itself. {}",
                sessions_lines(change)
            ),
        },
        NotificationClass::NeedsYou => Notice {
            title: format!("{} needs your decision", capitalised(&item(change))),
            body: NEEDS_YOU_BODY.to_string(),
        },
        NotificationClass::KeepsComingBack => Notice {
            title: format!("{} keeps coming back", capitalised(&item(change))),
            body: KEEPS_COMING_BACK_BODY.to_string(),
        },
        NotificationClass::RecordsChanged => Notice {
            title: RECORDS_CHANGED_TITLE.to_string(),
            body: RECORDS_CHANGED_BODY.to_string(),
        },
        NotificationClass::Permission => Notice {
            title: match change.count {
                1 => "AgentSweep can't check 1 project yet".to_string(),
                n => format!("AgentSweep can't check {n} projects yet"),
            },
            body: PERMISSION_BODY.to_string(),
        },
    }
}

/// The Item in the middle of a sentence: "the skill 'setup'".
fn item(change: &Unnotified) -> String {
    let project = change.item_id.as_ref().is_some_and(|id| id.is_project());
    let noun = change.kind.map_or("item", |kind| noun(kind, project));
    match change.name.is_empty() {
        true => format!("the {noun}"),
        false => format!("the {noun} '{}'", change.name),
    }
}

/// The Agent the Item belongs to, as a person knows it; none for an Item of
/// the workspace, which every Agent reads.
fn agent(change: &Unnotified) -> Option<&'static str> {
    match change.item_id.as_ref()?.as_str().split('/').next() {
        Some("claude-code") => Some("Claude Code"),
        Some("codex") => Some("Codex"),
        _ => None,
    }
}

/// Whether Agent sessions appeared to be running when AgentSweep stopped the
/// Item, and the restart request where one may be, in the words of the
/// confirmation after a Quarantine (ticket 73). The daemon tells only the
/// answer, not the count, so no count is named.
fn sessions_lines(change: &Unnotified) -> String {
    let agent = agent(change);
    match (change.sessions, agent) {
        (SessionsRunning::Yes, Some(agent)) => {
            format!("{agent} appears to be running. Restart it so it picks up the change.")
        }
        (SessionsRunning::Yes, None) => "A coding agent appears to be running. Restart it so it \
             picks up the change."
            .to_string(),
        (SessionsRunning::No, Some(agent)) => {
            format!("No {agent} session appears to be running.")
        }
        (SessionsRunning::No, None) => "No coding agent session appears to be running.".to_string(),
        (SessionsRunning::Unknown, Some(agent)) => format!(
            "AgentSweep could not tell whether {agent} is running. If it is open, restart it so \
             it picks up the change."
        ),
        (SessionsRunning::Unknown, None) => "AgentSweep could not tell whether a coding agent is \
             running. If it is open, restart it so it picks up the change."
            .to_string(),
    }
}

/// Whether a stream event may carry something to tell: a Finding that moved,
/// a Scan that ended, or Health that moved (a broken chain, a project that
/// Needs Permission). The Health that opens every subscription is how the
/// app asks on launch and again whenever the daemon comes back.
pub fn may_carry(event: &StateEvent) -> bool {
    matches!(
        event,
        StateEvent::FindingChanged { .. }
            | StateEvent::ScanFinished { .. }
            | StateEvent::HealthChanged { .. }
    )
}

/// Raises a notification. The seam the suite hands a fake through, so no
/// test ever posts a real one.
pub trait Notifier: Send + Sync {
    /// Asks the operating system whether the app may notify, prompting the
    /// user the first time. Answers whether it may.
    fn ask_permission(&self) -> bool;

    /// Raises one notification. Answers whether it was handed over.
    fn show(&self, notice: &Notice) -> bool;
}

/// What brought the app to the front.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activation {
    /// macOS asked the running app to reopen: a click on the app in Finder
    /// or the Dock, or a launch of the app while it runs.
    Reopen,
    /// The app became the active one, which is what a click on one of its
    /// notifications does.
    BecameActive,
}

/// Whether a notification was raised since the user last looked, which is
/// what turns an activation into "open the window on Needs your decision".
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Attention {
    raised: bool,
}

impl Attention {
    /// A notification was raised.
    pub fn raised(&mut self) {
        self.raised = true;
    }

    /// The user opened the popover or the window by other means, so the
    /// next activation is an ordinary one.
    pub fn seen(&mut self) {
        self.raised = false;
    }

    /// The pane to open the window on for this activation: Needs your
    /// decision after a notification, nothing extra otherwise.
    pub fn activated(&mut self, activation: Activation) -> Option<Pane> {
        let _ = activation;
        std::mem::take(&mut self.raised).then_some(Pane::Threats)
    }
}

/// The notifications the app raises, the permission it asked for, and
/// whether the user has looked since.
pub struct Notifications {
    notifier: Box<dyn Notifier>,
    /// One raise at a time, so two triggers never both raise the same
    /// change before either confirmed it. Holds whether the permission was
    /// asked and granted, once it was asked.
    raising: Mutex<Option<bool>>,
    attention: Mutex<Attention>,
}

impl std::fmt::Debug for Notifications {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifications")
            .field("attention", &self.attention)
            .finish_non_exhaustive()
    }
}

impl Notifications {
    /// Raises through `notifier`.
    pub fn new(notifier: Box<dyn Notifier>) -> Notifications {
        Notifications {
            notifier,
            raising: Mutex::new(None),
            attention: Mutex::new(Attention::default()),
        }
    }

    /// Asks the operating system for permission to notify now, prompting
    /// the user the first time: onboarding screen 5 does, so the prompt
    /// comes while the user is looking. The answer is kept, so the first
    /// change to say does not ask again. Answers whether the app may.
    pub fn ask_permission_now(&self) -> bool {
        let mut permission = self.raising.lock().expect("the raise is not poisoned");
        *permission.get_or_insert_with(|| self.notifier.ask_permission())
    }

    /// Asks the daemon for every un-notified change, raises each once and
    /// confirms what was raised. The permission is asked when there is
    /// first something to say; while it is refused nothing is raised and
    /// nothing confirmed. Answers how many were raised.
    pub fn raise(&self, asking: &Asking) -> Result<usize, ClientError> {
        let mut permission = self.raising.lock().expect("the raise is not poisoned");
        let changes = asking.unnotified()?;
        if changes.is_empty() {
            return Ok(0);
        }
        let permitted = *permission.get_or_insert_with(|| self.notifier.ask_permission());
        if !permitted {
            return Ok(0);
        }
        let raised: Vec<String> = changes
            .iter()
            .filter(|change| self.notifier.show(&notice(change)))
            .map(|change| change.id.clone())
            .collect();
        if raised.is_empty() {
            return Ok(0);
        }
        self.attention
            .lock()
            .expect("the attention is not poisoned")
            .raised();
        asking.notified(&raised)?;
        Ok(raised.len())
    }

    /// Raises what is un-notified when the event may carry something new.
    pub fn follow(&self, asking: &Asking, event: &StateEvent) -> Result<usize, ClientError> {
        match may_carry(event) {
            true => self.raise(asking),
            false => Ok(0),
        }
    }

    /// The pane to open the window on for this activation, if any.
    pub fn activated(&self, activation: Activation) -> Option<Pane> {
        self.attention
            .lock()
            .expect("the attention is not poisoned")
            .activated(activation)
    }

    /// The user opened the popover or the window by other means.
    pub fn seen(&self) {
        self.attention
            .lock()
            .expect("the attention is not poisoned")
            .seen();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use agentsweep_core::item::{ItemId, Kind};

    fn change(class: NotificationClass) -> Unnotified {
        let finding = !matches!(
            class,
            NotificationClass::RecordsChanged | NotificationClass::Permission
        );
        Unnotified {
            id: "claude-code/user/skill/~/.claude/skills/setup|rule/0001|abc".to_string(),
            class,
            item_id: finding
                .then(|| ItemId::from_recorded("claude-code/user/skill/~/.claude/skills/setup")),
            kind: finding.then_some(Kind::Skill),
            name: match finding {
                true => "setup".to_string(),
                false => String::new(),
            },
            sessions: SessionsRunning::Unknown,
            count: match class {
                NotificationClass::Permission => 2,
                _ => 0,
            },
        }
    }

    #[test]
    fn stopped_automatically_names_the_item_the_sessions_and_asks_for_a_restart() {
        let mut stopped = change(NotificationClass::StoppedAutomatically);
        stopped.sessions = SessionsRunning::Yes;
        assert_eq!(
            notice(&stopped),
            Notice {
                title: "Stopped: the skill 'setup'".to_string(),
                body: "AgentSweep moved it out of the way by itself. Claude Code appears to be \
                       running. Restart it so it picks up the change."
                    .to_string(),
            }
        );
        stopped.sessions = SessionsRunning::No;
        assert_eq!(
            notice(&stopped).body,
            "AgentSweep moved it out of the way by itself. No Claude Code session appears to be \
             running."
        );
        stopped.sessions = SessionsRunning::Unknown;
        assert!(
            notice(&stopped)
                .body
                .ends_with("AgentSweep could not tell whether Claude Code is running. If it is open, restart it so it picks up the change."),
        );
    }

    #[test]
    fn the_permission_asked_on_onboarding_screen_five_is_asked_once_and_kept() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Counting(Arc<AtomicUsize>);
        impl Notifier for Counting {
            fn ask_permission(&self) -> bool {
                self.0.fetch_add(1, Ordering::SeqCst);
                true
            }
            fn show(&self, _: &Notice) -> bool {
                true
            }
        }
        let asked = Arc::new(AtomicUsize::new(0));
        let notifications = Notifications::new(Box::new(Counting(Arc::clone(&asked))));
        assert!(notifications.ask_permission_now());
        assert!(notifications.ask_permission_now());
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_workspace_item_names_no_agent() {
        let mut stopped = change(NotificationClass::StoppedAutomatically);
        stopped.item_id = Some(ItemId::from_recorded(
            "workspace/project:/src/demo/env-file/.env",
        ));
        stopped.kind = Some(Kind::EnvFile);
        stopped.name = ".env".to_string();
        stopped.sessions = SessionsRunning::Yes;
        let raised = notice(&stopped);
        assert_eq!(raised.title, "Stopped: the env file '.env'");
        assert!(
            raised
                .body
                .contains("A coding agent appears to be running.")
        );
    }

    #[test]
    fn needs_you_says_nothing_was_changed_and_has_no_ai_wording() {
        // A late malicious Verdict arrives as an ordinary "needs you": the
        // daemon tells no more than the class, and the app says no more.
        let raised = notice(&change(NotificationClass::NeedsYou));
        assert_eq!(raised.title, "The skill 'setup' needs your decision");
        assert_eq!(raised.body, NEEDS_YOU_BODY);
        for text in [&raised.title, &raised.body] {
            for word in [
                "AI",
                "Claude",
                "Ollama",
                "Apple",
                "engine",
                "Verdict",
                "malicious",
            ] {
                assert!(!text.contains(word), "{word} in {text}");
            }
        }
    }

    #[test]
    fn keeps_coming_back_records_changed_and_permission_read_as_written() {
        assert_eq!(
            notice(&change(NotificationClass::KeepsComingBack)).title,
            "The skill 'setup' keeps coming back"
        );
        assert_eq!(
            notice(&change(NotificationClass::RecordsChanged)),
            Notice {
                title: RECORDS_CHANGED_TITLE.to_string(),
                body: RECORDS_CHANGED_BODY.to_string(),
            }
        );
        assert_eq!(
            notice(&change(NotificationClass::Permission)).title,
            "AgentSweep can't check 2 projects yet"
        );
        let mut one = change(NotificationClass::Permission);
        one.count = 1;
        assert_eq!(notice(&one).title, "AgentSweep can't check 1 project yet");
    }

    #[test]
    fn no_notification_carries_an_id_or_a_path() {
        for class in NotificationClass::ALL {
            let raised = notice(&change(class));
            for text in [&raised.title, &raised.body] {
                assert!(!text.contains('/'), "{text}");
                assert!(!text.contains("0001"), "{text}");
            }
        }
    }

    #[test]
    fn only_a_finding_a_scan_or_health_may_carry_something_to_tell() {
        assert!(!may_carry(&StateEvent::ScanProgress { done: 1, total: 2 }));
        assert!(!may_carry(&StateEvent::JudgementProgress {
            done: 1,
            total: 2
        }));
        assert!(may_carry(&StateEvent::FindingChanged {
            id: agentsweep_core::finding::FindingId::from_recorded("x|rule/0001|abc"),
            state: "open".to_string(),
            finding: None,
        }));
    }

    #[test]
    fn an_activation_after_a_notification_opens_needs_your_decision_once() {
        let mut attention = Attention::default();
        assert_eq!(attention.activated(Activation::Reopen), None);
        assert_eq!(attention.activated(Activation::BecameActive), None);

        attention.raised();
        assert_eq!(
            attention.activated(Activation::BecameActive),
            Some(Pane::Threats)
        );
        // The next activation is an ordinary one again.
        assert_eq!(attention.activated(Activation::Reopen), None);

        attention.raised();
        assert_eq!(attention.activated(Activation::Reopen), Some(Pane::Threats));

        // A user who opened the popover or the window has seen it.
        attention.raised();
        attention.seen();
        assert_eq!(attention.activated(Activation::BecameActive), None);
    }
}
