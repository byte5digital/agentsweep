//! The onboarding wizard of spec section 8.3: one question per screen.
//!
//! The wizard shows on any launch where SMAppService answers that the daemon
//! is not registered (the owner's decision of 2026-10-14), so a reinstall
//! after Uninstall shows it again and no flag is kept anywhere. Until the
//! daemon is registered nothing can be written, and the app writes nothing
//! itself: the answers from screen 3 on are held in memory, in a
//! [`Handover`], and reach the daemon through the `settings` request once it
//! answers.
//!
//! [`Wizard`] is the pure model: which screen is showing, Back and Next, and
//! the answers. The shell renders its view and carries out the one
//! [`Step`] it cannot take itself, registering the daemon.
//!
//! Screens 4 and 6 and the rest of screen 5 arrive with their own ticket;
//! until then screen 5 is the one line and the one button that register.

use agentsweep_core::settings::Posture;
use agentsweep_ipc::ClientError;
use agentsweep_ipc::protocol::{SettingsChange, SettingsState};
use serde_json::{Value, json};

use crate::asking::Asking;
use crate::inventory::Inventory;

/// One screen of the wizard, in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    /// Screen 1: What AgentSweep does, and that nothing leaves this Mac.
    Welcome,
    /// Screen 2: What was found: the Inventory.
    Found,
    /// Screen 3: How much detail: the Posture.
    Detail,
    /// Screen 5: Keep watching in the background: this screen registers the daemon
    /// and the login item.
    Background,
}

impl Screen {
    /// The screens in the order the wizard shows them.
    pub const ALL: [Screen; 4] = [
        Screen::Welcome,
        Screen::Found,
        Screen::Detail,
        Screen::Background,
    ];

    /// The spelling the page switches on.
    pub fn as_str(self) -> &'static str {
        match self {
            Screen::Welcome => "welcome",
            Screen::Found => "found",
            Screen::Detail => "detail",
            Screen::Background => "background",
        }
    }

    fn index(self) -> usize {
        Screen::ALL
            .iter()
            .position(|screen| *screen == self)
            .expect("every screen is listed")
    }
}

/// What Next asks of the shell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// The wizard moved to another screen; render it.
    Moved,
    /// Register the daemon and the login item, hold the answers for the
    /// daemon, and close the wizard.
    Register,
}

/// Screen 1's sentences.
pub const WELCOME: [&str; 2] = [
    "AgentSweep checks the skills, plugins, hooks and settings of Claude Code and Codex on this \
     Mac, and stops what is proven harmful before an agent can use it.",
    "Nothing leaves this Mac.",
];

/// Screen 3's question, its two answers and the line under them.
pub const DETAIL_QUESTION: &str = "How much detail would you like?";
/// The Simple Posture's answer.
pub const KEEP_IT_SIMPLE: &str = "Keep it simple";
/// The Developer Posture's answer.
pub const I_AM_A_DEVELOPER: &str = "I am a developer";
/// The line under them.
pub const CHANGEABLE_LATER: &str = "You can change this later in Settings.";

/// Screen 5's line and button, until its own ticket fills the screen.
pub const BACKGROUND: &str = "Protection continues after you quit AgentSweep.";
/// The button that registers.
pub const TURN_ON: &str = "Turn on protection";

/// The wizard: the screen showing and the answers so far.
#[derive(Clone, Debug)]
pub struct Wizard {
    screen: Screen,
    inventory: Inventory,
    posture: Posture,
}

impl Wizard {
    /// A wizard on screen 1, with the Inventory screen 2 shows. **Keep it
    /// simple** is chosen until the user chooses otherwise.
    pub fn new(inventory: Inventory) -> Wizard {
        Wizard {
            screen: Screen::Welcome,
            inventory,
            posture: Posture::Simple,
        }
    }

    /// The screen showing.
    pub fn screen(&self) -> Screen {
        self.screen
    }

    /// The Posture chosen on screen 3.
    pub fn posture(&self) -> Posture {
        self.posture
    }

    /// True on every screen but the first.
    pub fn offers_back(&self) -> bool {
        self.screen != Screen::Welcome
    }

    /// Next: the following screen, or, on the last, the registration.
    pub fn forward(&mut self) -> Step {
        match Screen::ALL.get(self.screen.index() + 1) {
            Some(screen) => {
                self.screen = *screen;
                Step::Moved
            }
            None => Step::Register,
        }
    }

    /// Back: the screen before, and nothing on the first. An answer given
    /// stays.
    pub fn back(&mut self) {
        if let Some(index) = self.screen.index().checked_sub(1) {
            self.screen = Screen::ALL[index];
        }
    }

    /// Chooses the Posture on screen 3.
    pub fn choose(&mut self, posture: Posture) {
        self.posture = posture;
    }

    /// The answers the daemon is handed once it answers.
    pub fn answers(&self) -> SettingsChange {
        SettingsChange {
            posture: Some(self.posture),
            ..SettingsChange::default()
        }
    }

    /// The view the page renders: the screen, its words, and the answers.
    pub fn to_value(&self) -> Value {
        json!({
            "screen": self.screen.as_str(),
            "step": self.screen.index() + 1,
            "steps": Screen::ALL.len(),
            "back": self.offers_back(),
            "welcome": WELCOME,
            "inventory": self.inventory.to_value(),
            "detail": {
                "question": DETAIL_QUESTION,
                "simple": KEEP_IT_SIMPLE,
                "developer": I_AM_A_DEVELOPER,
                "later": CHANGEABLE_LATER,
                "chosen": self.posture.as_str(),
            },
            "background": {
                "line": BACKGROUND,
                "button": TURN_ON,
            },
        })
    }
}

/// The one request the hand-over sends, which [`Asking`] carries in the app
/// and a test fakes.
pub trait SettingsLink {
    /// Moves the choices in `change` and answers where they all stand.
    fn change_settings(&self, change: &SettingsChange) -> Result<SettingsState, ClientError>;
}

impl SettingsLink for Asking {
    fn change_settings(&self, change: &SettingsChange) -> Result<SettingsState, ClientError> {
        Asking::change_settings(self, change)
    }
}

/// The answers held in memory until a daemon answers.
#[derive(Clone, Debug, Default)]
pub struct Handover {
    pending: Option<SettingsChange>,
}

impl Handover {
    /// Holds `answers` for the daemon, in place of any held before.
    pub fn hold(&mut self, answers: SettingsChange) {
        self.pending = Some(answers);
    }

    /// True while answers wait for a daemon.
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Hands the held answers to the daemon through `link`, once. A daemon
    /// that does not answer keeps them for the next try; one that answers,
    /// with the settings or with a refusal asking again would not change,
    /// takes them off the hand-over. Answers with the settings the daemon
    /// holds afterwards, when it took them.
    pub fn deliver(&mut self, link: &dyn SettingsLink) -> Option<SettingsState> {
        let change = self.pending.as_ref()?;
        match link.change_settings(change) {
            Ok(state) => {
                self.pending = None;
                Some(state)
            }
            Err(ClientError::Request(_) | ClientError::Refused(_)) => {
                self.pending = None;
                None
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::io;

    use crate::inventory::{Found, OWN_LISTS};

    fn inventory() -> Inventory {
        Inventory {
            agents: vec![Found {
                agent: "codex",
                name: "Codex",
                version: None,
                projects: 2,
                not_read: &["the cloud enterprise bundle", "the MDM managed preference"],
            }],
        }
    }

    /// The wizard moves one screen at a time, offers Back on every screen but
    /// the first, keeps the Posture answer across Back and Next, and asks
    /// for the registration only from screen 5.
    #[test]
    fn the_wizard_moves_screen_by_screen_and_keeps_the_posture_answer() {
        let mut wizard = Wizard::new(inventory());
        assert_eq!(wizard.screen(), Screen::Welcome);
        assert!(!wizard.offers_back());
        wizard.back();
        assert_eq!(wizard.screen(), Screen::Welcome);

        assert_eq!(wizard.forward(), Step::Moved);
        assert_eq!(wizard.screen(), Screen::Found);
        assert!(wizard.offers_back());
        assert_eq!(wizard.forward(), Step::Moved);
        assert_eq!(wizard.screen(), Screen::Detail);
        assert_eq!(wizard.posture(), Posture::Simple);

        wizard.choose(Posture::Developer);
        wizard.back();
        assert_eq!(wizard.screen(), Screen::Found);
        assert_eq!(wizard.forward(), Step::Moved);
        assert_eq!(wizard.posture(), Posture::Developer);

        assert_eq!(wizard.forward(), Step::Moved);
        assert_eq!(wizard.screen(), Screen::Background);
        assert_eq!(wizard.forward(), Step::Register);
        assert_eq!(wizard.screen(), Screen::Background);
        wizard.back();
        assert_eq!(wizard.screen(), Screen::Detail);

        assert_eq!(wizard.answers().posture, Some(Posture::Developer));
    }

    #[test]
    fn the_view_carries_the_screen_its_words_and_the_answer() {
        let mut wizard = Wizard::new(inventory());
        let view = wizard.to_value();
        assert_eq!(view["screen"], "welcome");
        assert_eq!(view["back"], false);
        assert_eq!(view["welcome"][1], "Nothing leaves this Mac.");
        assert_eq!(view["inventory"]["ownLists"], OWN_LISTS);
        assert_eq!(view["inventory"]["agents"][0]["projects"], "2 projects");

        wizard.forward();
        wizard.forward();
        wizard.choose(Posture::Developer);
        let view = wizard.to_value();
        assert_eq!(view["screen"], "detail");
        assert_eq!(view["step"], 3);
        assert_eq!(view["detail"]["simple"], KEEP_IT_SIMPLE);
        assert_eq!(view["detail"]["developer"], I_AM_A_DEVELOPER);
        assert_eq!(view["detail"]["chosen"], "developer");
    }

    /// A stand-in for the link to the daemon: it does not answer until told
    /// to, and records every change it was asked for.
    struct FakeLink {
        answering: RefCell<bool>,
        asked: RefCell<Vec<SettingsChange>>,
    }

    impl SettingsLink for FakeLink {
        fn change_settings(&self, change: &SettingsChange) -> Result<SettingsState, ClientError> {
            if !*self.answering.borrow() {
                return Err(ClientError::Unreachable(io::Error::from(
                    io::ErrorKind::NotFound,
                )));
            }
            self.asked.borrow_mut().push(change.clone());
            let mut state = crate::settings_pane::tests::state(Posture::Simple, true, true);
            if let Some(posture) = change.posture {
                state.posture = posture;
            }
            Ok(state)
        }
    }

    /// The Posture chosen on screen 3 waits in memory while no daemon
    /// answers, and reaches the settings request once, as soon as one does.
    #[test]
    fn the_posture_answer_reaches_the_settings_request_once_a_daemon_answers() {
        let mut wizard = Wizard::new(inventory());
        wizard.forward();
        wizard.forward();
        wizard.choose(Posture::Developer);
        wizard.forward();
        assert_eq!(wizard.forward(), Step::Register);

        let mut handover = Handover::default();
        let link = FakeLink {
            answering: RefCell::new(false),
            asked: RefCell::new(Vec::new()),
        };
        assert!(handover.deliver(&link).is_none(), "nothing is held yet");
        handover.hold(wizard.answers());

        assert!(handover.deliver(&link).is_none());
        assert!(handover.is_pending());
        assert!(link.asked.borrow().is_empty());

        *link.answering.borrow_mut() = true;
        let state = handover
            .deliver(&link)
            .expect("the daemon took the answers");
        assert_eq!(state.posture, Posture::Developer);
        assert!(!handover.is_pending());
        assert!(handover.deliver(&link).is_none());
        let asked = link.asked.borrow();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].posture, Some(Posture::Developer));
        assert_eq!(asked[0].rule_feed, None);
        assert_eq!(asked[0].update_check, None);
    }
}
