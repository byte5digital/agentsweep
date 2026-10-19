//! The onboarding wizard of spec section 8.3: one question per screen.
//!
//! The wizard shows on any launch where SMAppService answers that the daemon
//! is not registered (the owner's decision of 2026-10-14), so a reinstall
//! after Uninstall shows it again and no flag is kept anywhere. Until the
//! daemon is registered nothing can be written, and the app writes nothing
//! itself: the answers from screen 3 on are held in memory, in a
//! [`Handover`], and reach the daemon through the `settings` and `engine`
//! requests once it answers.
//!
//! [`Wizard`] is the pure model: which screen is showing, Back and Next, and
//! the answers. The shell renders its view and carries out the steps it
//! cannot take itself: registering the daemon and the login item (through
//! the [`Services`] seam), asking for notification permission, sending
//! check-now, and asking the daemon for the status screen 6 reports.
//!
//! - Screen 4, the AI check, preselects the local-first suggestion of spec
//!   section 4.4 from the engine answer: Ollama with a model of 4B or more,
//!   else Apple on-device when it is available, else Off. Claude is never
//!   preselected, only offered, and only in the Developer Posture, beside a
//!   way to choose Ollama. Ollama needs one confirmation naming the model;
//!   Claude needs the consent screen of the Settings pane, whose key is held
//!   in the hand-over and goes to the daemon once.
//! - Screen 5, Keep watching in the background, holds the Rule Feed and app
//!   update toggles, and, only when the Inventory found a registered project
//!   in a protected location class, offers the one click that sends
//!   check-now so the operating system's prompt appears in front of the
//!   user. Leaving it registers the daemon and the login item once and holds
//!   every answer for the daemon.
//! - Screen 6, First check finished, waits for the first Full Scan after the
//!   registration and reports its Item count, that everything present was
//!   recorded as the Baseline, what was stopped, and the result.

use agentsweep_core::apple::AppleAvailability;
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::finding::FindingState;
use agentsweep_core::judgement::{EngineSuggestion, suggested_engine};
use agentsweep_core::keychain::ClaudeKey;
use agentsweep_core::location::LocationClass;
use agentsweep_core::ollama::OllamaPresence;
use agentsweep_core::scan_pass::ScanKind;
use agentsweep_core::settings::{
    CloudCaps, DEFAULT_CLAUDE_MODEL, DEFAULT_OLLAMA_ADDRESS, JudgementEngine, Posture,
};
use agentsweep_ipc::ClientError;
use agentsweep_ipc::engine::{CloudUse, EngineChange, EngineState};
use agentsweep_ipc::protocol::{SettingsChange, SettingsState, StateEvent, Status};
use serde_json::{Value, json};

use crate::ai_check::{self, Bar};
use crate::asking::Asking;
use crate::inventory::Inventory;
use crate::settings_pane::BACKGROUND_DISCLOSURE;
use crate::supervision::{self, Launched, Services};

/// One screen of the wizard, in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    /// Screen 1: What AgentSweep does, and that nothing leaves this Mac.
    Welcome,
    /// Screen 2: What was found: the Inventory.
    Found,
    /// Screen 3: How much detail: the Posture.
    Detail,
    /// Screen 4: the AI check.
    AiCheck,
    /// Screen 5: Keep watching in the background: leaving it registers the
    /// daemon and the login item.
    Background,
    /// Screen 6: First check finished.
    FirstCheck,
}

impl Screen {
    /// The screens in the order the wizard shows them.
    pub const ALL: [Screen; 6] = [
        Screen::Welcome,
        Screen::Found,
        Screen::Detail,
        Screen::AiCheck,
        Screen::Background,
        Screen::FirstCheck,
    ];

    /// The spelling the page switches on.
    pub fn as_str(self) -> &'static str {
        match self {
            Screen::Welcome => "welcome",
            Screen::Found => "found",
            Screen::Detail => "detail",
            Screen::AiCheck => "ai",
            Screen::Background => "background",
            Screen::FirstCheck => "first",
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
    /// Ollama is chosen on screen 4 but not yet confirmed: show the one
    /// confirmation, and stay.
    ConfirmOllama,
    /// Leaving screen 5: register the daemon and the login item, ask for
    /// notification permission, and hold the answers for the daemon
    /// ([`Wizard::leave_background`]).
    Register,
    /// Screen 6 still waits for the first check; stay.
    Waiting,
    /// Screen 6 is done: close the wizard.
    Done,
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

/// Screen 4's heading in the Simple Posture.
pub const AI_CHECK_TITLE: &str = "AI check";
/// Screen 4's heading in the Developer Posture.
pub const AI_JUDGEMENT_TITLE: &str = "AI Judgement";
/// What the Apple on-device choice says on screen 4 (spec section 8.3).
pub const APPLE_LINE: &str =
    "Double-check unclear items with your Mac's built-in AI. Nothing leaves your Mac.";
/// The line over the Ollama and Claude choices in the Developer Posture.
pub const OTHER_ENGINES: &str = "Or choose another engine:";
/// What "Preview a request" says before the daemon runs.
pub const PREVIEW_LATER: &str = "A request can be previewed once AgentSweep runs: in Settings, \
     under AI check.";
/// What screen 4 says under the choices.
pub const AI_CHECK_LATER: &str = "You can change this later in Settings.";

/// Screen 5's sentences, in order.
pub const BACKGROUND_LINES: [&str; 3] = [
    "macOS will announce that AgentSweep added a background item, and ask whether AgentSweep may \
     send you notifications.",
    "Protection continues after you quit AgentSweep.",
    "AgentSweep also adds a check to Claude Code and Codex so flagged items cannot be used until \
     you decide.",
];
/// The button that registers.
pub const TURN_ON: &str = "Turn on protection";
/// The button that sends check-now.
pub const LOOK_THERE: &str = "Let macOS ask now";
/// What screen 5 says once that button was pressed.
pub const LOOK_THERE_SENT: &str = "AgentSweep looks there as soon as it runs. Answer macOS when \
     it asks.";

/// Screen 6's heading.
pub const FIRST_CHECK_TITLE: &str = "First check finished";
/// Screen 6's heading while it waits.
pub const FIRST_CHECK_WAITING_TITLE: &str = "Checking for the first time";
/// What screen 6 says while it waits.
pub const FIRST_CHECK_WAITING: &str =
    "AgentSweep is looking at everything your agents use. This can take a minute.";
/// The Baseline sentence of screen 6 (spec section 8.3).
pub const BASELINE_LINE: &str = "Everything present was recorded as the Baseline, so AgentSweep \
     notices when something changes.";
/// What screen 6 says when nothing was stopped.
pub const NOTHING_STOPPED: &str = "Nothing was stopped.";
/// The button that closes the wizard.
pub const DONE: &str = "Done";

/// The sentence of screen 5 naming where the protected projects are, and
/// that macOS will ask once. Documents reads as spec section 8.3 words it.
pub fn protected_line(classes: &[LocationClass]) -> String {
    let places: Vec<&str> = classes
        .iter()
        .filter_map(|class| match class {
            LocationClass::Unprotected => None,
            LocationClass::Documents => Some("in Documents"),
            LocationClass::Desktop => Some("on the Desktop"),
            LocationClass::Downloads => Some("in Downloads"),
            LocationClass::FileProvider => Some("in iCloud Drive or other cloud storage"),
            LocationClass::RemovableVolumes => Some("on an external disk"),
            LocationClass::NetworkVolumes => Some("on a network volume"),
        })
        .collect();
    let places = match places.as_slice() {
        [] => return String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    format!(
        "Some of your projects are {places}. macOS will ask once whether AgentSweep may look \
         there."
    )
}

/// The engine chosen on screen 4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pick {
    /// Apple on-device.
    Apple,
    /// Ollama with one model, and whether its one confirmation was given.
    Ollama {
        /// The model the confirmation names.
        model: String,
        /// True once the user confirmed it.
        confirmed: bool,
    },
    /// The Claude API, with the key held in the hand-over.
    Claude,
    /// No AI check.
    Off,
}

impl Pick {
    /// The engine it names.
    pub fn engine(&self) -> JudgementEngine {
        match self {
            Pick::Apple => JudgementEngine::Apple,
            Pick::Ollama { .. } => JudgementEngine::Ollama,
            Pick::Claude => JudgementEngine::Claude,
            Pick::Off => JudgementEngine::Off,
        }
    }
}

/// The choice screen 4 preselects from the engine answer: the local-first
/// suggestion of spec section 4.4, Ollama awaiting its confirmation, and
/// Off when nothing can be suggested or nothing answered yet. Never Claude.
pub fn preselected(look: Option<&EngineState>) -> Pick {
    let Some(look) = look else {
        return Pick::Off;
    };
    let unknown = AppleAvailability::Unavailable {
        reason: "unknown".to_string(),
    };
    match suggested_engine(
        look.ollama.as_ref().unwrap_or(&OllamaPresence::Absent),
        look.apple.as_ref().unwrap_or(&unknown),
    ) {
        EngineSuggestion::Ollama { model } => Pick::Ollama {
            model,
            confirmed: false,
        },
        EngineSuggestion::Apple => Pick::Apple,
        EngineSuggestion::Nothing => Pick::Off,
    }
}

/// The engine state before any daemon answered: every choice at its
/// default, nothing known about Ollama or Apple.
pub fn unanswered() -> EngineState {
    EngineState {
        engine: JudgementEngine::Off,
        ollama_address: DEFAULT_OLLAMA_ADDRESS.to_string(),
        ollama_model: String::new(),
        claude_model: String::new(),
        claude_model_in_use: DEFAULT_CLAUDE_MODEL.to_string(),
        caps: CloudCaps::default(),
        claude_key_ending: None,
        recorded: 0,
        ollama: None,
        apple: None,
        cloud_use: CloudUse::default(),
    }
}

/// What screen 6 reports once the first check finished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checked {
    /// How many Items the first Full Scan enumerated.
    pub items: usize,
    /// The Items that were stopped, as the Simple Posture names them.
    pub stopped: Vec<String>,
    /// The result: the Health's one sentence in the Posture chosen.
    pub result: String,
}

/// The answers the daemon is handed once it answers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Answers {
    /// The Posture and the two toggles, for the `settings` request.
    pub settings: SettingsChange,
    /// The engine, for the `engine` request.
    pub engine: EngineChange,
}

/// The wizard: the screen showing and the answers so far.
#[derive(Clone, Debug)]
pub struct Wizard {
    screen: Screen,
    inventory: Inventory,
    posture: Posture,
    look: Option<EngineState>,
    pick: Option<Pick>,
    rule_feed: bool,
    update_check: bool,
    looked_there: bool,
    registered_at: Option<Timestamp>,
    checked: Option<Checked>,
}

impl Wizard {
    /// A wizard on screen 1, with the Inventory screen 2 shows. **Keep it
    /// simple** is chosen until the user chooses otherwise, and both
    /// background requests are on, as their defaults are.
    pub fn new(inventory: Inventory) -> Wizard {
        Wizard {
            screen: Screen::Welcome,
            inventory,
            posture: Posture::Simple,
            look: None,
            pick: None,
            rule_feed: true,
            update_check: true,
            looked_there: false,
            registered_at: None,
            checked: None,
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

    /// True on every screen but the first and the last: once the daemon is
    /// registered there is no going back.
    pub fn offers_back(&self) -> bool {
        !matches!(self.screen, Screen::Welcome | Screen::FirstCheck)
    }

    /// Next: the following screen, or what the shell must do first.
    pub fn forward(&mut self) -> Step {
        match self.screen {
            Screen::AiCheck
                if matches!(
                    self.pick(),
                    Pick::Ollama {
                        confirmed: false,
                        ..
                    }
                ) =>
            {
                Step::ConfirmOllama
            }
            Screen::Background => Step::Register,
            Screen::FirstCheck => match self.checked {
                Some(_) => Step::Done,
                None => Step::Waiting,
            },
            screen => {
                self.screen = Screen::ALL[screen.index() + 1];
                Step::Moved
            }
        }
    }

    /// Back: the screen before, and nothing on the first or the last. An
    /// answer given stays.
    pub fn back(&mut self) {
        if !self.offers_back() {
            return;
        }
        if let Some(index) = self.screen.index().checked_sub(1) {
            self.screen = Screen::ALL[index];
        }
    }

    /// Chooses the Posture on screen 3.
    pub fn choose(&mut self, posture: Posture) {
        self.posture = posture;
    }

    /// Takes the engine answer screen 4 preselects from.
    pub fn look(&mut self, look: EngineState) {
        self.look = Some(look);
    }

    /// The engine chosen on screen 4: the user's choice, else the
    /// preselection.
    pub fn pick(&self) -> Pick {
        self.pick
            .clone()
            .unwrap_or_else(|| preselected(self.look.as_ref()))
    }

    /// Chooses Apple on-device, Ollama or Off on screen 4. Apple only when
    /// the engine answer did not say it is unavailable; Ollama only with a
    /// model of 4B or more to name, and then awaiting its confirmation.
    /// Claude is chosen through [`Wizard::agree_to_claude`].
    pub fn choose_engine(&mut self, engine: JudgementEngine) -> Result<(), String> {
        let refused = || "That engine cannot be chosen on this Mac.".to_string();
        let pick = match engine {
            JudgementEngine::Apple => {
                let unavailable = self
                    .look
                    .as_ref()
                    .and_then(|look| look.apple.as_ref())
                    .is_some_and(|apple| !apple.is_available());
                if unavailable {
                    return Err(refused());
                }
                Pick::Apple
            }
            JudgementEngine::Ollama => {
                let model = self
                    .look
                    .as_ref()
                    .and_then(ai_check::ollama_model)
                    .ok_or_else(refused)?;
                Pick::Ollama {
                    model,
                    confirmed: false,
                }
            }
            JudgementEngine::Off => Pick::Off,
            JudgementEngine::Claude => return Err(refused()),
        };
        self.pick = Some(pick);
        Ok(())
    }

    /// The one confirmation Ollama needs was given.
    pub fn confirm_ollama(&mut self) {
        if let Pick::Ollama { model, .. } = self.pick() {
            self.pick = Some(Pick::Ollama {
                model,
                confirmed: true,
            });
        }
    }

    /// The Claude consent screen was agreed to, with a key the shell now
    /// holds in the hand-over or one the daemon already has.
    pub fn agree_to_claude(&mut self) {
        self.pick = Some(Pick::Claude);
    }

    /// Moves one toggle of screen 5: `rule_feed` or `update_check`.
    pub fn toggle(&mut self, key: &str, on: bool) -> Result<(), String> {
        match key {
            "rule_feed" => self.rule_feed = on,
            "update_check" => self.update_check = on,
            _ => return Err("That is not a setting AgentSweep knows.".to_string()),
        }
        Ok(())
    }

    /// The protected location classes screen 5 names.
    fn protected(&self) -> Vec<LocationClass> {
        self.inventory.protected.iter().copied().collect()
    }

    /// The button of screen 5's protected-location line was pressed. True
    /// the first time only, and only while that line shows: the shell then
    /// sends check-now once, as soon as the daemon can take it.
    pub fn look_there(&mut self) -> bool {
        if self.screen != Screen::Background || self.protected().is_empty() || self.looked_there {
            return false;
        }
        self.looked_there = true;
        true
    }

    /// Registers the daemon and the login item through `services`, once:
    /// a second call registers nothing and answers None. `now` is when, so
    /// screen 6 reports only a Full Scan that finished after it.
    pub fn register_once(&mut self, services: &dyn Services, now: Timestamp) -> Option<Launched> {
        if self.registered_at.is_some() {
            return None;
        }
        self.registered_at = Some(now);
        Some(supervision::register(services))
    }

    /// True once the daemon was registered.
    pub fn is_registered(&self) -> bool {
        self.registered_at.is_some()
    }

    /// Leaving screen 5: registers the daemon and the login item once, holds
    /// every answer for the daemon in `handover`, and moves to screen 6.
    pub fn leave_background(
        &mut self,
        services: &dyn Services,
        handover: &mut Handover,
        now: Timestamp,
    ) -> Option<Launched> {
        if self.screen != Screen::Background {
            return None;
        }
        let launched = self.register_once(services, now);
        handover.hold(self.answers());
        self.screen = Screen::FirstCheck;
        launched
    }

    /// The answers the daemon is handed once it answers.
    pub fn answers(&self) -> Answers {
        let pick = self.pick();
        Answers {
            settings: SettingsChange {
                posture: Some(self.posture),
                rule_feed: Some(self.rule_feed),
                update_check: Some(self.update_check),
                ..SettingsChange::default()
            },
            engine: EngineChange {
                engine: Some(pick.engine()),
                ollama_model: match pick {
                    Pick::Ollama { model, .. } => Some(model),
                    _ => None,
                },
                ..EngineChange::default()
            },
        }
    }

    /// Whether screen 6 should ask the daemon for its status after
    /// `event`: while it waits, on the first Full Scan's ScanFinished, and
    /// on the Health every subscription opens with, in case that Scan
    /// finished before the app was listening.
    pub fn wants_status(&self, event: &StateEvent) -> bool {
        if self.screen != Screen::FirstCheck || self.checked.is_some() {
            return false;
        }
        match event {
            StateEvent::ScanFinished { summary } => summary.kind == ScanKind::Full,
            StateEvent::HealthChanged { .. } => true,
            _ => false,
        }
    }

    /// Takes the daemon's status on screen 6: once it carries a Full Scan
    /// that finished after the registration, the screen reports that
    /// Scan's Item count, the Items standing stopped, and the Health's one
    /// sentence. True when this completed the screen.
    pub fn take_status(&mut self, status: &Status) -> bool {
        if self.screen != Screen::FirstCheck || self.checked.is_some() {
            return false;
        }
        let (Some(registered_at), Some(scan)) = (self.registered_at, &status.scan) else {
            return false;
        };
        if scan.kind != ScanKind::Full || scan.finished_at() < registered_at {
            return false;
        }
        let stopped = status
            .findings
            .iter()
            .filter(|finding| finding.state == FindingState::Stopped)
            .map(|finding| crate::wording::simple(finding).title)
            .collect();
        self.checked = Some(Checked {
            items: scan.items,
            stopped,
            result: status.health.headline_in(self.posture),
        });
        true
    }

    /// Screen 4's view: the choices, and in the Developer Posture the
    /// others, from the engine answer; the Ollama confirmation and the
    /// Claude consent screen of the Settings pane.
    fn ai_view(&self) -> Value {
        let pick = self.pick();
        let mut state = self.look.clone().unwrap_or_else(unanswered);
        state.engine = pick.engine();
        if let Pick::Ollama { model, .. } = &pick {
            state.ollama_model = model.clone();
        }
        let developer = self.posture == Posture::Developer;
        let cards = ai_check::cards(&state, self.posture, true, &|_| Bar::Within);
        let card = |engine: JudgementEngine| {
            let mut card = cards
                .iter()
                .find(|card| card["engine"] == engine.as_str())
                .cloned()
                .unwrap_or(Value::Null);
            if engine == JudgementEngine::Apple {
                card["leaves"] = Value::from(APPLE_LINE);
            }
            card
        };
        let suggested_ollama = matches!(preselected(self.look.as_ref()), Pick::Ollama { .. });
        let mut choices = vec![card(JudgementEngine::Apple)];
        let mut others = Vec::new();
        if suggested_ollama {
            choices.insert(0, card(JudgementEngine::Ollama));
        } else if developer {
            others.push(card(JudgementEngine::Ollama));
        }
        choices.push(card(JudgementEngine::Off));
        if developer {
            others.push(card(JudgementEngine::Claude));
        }
        json!({
            "title": if developer { AI_JUDGEMENT_TITLE } else { AI_CHECK_TITLE },
            "choices": choices,
            "othersLine": (!others.is_empty()).then_some(OTHER_ENGINES),
            "others": others,
            "needsConfirmation": matches!(pick, Pick::Ollama { confirmed: false, .. }),
            "ollama": ai_check::ollama_confirmation(&state),
            "consent": ai_check::consent(&state, self.posture),
            "keySet": state.claude_key_ending.is_some(),
            "previewLater": PREVIEW_LATER,
            "later": AI_CHECK_LATER,
        })
    }

    /// Screen 5's view.
    fn background_view(&self) -> Value {
        let protected = self.protected();
        let developer = self.posture == Posture::Developer;
        let toggle = |key: &str, simple: &str, technical: &str, on: bool| {
            json!({
                "key": key,
                "label": if developer { technical } else { simple },
                "on": on,
            })
        };
        json!({
            "lines": BACKGROUND_LINES,
            "disclosure": BACKGROUND_DISCLOSURE,
            "toggles": [
                toggle("rule_feed", "Fetch newer detection rules", "Rule Feed", self.rule_feed),
                toggle(
                    "update_check",
                    "Check for app updates",
                    "App update check",
                    self.update_check
                ),
            ],
            "protected": (!protected.is_empty()).then(|| json!({
                "line": protected_line(&protected),
                "button": LOOK_THERE,
                "sent": self.looked_there.then_some(LOOK_THERE_SENT),
            })),
            "button": TURN_ON,
        })
    }

    /// Screen 6's view.
    fn first_view(&self) -> Value {
        match &self.checked {
            None => json!({
                "title": FIRST_CHECK_WAITING_TITLE,
                "waiting": FIRST_CHECK_WAITING,
            }),
            Some(checked) => json!({
                "title": FIRST_CHECK_TITLE,
                "items": match checked.items {
                    1 => "AgentSweep checked 1 item.".to_string(),
                    n => format!("AgentSweep checked {n} items."),
                },
                "baseline": BASELINE_LINE,
                "stoppedLine": match checked.stopped.len() {
                    0 => NOTHING_STOPPED.to_string(),
                    1 => "AgentSweep stopped 1 item before an agent could use it:".to_string(),
                    n => format!("AgentSweep stopped {n} items before an agent could use them:"),
                },
                "stopped": checked.stopped,
                "result": checked.result,
                "button": DONE,
            }),
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
            "ai": self.ai_view(),
            "background": self.background_view(),
            "first": self.first_view(),
        })
    }
}

/// The requests the hand-over sends, which [`Asking`] carries in the app
/// and a test fakes.
pub trait SettingsLink {
    /// Moves the choices in `change` and answers where they all stand.
    fn change_settings(&self, change: &SettingsChange) -> Result<SettingsState, ClientError>;

    /// Hands the Claude API key to the daemon.
    fn set_claude_key(&self, key: ClaudeKey) -> Result<EngineState, ClientError>;

    /// Moves the AI Judgement choices in `change`.
    fn change_engine(&self, change: &EngineChange) -> Result<EngineState, ClientError>;
}

impl SettingsLink for Asking {
    fn change_settings(&self, change: &SettingsChange) -> Result<SettingsState, ClientError> {
        Asking::change_settings(self, change)
    }

    fn set_claude_key(&self, key: ClaudeKey) -> Result<EngineState, ClientError> {
        Asking::set_claude_key(self, key)
    }

    fn change_engine(&self, change: &EngineChange) -> Result<EngineState, ClientError> {
        Asking::change_engine(self, change)
    }
}

/// What one request of the hand-over came to.
enum Sent<T> {
    /// The daemon took it.
    Taken(T),
    /// The daemon answered with a refusal; asking again would not change it.
    Refused,
    /// No daemon answered; keep it for the next try.
    Unanswered,
}

fn sent<T>(answer: Result<T, ClientError>) -> Sent<T> {
    match answer {
        Ok(taken) => Sent::Taken(taken),
        Err(ClientError::Request(_) | ClientError::Refused(_)) => Sent::Refused,
        Err(_) => Sent::Unanswered,
    }
}

/// The answers held in memory until a daemon answers: the settings, the
/// Claude API key when one was typed on the consent screen, and the engine.
/// The key is never written anywhere by the app; it is dropped, which wipes
/// it, once the daemon took it or refused it.
#[derive(Debug, Default)]
pub struct Handover {
    settings: Option<SettingsChange>,
    key: Option<ClaudeKey>,
    engine: Option<EngineChange>,
}

impl Handover {
    /// Holds `answers` for the daemon, in place of any held before.
    pub fn hold(&mut self, answers: Answers) {
        self.settings = Some(answers.settings);
        self.engine = Some(answers.engine);
    }

    /// Holds the Claude API key typed on the consent screen, in place of
    /// any held before.
    pub fn hold_key(&mut self, key: ClaudeKey) {
        self.key = Some(key);
    }

    /// True while answers wait for a daemon.
    pub fn is_pending(&self) -> bool {
        self.settings.is_some() || self.key.is_some() || self.engine.is_some()
    }

    /// Hands the held answers to the daemon through `link`, once, in order:
    /// the settings (so the Posture is in force before the engine is
    /// chosen), the key, then the engine. A daemon that does not answer
    /// keeps what is left for the next try; one that answers, with the
    /// choices or with a refusal asking again would not change, takes each
    /// off the hand-over. Answers with the settings the daemon holds
    /// afterwards, when it took them.
    pub fn deliver(&mut self, link: &dyn SettingsLink) -> Option<SettingsState> {
        let mut state = None;
        if let Some(change) = &self.settings {
            match sent(link.change_settings(change)) {
                Sent::Taken(taken) => state = Some(taken),
                Sent::Refused => {}
                Sent::Unanswered => return None,
            }
            self.settings = None;
        }
        if let Some(key) = &self.key {
            if let Sent::Unanswered = sent(link.set_claude_key(key.clone())) {
                return state;
            }
            self.key = None;
        }
        if let Some(change) = &self.engine {
            if let Sent::Unanswered = sent(link.change_engine(change)) {
                return state;
            }
            self.engine = None;
        }
        state
    }
}

/// The engine answer screen 4 preselects from before any daemon runs, taken
/// on this Mac the way the daemon takes it: Ollama asked at its default
/// loopback address (nothing leaves the Mac) and the Apple judgement helper
/// beside the app asked for its `check`. The real Mac only; the suite never
/// calls it.
pub fn look_here() -> EngineState {
    let mut state = unanswered();
    state.ollama = agentsweep_core::settings::OllamaAddress::parse(DEFAULT_OLLAMA_ADDRESS)
        .ok()
        .map(|address| agentsweep_core::ollama::OllamaClient::new(&address).presence());
    state.apple = Some(
        match agentsweep_core::apple_engine::AppleHelper::beside_this_executable() {
            Some(helper) => helper.check(),
            None => AppleAvailability::Unavailable {
                reason: agentsweep_core::apple::HELPER_MISSING.to_string(),
            },
        },
    );
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::io;

    use agentsweep_core::finding::Category;
    use agentsweep_core::health::Health;
    use agentsweep_core::item::Kind;
    use agentsweep_core::ollama::OllamaModel;
    use agentsweep_core::state::{ScanSummary, Trigger};

    use crate::inventory::{Found, OWN_LISTS};
    use crate::supervision::ServiceState;
    use crate::supervision::tests::Recorded;

    fn inventory() -> Inventory {
        Inventory {
            agents: vec![Found {
                agent: "codex",
                name: "Codex",
                version: None,
                projects: 2,
                not_read: &["the cloud enterprise bundle", "the MDM managed preference"],
            }],
            protected: Default::default(),
        }
    }

    fn in_documents() -> Inventory {
        let mut inventory = inventory();
        inventory.protected.insert(LocationClass::Documents);
        inventory
    }

    fn moment(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a readable moment")
    }

    fn look(ollama: Option<OllamaPresence>, apple: Option<AppleAvailability>) -> EngineState {
        EngineState {
            ollama,
            apple,
            ..unanswered()
        }
    }

    fn apple_available() -> Option<AppleAvailability> {
        Some(AppleAvailability::Available {
            model_version: "26.6.2 (25G83)".to_string(),
            context_size: Some(4096),
        })
    }

    fn apple_off() -> Option<AppleAvailability> {
        Some(AppleAvailability::Unavailable {
            reason: "apple_intelligence_not_enabled".to_string(),
        })
    }

    fn ollama_with(models: &[(&str, &str, bool)]) -> Option<OllamaPresence> {
        Some(OllamaPresence::Running {
            version: "0.12.6".to_string(),
            models: models
                .iter()
                .map(|(name, size, large_enough)| OllamaModel {
                    name: name.to_string(),
                    digest: "0000".to_string(),
                    parameter_size: size.to_string(),
                    large_enough: *large_enough,
                })
                .collect(),
        })
    }

    /// A wizard moved on to `screen`, in `posture`.
    fn on(screen: Screen, posture: Posture, inventory: Inventory) -> Wizard {
        let mut wizard = Wizard::new(inventory);
        wizard.choose(posture);
        while wizard.screen() != screen {
            assert_eq!(wizard.forward(), Step::Moved, "{:?}", wizard.screen());
        }
        wizard
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
        assert_eq!(wizard.screen(), Screen::AiCheck);
        assert_eq!(wizard.forward(), Step::Moved);
        assert_eq!(wizard.screen(), Screen::Background);
        assert_eq!(wizard.forward(), Step::Register);
        assert_eq!(wizard.screen(), Screen::Background);
        wizard.back();
        assert_eq!(wizard.screen(), Screen::AiCheck);

        assert_eq!(wizard.answers().settings.posture, Some(Posture::Developer));
    }

    #[test]
    fn the_view_carries_the_screen_its_words_and_the_answer() {
        let mut wizard = Wizard::new(inventory());
        let view = wizard.to_value();
        assert_eq!(view["screen"], "welcome");
        assert_eq!(view["back"], false);
        assert_eq!(view["steps"], 6);
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

    fn selected(view: &Value) -> Vec<String> {
        let ai = &view["ai"];
        let mut all: Vec<&Value> = ai["choices"].as_array().expect("choices").iter().collect();
        all.extend(ai["others"].as_array().expect("others"));
        all.into_iter()
            .filter(|card| card["selected"] == true)
            .map(|card| card["engine"].as_str().expect("an engine").to_string())
            .collect()
    }

    fn engines(view: &Value, list: &str) -> Vec<String> {
        view["ai"][list]
            .as_array()
            .expect("a list")
            .iter()
            .map(|card| card["engine"].as_str().expect("an engine").to_string())
            .collect()
    }

    /// Screen 4 preselects the local-first suggestion from the engine
    /// answer: Apple when it is available, Ollama when a model of 4B or more
    /// is present (a smaller one counts as absent), Off otherwise, and never
    /// Claude. Ollama and Claude are offered in the Developer Posture only,
    /// unless Ollama is itself the suggestion.
    #[test]
    fn screen_four_preselects_the_local_first_suggestion_and_never_claude() {
        // Apple available, no Ollama: Apple, with the spec's sentence.
        let mut wizard = on(Screen::AiCheck, Posture::Simple, inventory());
        assert_eq!(wizard.pick(), Pick::Off, "nothing answered yet");
        wizard.look(look(Some(OllamaPresence::Absent), apple_available()));
        assert_eq!(wizard.pick(), Pick::Apple);
        let view = wizard.to_value();
        assert_eq!(view["ai"]["title"], AI_CHECK_TITLE);
        assert_eq!(selected(&view), vec!["apple"]);
        assert_eq!(engines(&view, "choices"), vec!["apple", "off"]);
        assert_eq!(view["ai"]["choices"][0]["leaves"], APPLE_LINE);
        assert!(
            engines(&view, "others").is_empty(),
            "Simple offers no others"
        );
        assert_eq!(view["ai"]["othersLine"], Value::Null);

        // The Developer Posture adds the way to choose Ollama or Claude.
        wizard.choose(Posture::Developer);
        let view = wizard.to_value();
        assert_eq!(view["ai"]["title"], AI_JUDGEMENT_TITLE);
        assert_eq!(engines(&view, "others"), vec!["ollama", "claude"]);
        assert_eq!(view["ai"]["othersLine"], OTHER_ENGINES);
        assert_eq!(selected(&view), vec!["apple"]);

        // A 4B model pulled: Ollama, whatever Apple says, awaiting its one
        // confirmation, and shown as a choice even in Simple.
        for apple in [apple_available(), apple_off()] {
            let mut wizard = on(Screen::AiCheck, Posture::Simple, inventory());
            wizard.look(look(
                ollama_with(&[("qwen3:1.7b", "1.7B", false), ("qwen3:4b", "4.0B", true)]),
                apple,
            ));
            assert_eq!(
                wizard.pick(),
                Pick::Ollama {
                    model: "qwen3:4b".to_string(),
                    confirmed: false
                }
            );
            let view = wizard.to_value();
            assert_eq!(selected(&view), vec!["ollama"]);
            assert_eq!(engines(&view, "choices"), vec!["ollama", "apple", "off"]);
            assert_eq!(view["ai"]["needsConfirmation"], true);
            assert!(
                view["ai"]["ollama"]["question"]
                    .as_str()
                    .expect("the confirmation")
                    .contains("qwen3:4b")
            );
        }

        // Only a small model and Apple switched off: Off, never Claude.
        let mut wizard = on(Screen::AiCheck, Posture::Developer, inventory());
        wizard.look(look(
            ollama_with(&[("qwen3:1.7b", "1.7B", false)]),
            apple_off(),
        ));
        assert_eq!(wizard.pick(), Pick::Off);
        let view = wizard.to_value();
        assert_eq!(selected(&view), vec!["off"]);
        let apple = &view["ai"]["choices"][0];
        assert_eq!(apple["engine"], "apple");
        assert_eq!(apple["enabled"], false, "Apple cannot be chosen here");
        assert!(wizard.choose_engine(JudgementEngine::Apple).is_err());
        assert!(wizard.choose_engine(JudgementEngine::Ollama).is_err());
        assert!(wizard.choose_engine(JudgementEngine::Claude).is_err());
        assert_eq!(wizard.answers().engine.engine, Some(JudgementEngine::Off));
    }

    /// Ollama needs its one confirmation before Next moves on; once given,
    /// the engine request names the model. Claude is chosen through the
    /// consent screen only.
    #[test]
    fn ollama_needs_its_confirmation_and_claude_its_consent() {
        let mut wizard = on(Screen::AiCheck, Posture::Developer, inventory());
        wizard.look(look(
            ollama_with(&[("qwen3:8b", "8.2B", true)]),
            apple_available(),
        ));
        assert_eq!(wizard.forward(), Step::ConfirmOllama);
        assert_eq!(wizard.screen(), Screen::AiCheck);
        wizard.confirm_ollama();
        assert_eq!(wizard.forward(), Step::Moved);
        assert_eq!(wizard.screen(), Screen::Background);
        let engine = wizard.answers().engine;
        assert_eq!(engine.engine, Some(JudgementEngine::Ollama));
        assert_eq!(engine.ollama_model.as_deref(), Some("qwen3:8b"));

        wizard.back();
        wizard.choose_engine(JudgementEngine::Off).expect("Off");
        assert_eq!(wizard.answers().engine.engine, Some(JudgementEngine::Off));
        assert_eq!(wizard.answers().engine.ollama_model, None);
        wizard.agree_to_claude();
        assert_eq!(wizard.pick(), Pick::Claude);
        assert_eq!(
            wizard.answers().engine.engine,
            Some(JudgementEngine::Claude)
        );
        assert_eq!(selected(&wizard.to_value()), vec!["claude"]);
    }

    /// Screen 5 names the protected location only when the Inventory found
    /// a registered project in one, and its button sends check-now once.
    #[test]
    fn screen_five_offers_the_protected_location_line_only_when_needed_and_sends_once() {
        let mut wizard = on(Screen::Background, Posture::Simple, inventory());
        let view = wizard.to_value();
        assert_eq!(view["background"]["protected"], Value::Null);
        assert_eq!(view["background"]["lines"][1], BACKGROUND_LINES[1]);
        assert_eq!(view["background"]["disclosure"], BACKGROUND_DISCLOSURE);
        assert_eq!(view["background"]["button"], TURN_ON);
        assert!(!wizard.look_there(), "no line, no check-now");

        let mut wizard = on(Screen::AiCheck, Posture::Simple, in_documents());
        assert!(!wizard.look_there(), "only on screen 5");
        wizard.forward();
        let view = wizard.to_value();
        assert_eq!(
            view["background"]["protected"]["line"],
            "Some of your projects are in Documents. macOS will ask once whether AgentSweep may \
             look there."
        );
        assert_eq!(view["background"]["protected"]["sent"], Value::Null);
        assert!(wizard.look_there());
        assert!(!wizard.look_there(), "check-now goes once");
        assert!(!wizard.look_there());
        assert_eq!(
            wizard.to_value()["background"]["protected"]["sent"],
            LOOK_THERE_SENT
        );

        assert_eq!(
            protected_line(&[LocationClass::Desktop, LocationClass::Downloads]),
            "Some of your projects are on the Desktop and in Downloads. macOS will ask once \
             whether AgentSweep may look there."
        );
    }

    /// A stand-in for the link to the daemon: it does not answer until told
    /// to, and records every request it was asked.
    #[derive(Default)]
    struct FakeLink {
        answering: RefCell<bool>,
        refuse_key: bool,
        settings: RefCell<Vec<SettingsChange>>,
        keys: RefCell<Vec<String>>,
        engines: RefCell<Vec<EngineChange>>,
    }

    fn unreachable() -> ClientError {
        ClientError::Unreachable(io::Error::from(io::ErrorKind::NotFound))
    }

    impl SettingsLink for FakeLink {
        fn change_settings(&self, change: &SettingsChange) -> Result<SettingsState, ClientError> {
            if !*self.answering.borrow() {
                return Err(unreachable());
            }
            self.settings.borrow_mut().push(change.clone());
            let mut state = crate::settings_pane::tests::state(Posture::Simple, true, true);
            if let Some(posture) = change.posture {
                state.posture = posture;
            }
            if let Some(on) = change.rule_feed {
                state.rule_feed = on;
            }
            if let Some(on) = change.update_check {
                state.update_check = on;
            }
            Ok(state)
        }

        fn set_claude_key(&self, key: ClaudeKey) -> Result<EngineState, ClientError> {
            if !*self.answering.borrow() {
                return Err(unreachable());
            }
            self.keys.borrow_mut().push(key.ending());
            if self.refuse_key {
                return Err(ClientError::Request(
                    agentsweep_ipc::protocol::RequestError::new("malformed", "not a key"),
                ));
            }
            Ok(unanswered())
        }

        fn change_engine(&self, change: &EngineChange) -> Result<EngineState, ClientError> {
            if !*self.answering.borrow() {
                return Err(unreachable());
            }
            self.engines.borrow_mut().push(change.clone());
            Ok(unanswered())
        }
    }

    /// Leaving screen 5 registers the daemon and the login item once, and
    /// the held Posture, engine and toggles wait in memory while no daemon
    /// answers, then reach the settings and engine requests once, as soon
    /// as one does.
    #[test]
    fn leaving_screen_five_registers_once_and_hands_every_answer_over_once() {
        let services = Recorded::with(ServiceState::NotRegistered, ServiceState::NotRegistered);
        let mut wizard = on(Screen::AiCheck, Posture::Developer, in_documents());
        wizard.look(look(Some(OllamaPresence::Absent), apple_available()));
        wizard.forward();
        wizard.toggle("rule_feed", false).expect("a toggle");
        wizard.toggle("update_check", false).expect("a toggle");
        assert!(wizard.toggle("telemetry", true).is_err());

        // The protected-location button registers first, then leaving
        // registers nothing more.
        assert!(wizard.look_there());
        let now = moment("2026-10-19T10:00:00.000Z");
        assert!(wizard.register_once(&services, now).is_some());
        assert_eq!(
            services.calls(),
            vec!["register agent", "register login item"]
        );

        let mut handover = Handover::default();
        let link = FakeLink::default();
        assert!(handover.deliver(&link).is_none(), "nothing is held yet");
        assert_eq!(wizard.forward(), Step::Register);
        assert!(
            wizard
                .leave_background(&services, &mut handover, now)
                .is_none()
        );
        assert_eq!(wizard.screen(), Screen::FirstCheck);
        assert!(!wizard.offers_back());
        assert!(
            wizard
                .leave_background(&services, &mut handover, now)
                .is_none()
        );
        assert_eq!(
            services.calls(),
            vec!["register agent", "register login item"],
            "registered once"
        );

        assert!(handover.deliver(&link).is_none());
        assert!(handover.is_pending());
        assert!(link.settings.borrow().is_empty());

        *link.answering.borrow_mut() = true;
        let state = handover
            .deliver(&link)
            .expect("the daemon took the answers");
        assert_eq!(state.posture, Posture::Developer);
        assert!(!state.rule_feed);
        assert!(!handover.is_pending());
        assert!(handover.deliver(&link).is_none());
        let settings = link.settings.borrow();
        assert_eq!(settings.len(), 1);
        assert_eq!(settings[0].posture, Some(Posture::Developer));
        assert_eq!(settings[0].rule_feed, Some(false));
        assert_eq!(settings[0].update_check, Some(false));
        let engines = link.engines.borrow();
        assert_eq!(engines.len(), 1);
        assert_eq!(engines[0].engine, Some(JudgementEngine::Apple));
        assert!(link.keys.borrow().is_empty());
    }

    /// Leaving screen 5 without the protected-location button registers
    /// once too.
    #[test]
    fn leaving_screen_five_registers_the_daemon_and_the_login_item() {
        let services = Recorded::with(ServiceState::NotFound, ServiceState::NotRegistered);
        let mut wizard = on(Screen::Background, Posture::Simple, inventory());
        let mut handover = Handover::default();
        let launched = wizard
            .leave_background(&services, &mut handover, Timestamp::now())
            .expect("registered");
        assert!(launched.registered_agent && launched.registered_login_item);
        assert_eq!(
            services.calls(),
            vec!["register agent", "register login item"]
        );
        assert!(handover.is_pending());
    }

    /// A key typed on the consent screen is held until the daemon answers,
    /// handed over once before the engine is switched to Claude, and gone
    /// from the hand-over afterwards, refused or not.
    #[test]
    fn the_claude_key_is_handed_over_once_before_the_engine() {
        for refuse_key in [false, true] {
            let mut wizard = on(Screen::AiCheck, Posture::Developer, inventory());
            let mut handover = Handover::default();
            handover.hold_key(ClaudeKey::new("sk-ant-test-0000000000000000004f2a").expect("a key"));
            wizard.agree_to_claude();
            wizard.forward();
            wizard.leave_background(
                &Recorded::with(ServiceState::NotRegistered, ServiceState::NotRegistered),
                &mut handover,
                Timestamp::now(),
            );
            let link = FakeLink {
                refuse_key,
                ..FakeLink::default()
            };
            assert!(handover.deliver(&link).is_none());
            assert!(handover.is_pending(), "the key waits");
            *link.answering.borrow_mut() = true;
            handover.deliver(&link);
            assert!(!handover.is_pending());
            assert_eq!(*link.keys.borrow(), vec!["4f2a".to_string()]);
            assert_eq!(
                link.engines.borrow()[0].engine,
                Some(JudgementEngine::Claude)
            );
            handover.deliver(&link);
            assert_eq!(link.keys.borrow().len(), 1, "once");
            assert!(!format!("{handover:?}").contains("sk-ant"));
        }
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

    fn registered_wizard() -> Wizard {
        let mut wizard = on(Screen::Background, Posture::Simple, inventory());
        wizard.leave_background(
            &Recorded::with(ServiceState::NotRegistered, ServiceState::NotRegistered),
            &mut Handover::default(),
            moment("2026-10-19T10:00:00.000Z"),
        );
        wizard
    }

    /// Screen 6 waits for the first Full Scan after the registration, then
    /// reports its Item count, the Baseline sentence, what was stopped and
    /// the result; a Scan from before the registration does not count.
    #[test]
    fn screen_six_waits_for_the_first_scan_and_reports_what_was_stopped() {
        let mut wizard = registered_wizard();
        assert_eq!(wizard.forward(), Step::Waiting);
        let view = wizard.to_value();
        assert_eq!(view["screen"], "first");
        assert_eq!(view["first"]["waiting"], FIRST_CHECK_WAITING);

        let finished = StateEvent::ScanFinished {
            summary: Box::new(summary(ScanKind::Full, "2026-10-19T10:00:05.000Z", 42)),
        };
        let change = StateEvent::ScanFinished {
            summary: Box::new(summary(ScanKind::Change, "2026-10-19T10:00:05.000Z", 1)),
        };
        assert!(wizard.wants_status(&finished));
        assert!(!wizard.wants_status(&change));

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
        assert!(!wizard.take_status(&status));
        status.scan = Some(summary(ScanKind::Full, "2026-10-19T09:00:00.000Z", 7));
        assert!(!wizard.take_status(&status));
        assert_eq!(wizard.forward(), Step::Waiting);

        status.scan = Some(summary(ScanKind::Full, "2026-10-19T10:00:05.000Z", 42));
        assert!(wizard.take_status(&status));
        assert!(!wizard.wants_status(&finished), "done waiting");
        let view = wizard.to_value();
        assert_eq!(view["first"]["title"], FIRST_CHECK_TITLE);
        assert_eq!(view["first"]["items"], "AgentSweep checked 42 items.");
        assert_eq!(view["first"]["baseline"], BASELINE_LINE);
        assert_eq!(
            view["first"]["stoppedLine"],
            "AgentSweep stopped 1 item before an agent could use it:"
        );
        assert_eq!(
            view["first"]["stopped"][0],
            crate::wording::simple(&stopped).title
        );
        assert_eq!(view["first"]["result"], status.health.headline());
        assert_eq!(wizard.forward(), Step::Done);
    }

    #[test]
    fn screen_six_says_so_when_nothing_was_stopped() {
        let mut wizard = registered_wizard();
        let mut status = crate::findings::tests::status_of(Vec::new());
        status.health = Health::running();
        status.scan = Some(summary(ScanKind::Full, "2026-10-19T10:00:01.000Z", 1));
        assert!(wizard.take_status(&status));
        let view = wizard.to_value();
        assert_eq!(view["first"]["items"], "AgentSweep checked 1 item.");
        assert_eq!(view["first"]["stoppedLine"], NOTHING_STOPPED);
        assert_eq!(view["first"]["stopped"], json!([]));
    }
}
