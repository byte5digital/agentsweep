//! The AI Judgement choices and the Claude API key, as the daemon keeps them
//! (spec sections 4.4, 6.9 and 8.10).
//!
//! There is no engine yet; this is the choosing. The choices live in the
//! settings file. The Claude API key lives in the second item of the login
//! Keychain under the daemon's service and nowhere else: a client hands it
//! over once, the daemon stores it, and every answer names its last four
//! characters and nothing more. `ANTHROPIC_API_KEY` and `OLLAMA_HOST` are
//! never read.
//!
//! Exactly one engine is active, and only a request moves it: nothing in the
//! daemon switches an engine on or over by itself (ADR 0005). Every engine
//! change, enabled, switched, disabled, key added or key removed, appends one
//! `engine-changed` event to the Event Log carrying the engines and model ids
//! involved and no key material.

use std::sync::Arc;

use agentsweep_core::eventlog::{Action, Actor, Event};
use agentsweep_core::judged::Judge;
use agentsweep_core::judgement_request::Normalisation;
use agentsweep_core::keychain::{ClaudeKey, ClaudeKeyStore, MemoryClaudeKeyStore};
use agentsweep_core::ollama::OllamaClient;
use agentsweep_core::settings::{
    CLAUDE_MODEL, ChoiceRefused, JudgementEngine, JudgementSettings, OLLAMA_MODEL, OllamaAddress,
    SettingsFile, SettingsWriter, model_id,
};
use agentsweep_ipc::protocol::{EngineChange, EngineState, RequestError};

use crate::options::KeySourceChoice;
use crate::service::Daemon;
use crate::stores::open_the_event_log;

/// The store the Claude API key is kept in, by where the chain key comes from:
/// the login Keychain for the shipped daemon, the process's memory for a test
/// or a developer's hand run, which therefore never touches the Keychain.
pub fn claude_key_store(choice: KeySourceChoice) -> Box<dyn ClaudeKeyStore + Send + Sync> {
    match choice {
        KeySourceChoice::Memory => Box::new(MemoryClaudeKeyStore::empty()),
        KeySourceChoice::Keychain => login_keychain(),
    }
}

#[cfg(target_os = "macos")]
fn login_keychain() -> Box<dyn ClaudeKeyStore + Send + Sync> {
    Box::new(agentsweep_core::keychain::LoginKeychainClaudeKey::for_the_daemon())
}

/// There is no Keychain off macOS (spec section 6.1); a key that lives only as
/// long as the process is the honest stand-in.
#[cfg(not(target_os = "macos"))]
fn login_keychain() -> Box<dyn ClaudeKeyStore + Send + Sync> {
    Box::new(MemoryClaudeKeyStore::empty())
}

/// What one engine change was, as the Event Log names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EngineChangeKind {
    /// From off to an engine.
    Enabled,
    /// From one engine to another, or to another model of the same one.
    Switched,
    /// From an engine to off.
    Disabled,
    /// A Claude API key was handed over.
    KeyAdded,
    /// The Claude API key was removed.
    KeyRemoved,
}

impl EngineChangeKind {
    fn as_str(self) -> &'static str {
        match self {
            EngineChangeKind::Enabled => "enabled",
            EngineChangeKind::Switched => "switched",
            EngineChangeKind::Disabled => "disabled",
            EngineChangeKind::KeyAdded => "key-added",
            EngineChangeKind::KeyRemoved => "key-removed",
        }
    }
}

/// The engine change between two sets of choices, if there was one: the
/// active engine moved, or the active engine now runs another model.
fn engine_change(
    before: &JudgementSettings,
    after: &JudgementSettings,
) -> Option<EngineChangeKind> {
    match (before.engine, after.engine) {
        (from, to) if from == to => (to.is_on() && before.model_of(from) != after.model_of(to))
            .then_some(EngineChangeKind::Switched),
        (JudgementEngine::Off, _) => Some(EngineChangeKind::Enabled),
        (_, JudgementEngine::Off) => Some(EngineChangeKind::Disabled),
        _ => Some(EngineChangeKind::Switched),
    }
}

/// The `engine-changed` event for a change between two sets of choices. It
/// names the engines and model ids and nothing else.
fn engine_event(
    kind: EngineChangeKind,
    before: &JudgementSettings,
    after: &JudgementSettings,
) -> Event {
    let mut event = Event::new(Action::EngineChanged, Actor::User)
        .noting("change", kind.as_str())
        .noting("from_engine", before.engine.as_str())
        .noting("to_engine", after.engine.as_str());
    let from_model = before.model_of(before.engine);
    if !from_model.is_empty() {
        event = event.noting("from_model", from_model);
    }
    let to_model = after.model_of(after.engine);
    if !to_model.is_empty() {
        event = event.noting("to_model", to_model);
    }
    event
}

/// The `engine-changed` event for a key handed over or removed. It names the
/// engine the key belongs to and nothing of the key.
fn key_event(kind: EngineChangeKind) -> Event {
    Event::new(Action::EngineChanged, Actor::User)
        .noting("change", kind.as_str())
        .noting("engine", JudgementEngine::Claude.as_str())
}

/// A refused choice as the client is told it.
fn refused(refusal: ChoiceRefused) -> RequestError {
    RequestError::new("refused", refusal.to_string())
}

/// The Keychain could not be used. The detail is the Keychain's own error,
/// which never holds the key.
fn keychain_unavailable(error: impl std::fmt::Display) -> RequestError {
    RequestError::new(
        "keychain-unavailable",
        format!("the Claude API key could not be kept in the login Keychain: {error}"),
    )
}

impl Daemon {
    /// Where the AI Judgement choices stand, with the last four characters of
    /// the Claude API key when one is set.
    pub fn engine_state(&self) -> EngineState {
        let judgement = self.judgement();
        self.engine_state_of(&judgement, 0)
    }

    fn engine_state_of(&self, judgement: &JudgementSettings, recorded: u32) -> EngineState {
        let claude_key_ending = match self.claude_key.load() {
            Ok(key) => key.map(|key| key.ending()),
            Err(error) => {
                say!("the Claude API key could not be read: {error}");
                None
            }
        };
        EngineState {
            engine: judgement.engine,
            ollama_address: judgement.ollama_address.as_str().to_string(),
            ollama_model: judgement.ollama_model.clone(),
            claude_model: judgement.claude_model.clone(),
            claude_model_in_use: judgement.claude_model_in_use().to_string(),
            caps: judgement.caps,
            claude_key_ending,
            recorded,
            ollama: None,
        }
    }

    /// The active Judgement Engine as a Scan looks up its Verdicts under,
    /// None while AI Judgement is off. Requests normalise the home of the
    /// machine in force.
    pub fn judge_in_force(&self) -> Option<Judge> {
        let machine = self.machine_in_force();
        Judge::of_settings(&self.judgement(), Normalisation::of_home(machine.home()))
    }

    /// The AI Judgement choices as they stand.
    pub fn judgement(&self) -> JudgementSettings {
        self.settings
            .lock()
            .expect("the settings are not poisoned")
            .judgement
            .clone()
    }

    /// Moves the choices a request names, all of them or none: a choice
    /// refused leaves the settings file as it was. The Claude engine is
    /// refused while no key is set. An engine change appends one
    /// `engine-changed` event.
    ///
    /// The answer says whether Ollama runs at the address the settings now
    /// name and which models it has pulled, asked on that loopback address
    /// with a short timeout and after any write is done. AgentSweep never
    /// pulls a model and never starts Ollama.
    pub fn change_engine(
        self: &Arc<Daemon>,
        change: &EngineChange,
    ) -> Result<EngineState, RequestError> {
        let mut state = self.change_engine_choices(change)?;
        if self.detect_ollama {
            let address = self.judgement().ollama_address;
            state.ollama = Some(OllamaClient::new(&address).presence());
        }
        Ok(state)
    }

    fn change_engine_choices(
        self: &Arc<Daemon>,
        change: &EngineChange,
    ) -> Result<EngineState, RequestError> {
        if change.is_empty() {
            return Ok(self.engine_state());
        }
        // The write lock first, as every writer of the Event Log takes it, and
        // the settings under it, so two changes cannot interleave.
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let before = self.judgement();
        let mut after = before.clone();
        if let Some(address) = &change.ollama_address {
            after.ollama_address = OllamaAddress::parse(address).map_err(refused)?;
        }
        if let Some(model) = &change.ollama_model {
            after.ollama_model = model_id(OLLAMA_MODEL, model).map_err(refused)?;
        }
        if let Some(model) = &change.claude_model {
            after.claude_model = model_id(CLAUDE_MODEL, model).map_err(refused)?;
        }
        if let Some(items) = change.items_per_scan {
            after.caps.items_per_scan = items;
        }
        if let Some(items) = change.items_per_day {
            after.caps.items_per_day = items;
        }
        if let Some(cents) = change.cents_per_month {
            after.caps.cents_per_month = cents;
        }
        if let Some(engine) = change.engine {
            if engine == JudgementEngine::Claude
                && before.engine != JudgementEngine::Claude
                && !self.holds_a_claude_key()?
            {
                return Err(RequestError::new(
                    "claude-key-missing",
                    "the Claude engine needs a Claude API key first",
                ));
            }
            after.engine = engine;
        }
        if after == before {
            return Ok(self.engine_state_of(&after, 0));
        }
        self.write_judgement(&after)?;
        let recorded = match engine_change(&before, &after) {
            Some(kind) => self.record(&engine_event(kind, &before, &after)),
            None => 0,
        };
        self.tell_settings();
        Ok(self.engine_state_of(&after, recorded))
    }

    /// Keeps the Claude API key a client handed over in the Keychain, in
    /// place of any key held, and appends one `engine-changed` event. The
    /// engine is not switched on by it: that is the user's next choice.
    pub fn set_claude_key(
        self: &Arc<Daemon>,
        key: &ClaudeKey,
    ) -> Result<EngineState, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        self.claude_key.store(key).map_err(keychain_unavailable)?;
        say!("a Claude API key was handed over and kept in the login Keychain");
        let recorded = self.record(&key_event(EngineChangeKind::KeyAdded));
        self.tell_settings();
        Ok(self.engine_state_of(&self.judgement(), recorded))
    }

    /// Removes the Claude API key from the Keychain. An active Claude engine
    /// goes off with it (spec section 4.4): two events, the key removed and
    /// the engine disabled.
    pub fn remove_claude_key(self: &Arc<Daemon>) -> Result<EngineState, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let held = self.holds_a_claude_key()?;
        self.claude_key.forget().map_err(keychain_unavailable)?;
        let mut recorded = 0;
        if held {
            say!("the Claude API key was removed from the login Keychain");
            recorded += self.record(&key_event(EngineChangeKind::KeyRemoved));
        }
        let before = self.judgement();
        if before.engine == JudgementEngine::Claude {
            let after = JudgementSettings {
                engine: JudgementEngine::Off,
                ..before.clone()
            };
            self.write_judgement(&after)?;
            recorded += self.record(&engine_event(EngineChangeKind::Disabled, &before, &after));
        }
        if held || before.engine == JudgementEngine::Claude {
            self.tell_settings();
        }
        Ok(self.engine_state_of(&self.judgement(), recorded))
    }

    /// Whether the Keychain holds a Claude API key. The key itself is dropped,
    /// and wiped, at once.
    fn holds_a_claude_key(&self) -> Result<bool, RequestError> {
        self.claude_key
            .load()
            .map(|key| key.is_some())
            .map_err(keychain_unavailable)
    }

    /// Writes the choices to the settings file and takes them in force. A
    /// settings file that could not be read is written over here, as the
    /// Rule Feed toggle does: the user has just made the choice it holds.
    fn write_judgement(&self, judgement: &JudgementSettings) -> Result<(), RequestError> {
        let mut settings = self.settings.lock().expect("the settings are not poisoned");
        let mut next = settings.clone();
        next.judgement = judgement.clone();
        let file = SettingsFile::in_data_directory(&self.directory);
        SettingsWriter::write(&file, &next).map_err(|error| {
            say!("the settings file could not be written: {error}");
            RequestError::new("not-written", "the choice could not be written down")
        })?;
        *settings = next;
        drop(settings);
        let cleared = {
            let mut health = self.health.lock().expect("the health is not poisoned");
            std::mem::replace(&mut health.settings_unreadable, false)
        };
        if cleared {
            self.tell_health();
        }
        Ok(())
    }

    /// Appends one event to the Event Log under the write lock the caller
    /// holds, and answers how many were appended: one, or none when the log
    /// could not be written, which is said in the daemon's own log.
    fn record(&self, event: &Event) -> u32 {
        let written = open_the_event_log(&self.directory, &*self.keys)
            .and_then(|(mut writer, _)| writer.append(event));
        match written {
            Ok(_) => {
                say!(
                    "the Judgement Engine change was recorded: {}",
                    event.detail.get("change").map(String::as_str).unwrap_or("")
                );
                1
            }
            Err(error) => {
                say!("the Judgement Engine change could not be recorded: {error}");
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(engine: JudgementEngine) -> JudgementSettings {
        JudgementSettings {
            engine,
            ollama_model: "qwen3:8b".to_string(),
            ..JudgementSettings::default()
        }
    }

    #[test]
    fn enabling_switching_and_disabling_are_told_apart() {
        let off = with(JudgementEngine::Off);
        let apple = with(JudgementEngine::Apple);
        let ollama = with(JudgementEngine::Ollama);
        assert_eq!(engine_change(&off, &apple), Some(EngineChangeKind::Enabled));
        assert_eq!(
            engine_change(&apple, &ollama),
            Some(EngineChangeKind::Switched)
        );
        assert_eq!(
            engine_change(&ollama, &off),
            Some(EngineChangeKind::Disabled)
        );
        assert_eq!(engine_change(&apple, &apple), None);
        assert_eq!(engine_change(&off, &off), None);
    }

    /// Another model for the active engine changes what judges the Items, so
    /// it is a switch; another model for an engine that is not active is not.
    #[test]
    fn another_model_is_a_switch_only_for_the_active_engine() {
        let ollama = with(JudgementEngine::Ollama);
        let other = JudgementSettings {
            ollama_model: "gemma3:12b".to_string(),
            ..ollama.clone()
        };
        assert_eq!(
            engine_change(&ollama, &other),
            Some(EngineChangeKind::Switched)
        );
        let apple = with(JudgementEngine::Apple);
        let apple_other = JudgementSettings {
            ollama_model: "gemma3:12b".to_string(),
            ..apple.clone()
        };
        assert_eq!(engine_change(&apple, &apple_other), None);
    }

    #[test]
    fn an_engine_event_names_the_engines_and_models_and_nothing_else() {
        let ollama = with(JudgementEngine::Ollama);
        let claude = with(JudgementEngine::Claude);
        let event = engine_event(EngineChangeKind::Switched, &ollama, &claude);
        assert_eq!(event.action, Action::EngineChanged);
        assert_eq!(event.actor, Actor::User);
        assert!(event.item_id.is_none());
        assert!(event.sensitive.is_empty());
        let detail: Vec<(&str, &str)> = event
            .detail
            .iter()
            .map(|(name, fact)| (name.as_str(), fact.as_str()))
            .collect();
        assert_eq!(
            detail,
            vec![
                ("change", "switched"),
                ("from_engine", "ollama"),
                ("from_model", "qwen3:8b"),
                ("to_engine", "claude"),
                ("to_model", "claude-sonnet-5"),
            ]
        );
    }

    #[test]
    fn a_key_event_names_the_claude_engine_and_nothing_of_the_key() {
        let event = key_event(EngineChangeKind::KeyAdded);
        assert!(event.sensitive.is_empty());
        assert_eq!(event.detail.len(), 2);
        assert_eq!(
            event.detail.get("change").map(String::as_str),
            Some("key-added")
        );
        assert_eq!(
            event.detail.get("engine").map(String::as_str),
            Some("claude")
        );
    }
}
