//! The AI check in the Settings pane (spec sections 4.4, 8.4 and 8.10).
//!
//! - **Four cards**: Apple on-device, Ollama on this Mac, Claude over the
//!   internet and Off, each with one line on what leaves the Mac. Exactly
//!   one is selected: the engine the daemon answered with. An engine outside
//!   the eval bar, or not measured, is shown disabled in the Simple Posture
//!   and enabled with a warning in the Developer Posture.
//! - **The Ollama confirmation** names the model the daemon reports and
//!   says Ollama is asked on this Mac only.
//! - **The Claude consent screen**: a what / to whom / when / cost table with
//!   the three caps, **Preview a request**, the key field and "I agree, turn
//!   it on". The key goes to the daemon once and the app keeps no copy of it:
//!   the field then reads "key set, ending in ..." with a way to remove it,
//!   which turns the engine off.
//! - **Advanced**: the Ollama address, refused here before it is sent when it
//!   is not on this Mac, and in the Developer Posture the Claude model id,
//!   labelled unsupported and outside the eval.
//! - The cap-reached line, and after every change a line saying it was
//!   recorded.
//!
//! The Simple Posture calls it the "AI check" and says it never decides
//! anything by itself (spec section 8.4). Every choice moves through the
//! daemon, which is the only writer of the settings and the only process
//! that touches the Keychain; the app never calls an engine.

use agentsweep_core::apple::AppleAvailability;
use agentsweep_core::keychain::ClaudeKey;
use agentsweep_core::ollama::OllamaPresence;
use agentsweep_core::settings::{
    CLAUDE_MODEL, CloudCaps, DEFAULT_CLAUDE_MODEL, DEFAULT_OLLAMA_ADDRESS, JudgementEngine,
    OLLAMA_MODEL, OllamaAddress, Posture, model_id,
};
use agentsweep_ipc::engine::{EngineChange, EngineState};
use agentsweep_ipc::preview::{PreviewOutcome, RequestPreview};
use serde_json::{Value, json};

use crate::asking::{Asking, refusal};

/// Where an engine stands against the eval bar of spec section 4.4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bar {
    /// Within the bar, or no bar reported for it.
    Within,
    /// Measured and outside the bar.
    Outside,
    /// No measurement for this engine and model.
    NotMeasured,
}

/// Where `engine` stands against the eval bar, as the daemon's engine
/// answer reports it. The answer reports no bar yet (the eval table lands
/// with the eval runs), so every engine reads as within it and nothing is
/// held back that the daemon would let through.
pub fn bar_of(_state: &EngineState, _engine: JudgementEngine) -> Bar {
    Bar::Within
}

/// What the Simple Posture says the AI check is.
pub const SIMPLE_INTRO: &str = "The AI check takes a second look at items AgentSweep's own \
     checks could not settle. It never decides anything by itself: what it finds is shown to \
     you, and nothing is moved because of it.";

/// What the Developer Posture says AI Judgement is.
pub const DEVELOPER_INTRO: &str = "T3 AI Judgement asks one Judgement Engine about Items in \
     the Ambiguous Band. A malicious Verdict raises a Finding with manual Quarantine only; it \
     never quarantines by itself.";

/// The cards in their order: engine, title, what leaves the Mac.
pub const CARDS: [(JudgementEngine, &str, &str); 4] = [
    (
        JudgementEngine::Apple,
        "Apple on-device",
        "Nothing leaves your Mac: your Mac's built-in AI looks at the item.",
    ),
    (
        JudgementEngine::Ollama,
        "Ollama on this Mac",
        "Nothing leaves your Mac: Ollama is asked on this Mac only.",
    ),
    (
        JudgementEngine::Claude,
        "Claude over the internet",
        "The item, with passwords, tokens and your user name taken out, is sent to Anthropic \
         under your own API key.",
    ),
    (
        JudgementEngine::Off,
        "Off",
        "Nothing is checked by AI, and nothing leaves your Mac.",
    ),
];

/// Why an engine outside the bar is not offered in the Simple Posture.
pub const OUTSIDE_SIMPLE: &str = "Not offered: in AgentSweep's tests it called too many \
     harmless items malicious.";
/// The warning on an engine outside the bar in the Developer Posture.
pub const OUTSIDE_DEVELOPER: &str = "Outside the eval bar: more than 2 % false-malicious on the \
     benign set. You can still use it.";
/// Why an engine not measured is not offered in the Simple Posture.
pub const NOT_MEASURED_SIMPLE: &str = "Not offered: AgentSweep has not tested it yet.";
/// The warning on an engine not measured in the Developer Posture.
pub const NOT_MEASURED_DEVELOPER: &str = "Not measured: this engine and model have no eval \
     result. You can still use it.";

/// The heading of the consent screen.
pub const CONSENT_TITLE: &str = "Check unclear items with Claude";
/// The button that hands the key over and turns the engine on.
pub const AGREE: &str = "I agree, turn it on";
/// The link that shows a request.
pub const PREVIEW: &str = "Preview a request";
/// The button that removes the key.
pub const REMOVE_KEY: &str = "Remove the key";
/// The Claude model id field's label (Developer Posture only).
pub const CLAUDE_MODEL_LABEL: &str = "Claude model id (unsupported)";
/// What the Claude model id field says.
pub const CLAUDE_MODEL_LINE: &str = "Unsupported and outside the eval: AgentSweep measured only \
     its default model. Leave it empty to use the default.";
/// What the model price line says when the model in use has no price.
pub const UNPRICED_LINE: &str = "AgentSweep does not know this model's price, so every request \
     is counted at the price of the most expensive Claude model.";

/// The line under the key field once a key is set.
pub fn key_set_line(ending: &str) -> String {
    format!("Key set, ending in …{ending}")
}

/// A sum of cents in dollars, without cents when there are none.
pub fn dollars(cents: u64) -> String {
    match cents % 100 {
        0 => format!("${}", cents / 100),
        rest => format!("${}.{rest:02}", cents / 100),
    }
}

/// The three caps in one sentence.
pub fn caps_line(caps: &CloudCaps) -> String {
    format!(
        "AgentSweep stops at {} items per check, {} items per day and {} per month.",
        caps.items_per_scan,
        caps.items_per_day,
        dollars(u64::from(caps.cents_per_month))
    )
}

/// The model of a running Ollama the confirmation names: the one the
/// settings already name, else the first model of 4B or more Ollama
/// reports. None when the daemon reports neither.
pub fn ollama_model(state: &EngineState) -> Option<String> {
    if !state.ollama_model.is_empty() {
        return Some(state.ollama_model.clone());
    }
    match &state.ollama {
        Some(OllamaPresence::Running { models, .. }) => models
            .iter()
            .find(|model| model.large_enough)
            .map(|model| model.name.clone()),
        _ => None,
    }
}

/// Why the Ollama card cannot be chosen, when it cannot.
fn ollama_reason(state: &EngineState) -> Option<&'static str> {
    if ollama_model(state).is_some() {
        return None;
    }
    Some(match &state.ollama {
        Some(OllamaPresence::Absent) => "Ollama is not running on this Mac.",
        Some(OllamaPresence::Running { .. }) => {
            "Ollama has no model of 4B or more. AgentSweep never downloads one."
        }
        None => "AgentSweep has not seen Ollama on this Mac.",
    })
}

/// Why the Apple card cannot be chosen, when the daemon said it cannot.
fn apple_reason(state: &EngineState, posture: Posture) -> Option<String> {
    let Some(AppleAvailability::Unavailable { reason }) = &state.apple else {
        return None;
    };
    let sentence = match reason.as_str() {
        "apple_intelligence_not_enabled" => {
            "Apple Intelligence is switched off in System Settings."
        }
        "device_not_eligible" => "This Mac cannot run Apple's on-device model.",
        "model_not_ready" => "Apple's on-device model is not ready yet. Try again later.",
        _ => "Apple's on-device model is not available on this Mac.",
    };
    Some(match posture {
        Posture::Developer => format!("{sentence} ({reason})"),
        Posture::Simple => sentence.to_string(),
    })
}

/// One card as the window renders it.
fn card(
    state: &EngineState,
    posture: Posture,
    available: bool,
    bar: Bar,
    (engine, title, leaves): (JudgementEngine, &str, &str),
) -> Value {
    let developer = posture == Posture::Developer;
    let mut reason: Option<String> = match engine {
        JudgementEngine::Apple => apple_reason(state, posture),
        JudgementEngine::Ollama => ollama_reason(state).map(str::to_string),
        JudgementEngine::Claude | JudgementEngine::Off => None,
    };
    let mut warning: Option<&str> = None;
    if reason.is_none() && engine.is_on() {
        match (bar, developer) {
            (Bar::Within, _) => {}
            (Bar::Outside, false) => reason = Some(OUTSIDE_SIMPLE.to_string()),
            (Bar::Outside, true) => warning = Some(OUTSIDE_DEVELOPER),
            (Bar::NotMeasured, false) => reason = Some(NOT_MEASURED_SIMPLE.to_string()),
            (Bar::NotMeasured, true) => warning = Some(NOT_MEASURED_DEVELOPER),
        }
    }
    let ask = match engine {
        JudgementEngine::Ollama => "ollama",
        JudgementEngine::Claude => "claude",
        JudgementEngine::Apple | JudgementEngine::Off => "choose",
    };
    json!({
        "engine": engine.as_str(),
        "title": title,
        "leaves": leaves,
        "selected": state.engine == engine,
        "enabled": available && reason.is_none(),
        "reason": reason,
        "warning": warning,
        "ask": ask,
    })
}

/// The four cards, from the daemon's engine answer, the Posture in force,
/// whether the daemon can take a choice, and where each engine stands
/// against the eval bar.
pub fn cards(
    state: &EngineState,
    posture: Posture,
    available: bool,
    bar: &dyn Fn(JudgementEngine) -> Bar,
) -> Vec<Value> {
    CARDS
        .iter()
        .map(|entry| card(state, posture, available, bar(entry.0), *entry))
        .collect()
}

/// The Ollama confirmation: the model the daemon reports and that Ollama
/// is asked on this Mac only. None when no model can be named.
pub fn ollama_confirmation(state: &EngineState) -> Option<Value> {
    let model = ollama_model(state)?;
    Some(json!({
        "question": format!("Use Ollama with the model '{model}'?"),
        "lines": [
            format!(
                "AgentSweep asks Ollama at {} only, a loopback address on this Mac. Nothing \
                 leaves your Mac.",
                state.ollama_address
            ),
            "AgentSweep never downloads a model and never starts Ollama.".to_string(),
        ],
        "ok": "Use Ollama",
        "model": model,
    }))
}

/// The consent screen: the table, the caps, the preview link, the key
/// field and the button.
pub fn consent(state: &EngineState, posture: Posture) -> Value {
    let model = match posture {
        Posture::Developer => format!(" (model {})", state.claude_model_in_use),
        Posture::Simple => String::new(),
    };
    json!({
        "title": CONSENT_TITLE,
        "rows": [
            {
                "label": "What",
                "text": "One unclear item at a time: its kind and where it sits, the signs \
                         AgentSweep noticed, and its content with passwords, tokens and your \
                         user name taken out.",
            },
            {
                "label": "To whom",
                "text": format!("Anthropic, through the Claude API, under your own API key{model}."),
            },
            {
                "label": "When",
                "text": "Only for items AgentSweep's own checks could not settle, while it \
                         checks. Never for items it already decided.",
            },
            {
                "label": "Cost",
                "text": format!(
                    "Anthropic bills your account for each request. {}",
                    caps_line(&state.caps)
                ),
            },
        ],
        "caps": {
            "itemsPerScan": state.caps.items_per_scan,
            "itemsPerDay": state.caps.items_per_day,
            "perMonth": dollars(u64::from(state.caps.cents_per_month)),
        },
        "preview": PREVIEW,
        "keyLabel": "Your Claude API key",
        "keyLine": "AgentSweep keeps it in your login Keychain. This window does not keep it.",
        "agree": AGREE,
    })
}

/// The key the daemon holds, as the field shows it, or None.
fn key_view(state: &EngineState) -> Value {
    match &state.claude_key_ending {
        Some(ending) => json!({
            "set": true,
            "line": key_set_line(ending),
            "remove": REMOVE_KEY,
            "removeLine": "Removing the key turns the Claude AI check off.",
        }),
        None => json!({ "set": false }),
    }
}

/// The cloud lines: the cap-reached line, what the caps counted, and the
/// unpriced model line.
fn cloud_lines(state: &EngineState) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(notice) = &state.cloud_use.judgement_cap {
        lines.push(notice.line());
    }
    if state.engine == JudgementEngine::Claude || state.cloud_use.items_today > 0 {
        let cents = state.cloud_use.microdollars_this_month.div_ceil(10_000);
        lines.push(format!(
            "Today {} of {} items, this month {} of {}.",
            state.cloud_use.items_today,
            state.caps.items_per_day,
            dollars(cents),
            dollars(u64::from(state.caps.cents_per_month))
        ));
    }
    if !state.cloud_use.model_priced {
        lines.push(UNPRICED_LINE.to_string());
    }
    lines
}

/// The AI check's place under Advanced: the Ollama address, and in the
/// Developer Posture the Claude model id.
fn advanced(state: &EngineState, posture: Posture) -> Value {
    json!({
        "ollamaAddress": {
            "label": "Ollama address",
            "value": state.ollama_address,
            "default": DEFAULT_OLLAMA_ADDRESS,
            "line": "Ollama is asked on this Mac only: localhost or a loopback address such as \
                     127.0.0.1, and a port.",
        },
        "claudeModel": (posture == Posture::Developer).then(|| json!({
            "label": CLAUDE_MODEL_LABEL,
            "value": state.claude_model,
            "default": DEFAULT_CLAUDE_MODEL,
            "line": CLAUDE_MODEL_LINE,
        })),
    })
}

/// The AI check as the window renders it, or None before the daemon
/// answered.
pub fn view(
    state: Option<&EngineState>,
    posture: Posture,
    available: bool,
    bar: &dyn Fn(JudgementEngine) -> Bar,
) -> Value {
    let Some(state) = state else {
        return Value::Null;
    };
    let developer = posture == Posture::Developer;
    json!({
        "title": if developer { "AI Judgement" } else { "AI check" },
        "intro": if developer { DEVELOPER_INTRO } else { SIMPLE_INTRO },
        "available": available,
        "cards": cards(state, posture, available, bar),
        "ollama": ollama_confirmation(state),
        "consent": consent(state, posture),
        "key": key_view(state),
        "lines": cloud_lines(state),
        "advanced": advanced(state, posture),
    })
}

/// The line after an engine change the daemon answered: that it was
/// recorded, or that nothing changed.
pub fn recorded_line(state: &EngineState, posture: Posture) -> String {
    match (state.recorded, posture) {
        (0, _) => "Nothing changed.".to_string(),
        (_, Posture::Simple) => {
            "Done. The change was recorded and is listed in Activity.".to_string()
        }
        (1, Posture::Developer) => "Recorded in the Event Log.".to_string(),
        (n, Posture::Developer) => format!("Recorded in the Event Log ({n} events)."),
    }
}

/// The change one control of the AI check asks for, from what the window
/// sends: `{"engine": "apple"}`, `{"engine": "ollama", "model": "qwen3:8b"}`,
/// `{"ollama_address": "localhost:11434"}` or `{"claude_model": ""}`.
/// An Ollama address off this Mac and a malformed model id are refused here,
/// before anything is sent.
pub fn change_of(asked: &Value) -> Result<EngineChange, String> {
    let unknown = || "That is not a setting AgentSweep knows.".to_string();
    let refused = |reason: String| format!("Nothing was changed: {reason}.");
    let object = asked.as_object().ok_or_else(unknown)?;
    let mut change = EngineChange::default();
    if let Some(engine) = object.get("engine") {
        let engine = engine
            .as_str()
            .and_then(JudgementEngine::parse)
            .ok_or_else(unknown)?;
        change.engine = Some(engine);
        if engine == JudgementEngine::Ollama {
            let model = object.get("model").and_then(Value::as_str).unwrap_or("");
            let model = model_id(OLLAMA_MODEL, model).map_err(|why| refused(why.reason))?;
            if model.is_empty() {
                return Err(refused("Ollama needs a model".to_string()));
            }
            change.ollama_model = Some(model);
        }
    } else if let Some(address) = object.get("ollama_address") {
        let address = address.as_str().ok_or_else(unknown)?.trim();
        let address = match address {
            "" => DEFAULT_OLLAMA_ADDRESS.to_string(),
            typed => OllamaAddress::parse(typed)
                .map_err(|why| refused(why.reason))?
                .as_str()
                .to_string(),
        };
        change.ollama_address = Some(address);
    } else if let Some(model) = object.get("claude_model") {
        let model = model.as_str().ok_or_else(unknown)?;
        change.claude_model =
            Some(model_id(CLAUDE_MODEL, model.trim()).map_err(|why| refused(why.reason))?);
    }
    match change.is_empty() {
        true => Err(unknown()),
        false => Ok(change),
    }
}

/// A refusal as the AI check says it.
fn said(error: &agentsweep_ipc::ClientError) -> String {
    refusal(error).replace("Nothing was done", "Nothing was changed")
}

/// Overwrites the text of a typed key before its memory is given back.
fn wipe(mut typed: String) {
    // SAFETY: zero bytes are valid UTF-8, so the string stays a string.
    let bytes = unsafe { typed.as_mut_vec() };
    for byte in bytes.iter_mut() {
        // SAFETY: the pointer comes from a live, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

/// "I agree, turn it on": hands a typed key to the daemon once, when one was
/// typed, and turns the Claude engine on. The typed text is wiped and the
/// key dropped (and wiped) before this returns, so nothing of it stays in
/// the app. The answer counts every event both steps recorded.
pub fn turn_on_claude(asking: &Asking, typed: Option<String>) -> Result<EngineState, String> {
    let mut recorded = 0;
    if let Some(typed) = typed {
        let key = ClaudeKey::new(&typed);
        wipe(typed);
        if let Ok(key) = key {
            recorded += asking.set_claude_key(key).map_err(|e| said(&e))?.recorded;
        } else {
            return Err("Nothing was changed: that does not look like a Claude API key.".into());
        }
    }
    let mut state = asking
        .change_engine(&EngineChange {
            engine: Some(JudgementEngine::Claude),
            ..EngineChange::default()
        })
        .map_err(|e| said(&e))?;
    state.recorded += recorded;
    Ok(state)
}

/// Removes the Claude API key, which turns the Claude engine off.
pub fn remove_claude_key(asking: &Asking) -> Result<EngineState, String> {
    asking.remove_claude_key().map_err(|e| said(&e))
}

/// Moves one choice of the AI check through the daemon.
pub fn change(asking: &Asking, asked: &Value) -> Result<EngineState, String> {
    let change = change_of(asked)?;
    asking.change_engine(&change).map_err(|e| said(&e))
}

/// A request preview as the window shows it: the daemon's system prompt and
/// user turn verbatim, with what it measured, or that the Item is too large.
pub fn preview_view(preview: &RequestPreview) -> Value {
    let about = match preview.sample {
        true => "A sample item AgentSweep ships, as Claude would receive it.".to_string(),
        false => format!("The item {}, as Claude would receive it.", preview.item),
    };
    match &preview.outcome {
        PreviewOutcome::Request {
            system,
            user,
            prompt_version,
            tokens,
            budget,
            windowed,
            nonce,
        } => json!({
            "about": about,
            "system": system,
            "user": user,
            "nonce": nonce,
            "lines": [
                "Passwords, tokens and other secrets show only as <redacted:type:len>.",
                "The marker around the item is new for every request.",
                format!(
                    "Prompt version {prompt_version}, about {tokens} of {budget} tokens{}.",
                    if *windowed { ", cut to the parts around what was noticed" } else { "" }
                ),
            ],
            "tooLarge": false,
        }),
        PreviewOutcome::TooLarge { tokens, budget } => json!({
            "about": about,
            "system": Value::Null,
            "user": Value::Null,
            "nonce": Value::Null,
            "lines": [format!(
                "Too large to send: about {tokens} tokens, over the limit of {budget}. Nothing \
                 would be sent about it."
            )],
            "tooLarge": true,
        }),
    }
}

/// "Preview a request" for the Claude engine: one Item by id, or the sample
/// Item the consent screen shows.
pub fn preview(asking: &Asking, item: Option<&str>) -> Result<Value, String> {
    asking
        .preview_request(item, JudgementEngine::Claude)
        .map(|preview| preview_view(&preview))
        .map_err(|e| said(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::ollama::OllamaModel;
    use agentsweep_core::spend::{CapNotice, JudgementCap};
    use agentsweep_ipc::engine::CloudUse;

    fn state(engine: JudgementEngine) -> EngineState {
        EngineState {
            engine,
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

    fn running_ollama(models: &[(&str, bool)]) -> Option<OllamaPresence> {
        Some(OllamaPresence::Running {
            version: "0.12.6".to_string(),
            models: models
                .iter()
                .map(|(name, large_enough)| OllamaModel {
                    name: name.to_string(),
                    digest: "1111".to_string(),
                    parameter_size: "8B".to_string(),
                    large_enough: *large_enough,
                })
                .collect(),
        })
    }

    fn within(_: JudgementEngine) -> Bar {
        Bar::Within
    }

    fn by_engine<'v>(cards: &'v [Value], engine: &str) -> &'v Value {
        cards
            .iter()
            .find(|card| card["engine"] == engine)
            .unwrap_or_else(|| panic!("no card for {engine}"))
    }

    #[test]
    fn four_cards_in_order_each_saying_what_leaves_the_mac() {
        let cards = cards(
            &state(JudgementEngine::Apple),
            Posture::Simple,
            true,
            &within,
        );
        let engines: Vec<_> = cards.iter().map(|card| card["engine"].clone()).collect();
        assert_eq!(engines, ["apple", "ollama", "claude", "off"]);
        let titles: Vec<_> = cards.iter().map(|card| card["title"].clone()).collect();
        assert_eq!(
            titles,
            [
                "Apple on-device",
                "Ollama on this Mac",
                "Claude over the internet",
                "Off"
            ]
        );
        for card in &cards {
            assert!(!card["leaves"].as_str().expect("a line").is_empty());
        }
        assert!(
            cards[2]["leaves"]
                .as_str()
                .expect("a line")
                .contains("Anthropic")
        );
        assert_eq!(cards[0]["selected"], true);
        assert_eq!(
            cards.iter().filter(|card| card["selected"] == true).count(),
            1
        );
        assert_eq!(cards[0]["enabled"], true);
        assert_eq!(cards[3]["enabled"], true);
    }

    /// Spec section 4.4: an engine that misses the eval bar ships disabled
    /// in the Simple Posture; the Developer Posture can enable it with a
    /// warning. The same holds for an engine not measured.
    #[test]
    fn an_engine_outside_the_bar_is_disabled_in_simple_and_warned_in_developer() {
        let mut answer = state(JudgementEngine::Off);
        answer.ollama = running_ollama(&[("qwen3:8b", true)]);
        let bar = |engine: JudgementEngine| match engine {
            JudgementEngine::Ollama => Bar::Outside,
            JudgementEngine::Apple => Bar::NotMeasured,
            _ => Bar::Within,
        };

        let simple = cards(&answer, Posture::Simple, true, &bar);
        let ollama = by_engine(&simple, "ollama");
        assert_eq!(ollama["enabled"], false);
        assert_eq!(ollama["reason"], OUTSIDE_SIMPLE);
        assert_eq!(ollama["warning"], Value::Null);
        let apple = by_engine(&simple, "apple");
        assert_eq!(apple["enabled"], false);
        assert_eq!(apple["reason"], NOT_MEASURED_SIMPLE);
        assert_eq!(by_engine(&simple, "claude")["enabled"], true);

        let developer = cards(&answer, Posture::Developer, true, &bar);
        let ollama = by_engine(&developer, "ollama");
        assert_eq!(ollama["enabled"], true);
        assert_eq!(ollama["reason"], Value::Null);
        assert_eq!(ollama["warning"], OUTSIDE_DEVELOPER);
        let apple = by_engine(&developer, "apple");
        assert_eq!(apple["enabled"], true);
        assert_eq!(apple["warning"], NOT_MEASURED_DEVELOPER);
    }

    /// With the daemon away nothing can be chosen, and the engine in force
    /// still shows as selected.
    #[test]
    fn with_protection_off_no_card_can_be_chosen() {
        let cards = cards(
            &state(JudgementEngine::Apple),
            Posture::Simple,
            false,
            &within,
        );
        assert!(cards.iter().all(|card| card["enabled"] == false));
        assert_eq!(cards[0]["selected"], true);
    }

    #[test]
    fn apple_unavailable_says_why_and_the_developer_sees_the_reason() {
        let mut answer = state(JudgementEngine::Off);
        answer.apple = Some(AppleAvailability::Unavailable {
            reason: "apple_intelligence_not_enabled".to_string(),
        });
        let simple = cards(&answer, Posture::Simple, true, &within);
        assert_eq!(simple[0]["enabled"], false);
        assert_eq!(
            simple[0]["reason"],
            "Apple Intelligence is switched off in System Settings."
        );
        let developer = cards(&answer, Posture::Developer, true, &within);
        assert!(
            developer[0]["reason"]
                .as_str()
                .expect("a reason")
                .ends_with("(apple_intelligence_not_enabled)")
        );
    }

    /// Ollama can be chosen only with a model the daemon names: the one set,
    /// or the first of 4B or more it reports. A smaller model counts as
    /// none.
    #[test]
    fn the_ollama_confirmation_names_the_model_the_daemon_reports() {
        let mut answer = state(JudgementEngine::Off);
        answer.ollama = Some(OllamaPresence::Absent);
        assert_eq!(ollama_confirmation(&answer), None);
        let card = &cards(&answer, Posture::Simple, true, &within)[1];
        assert_eq!(card["enabled"], false);
        assert_eq!(card["reason"], "Ollama is not running on this Mac.");

        answer.ollama = running_ollama(&[("qwen3:1.7b", false)]);
        assert_eq!(ollama_confirmation(&answer), None);
        assert!(
            cards(&answer, Posture::Simple, true, &within)[1]["reason"]
                .as_str()
                .expect("a reason")
                .contains("4B")
        );

        answer.ollama = running_ollama(&[("qwen3:1.7b", false), ("qwen3:8b", true)]);
        let asked = ollama_confirmation(&answer).expect("a confirmation");
        assert_eq!(asked["model"], "qwen3:8b");
        assert_eq!(asked["question"], "Use Ollama with the model 'qwen3:8b'?");
        let first = asked["lines"][0].as_str().expect("a line");
        assert!(first.contains("127.0.0.1:11434"), "{first}");
        assert!(first.contains("loopback"), "{first}");
        assert_eq!(
            cards(&answer, Posture::Simple, true, &within)[1]["enabled"],
            true
        );

        answer.ollama_model = "llama3.1:8b".to_string();
        assert_eq!(
            ollama_confirmation(&answer).expect("a confirmation")["model"],
            "llama3.1:8b"
        );
    }

    /// A non-loopback Ollama address is refused before anything is sent.
    #[test]
    fn an_ollama_address_off_this_mac_is_refused_before_it_is_sent() {
        for address in [
            "192.168.1.20:11434",
            "ollama.example.invalid:11434",
            "0.0.0.0:11434",
        ] {
            let refused = change_of(&json!({ "ollama_address": address })).expect_err(address);
            assert!(refused.starts_with("Nothing was changed:"), "{refused}");
        }
        let taken = change_of(&json!({ "ollama_address": " localhost:11500 " })).expect("taken");
        assert_eq!(taken.ollama_address.as_deref(), Some("localhost:11500"));
        let cleared = change_of(&json!({ "ollama_address": "" })).expect("taken");
        assert_eq!(
            cleared.ollama_address.as_deref(),
            Some(DEFAULT_OLLAMA_ADDRESS)
        );
    }

    #[test]
    fn each_control_asks_for_its_own_engine_change() {
        assert_eq!(
            change_of(&json!({ "engine": "apple" })),
            Ok(EngineChange {
                engine: Some(JudgementEngine::Apple),
                ..EngineChange::default()
            })
        );
        assert_eq!(
            change_of(&json!({ "engine": "ollama", "model": "qwen3:8b" })),
            Ok(EngineChange {
                engine: Some(JudgementEngine::Ollama),
                ollama_model: Some("qwen3:8b".to_string()),
                ..EngineChange::default()
            })
        );
        assert!(change_of(&json!({ "engine": "ollama" })).is_err());
        assert_eq!(
            change_of(&json!({ "claude_model": "claude-custom-1" })),
            Ok(EngineChange {
                claude_model: Some("claude-custom-1".to_string()),
                ..EngineChange::default()
            })
        );
        assert!(
            change_of(
                &json!({ "claude_model": "sk-ant-api03-pasted-here-by-mistake-0000000000000000" })
            )
            .is_err()
        );
        assert!(change_of(&json!({ "engine": "typesafe" })).is_err());
        assert!(change_of(&json!({ "colour": "blue" })).is_err());
    }

    /// The consent screen is a what / to whom / when / cost table with the
    /// three caps.
    #[test]
    fn the_consent_screen_shows_the_table_and_the_three_caps() {
        let screen = consent(&state(JudgementEngine::Off), Posture::Simple);
        let labels: Vec<_> = screen["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .map(|row| row["label"].clone())
            .collect();
        assert_eq!(labels, ["What", "To whom", "When", "Cost"]);
        let cost = screen["rows"][3]["text"].as_str().expect("a cost");
        assert!(cost.contains("25 items per check"), "{cost}");
        assert!(cost.contains("200 items per day"), "{cost}");
        assert!(cost.contains("$5 per month"), "{cost}");
        assert!(
            screen["rows"][1]["text"]
                .as_str()
                .expect("a row")
                .contains("Anthropic")
        );
        assert_eq!(screen["caps"]["itemsPerScan"], 25);
        assert_eq!(screen["caps"]["itemsPerDay"], 200);
        assert_eq!(screen["caps"]["perMonth"], "$5");
        assert_eq!(screen["agree"], AGREE);
        assert_eq!(screen["preview"], PREVIEW);
        let developer = consent(&state(JudgementEngine::Off), Posture::Developer);
        assert!(
            developer["rows"][1]["text"]
                .as_str()
                .expect("a row")
                .contains("claude-sonnet-5")
        );
        assert_eq!(dollars(250), "$2.50");
        assert_eq!(dollars(1205), "$12.05");
    }

    #[test]
    fn a_set_key_shows_its_ending_and_a_way_to_remove_it() {
        let mut answer = state(JudgementEngine::Claude);
        let none = view(Some(&answer), Posture::Simple, true, &within);
        assert_eq!(none["key"]["set"], false);
        answer.claude_key_ending = Some("4f2a".to_string());
        let set = view(Some(&answer), Posture::Simple, true, &within);
        assert_eq!(set["key"]["set"], true);
        assert_eq!(set["key"]["line"], "Key set, ending in …4f2a");
        assert_eq!(set["key"]["remove"], REMOVE_KEY);
    }

    /// Spec section 8.4: "AI check" in the Simple Posture, with copy saying
    /// it never decides anything by itself.
    #[test]
    fn the_simple_posture_calls_it_the_ai_check_that_never_decides_by_itself() {
        let simple = view(
            Some(&state(JudgementEngine::Off)),
            Posture::Simple,
            true,
            &within,
        );
        assert_eq!(simple["title"], "AI check");
        assert!(SIMPLE_INTRO.contains("never decides anything by itself"));
        assert_eq!(simple["intro"], SIMPLE_INTRO);
        assert_eq!(simple["advanced"]["claudeModel"], Value::Null);
        assert_eq!(view(None, Posture::Simple, true, &within), Value::Null);
    }

    /// The Developer Posture's Claude model id field is labelled unsupported
    /// and outside the eval.
    #[test]
    fn the_developer_claude_model_field_is_labelled_unsupported() {
        let developer = view(
            Some(&state(JudgementEngine::Off)),
            Posture::Developer,
            true,
            &within,
        );
        let field = &developer["advanced"]["claudeModel"];
        assert_eq!(field["label"], CLAUDE_MODEL_LABEL);
        assert!(
            field["label"]
                .as_str()
                .expect("a label")
                .contains("unsupported")
        );
        assert!(
            field["line"]
                .as_str()
                .expect("a line")
                .contains("outside the eval")
        );
        assert_eq!(field["default"], DEFAULT_CLAUDE_MODEL);
        assert_eq!(
            developer["advanced"]["ollamaAddress"]["value"],
            "127.0.0.1:11434"
        );
    }

    #[test]
    fn the_cap_reached_line_and_the_unpriced_model_line_show() {
        let mut answer = state(JudgementEngine::Claude);
        answer.cloud_use = CloudUse {
            items_today: 200,
            microdollars_this_month: 4_200_001,
            model_priced: false,
            judgement_cap: Some(CapNotice {
                cap: JudgementCap::Day,
                waiting: 7,
            }),
        };
        let lines = view(Some(&answer), Posture::Simple, true, &within)["lines"].clone();
        assert_eq!(
            lines[0],
            "The AI check reached its limit for this scan. 7 items will be looked at next time."
        );
        assert_eq!(lines[1], "Today 200 of 200 items, this month $4.21 of $5.");
        assert_eq!(lines[2], UNPRICED_LINE);
        let quiet = view(
            Some(&state(JudgementEngine::Apple)),
            Posture::Simple,
            true,
            &within,
        );
        assert_eq!(quiet["lines"], json!([]));
    }

    #[test]
    fn every_engine_change_says_it_was_recorded() {
        let mut answer = state(JudgementEngine::Apple);
        answer.recorded = 1;
        assert!(recorded_line(&answer, Posture::Simple).contains("recorded"));
        assert_eq!(
            recorded_line(&answer, Posture::Developer),
            "Recorded in the Event Log."
        );
        answer.recorded = 2;
        assert_eq!(
            recorded_line(&answer, Posture::Developer),
            "Recorded in the Event Log (2 events)."
        );
        answer.recorded = 0;
        assert_eq!(recorded_line(&answer, Posture::Simple), "Nothing changed.");
    }

    /// The preview shows the daemon's request verbatim.
    #[test]
    fn the_preview_shows_the_request_verbatim() {
        let user =
            "<untrusted-abc>\n\"env\": {\"TOKEN\": \"<redacted:secret:23>\"}\n</untrusted-abc>";
        let shown = preview_view(&RequestPreview {
            engine: JudgementEngine::Claude,
            item: "sample".to_string(),
            sample: true,
            outcome: PreviewOutcome::Request {
                system: "You review.".to_string(),
                user: user.to_string(),
                nonce: "abc".to_string(),
                prompt_version: "3".to_string(),
                tokens: 120,
                budget: 32_000,
                windowed: false,
            },
        });
        assert_eq!(shown["user"], user);
        assert_eq!(shown["system"], "You review.");
        assert_eq!(shown["tooLarge"], false);
        let large = preview_view(&RequestPreview {
            engine: JudgementEngine::Claude,
            item: "x".to_string(),
            sample: false,
            outcome: PreviewOutcome::TooLarge {
                tokens: 50_000,
                budget: 32_000,
            },
        });
        assert_eq!(large["tooLarge"], true);
        assert_eq!(large["user"], Value::Null);
    }
}
