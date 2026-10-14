//! The Claude API engine: the opt-in cloud Judgement Engine of spec section
//! 4.4, and the third and last outbound request of the egress promise (spec
//! section 1.1).
//!
//! The module exists only in a build with the `daemon` feature, like the
//! Keychain, so neither build of the CLI can compile a request to the Claude
//! API: the in-bundle CLI hands its Judgement Requests to the daemon, and the
//! crates.io build has Ollama only.
//!
//! One Item is one synchronous `POST /v1/messages` over `ureq` and rustls, on
//! the caller's blocking thread (ADR 0011). The body carries the model, a
//! bound on the answer's tokens, the fixed system prompt, one user turn
//! holding the redacted Judgement Request inside its nonce block, and
//! `output_config` with `effort: low` and the Verdict schema. Nothing else
//! about the machine or the user is sent: no tools, no history, no sampling
//! parameters (the default model refuses them; the deterministic checks of
//! [`crate::judgement`] are the guard against drift), no identifiers. The
//! headers are the key, the API version, the content type and the User-Agent
//! naming AgentSweep and its version.
//!
//! The key is read from its [`ClaudeKeyStore`] for each call and dropped when
//! the call ends. It travels in its header and nowhere else: no error, no
//! `Debug` output and no log line carries it.
//!
//! Every failure is no Verdict, never benign: `stop_reason: refusal`, an
//! answer cut off at `max_tokens`, any 4xx or 5xx, a connection or TLS
//! failure, and an answer that fails the schema (which the checks of
//! [`crate::judgement`] catch). A `429` honours `retry-after` once and then
//! gives no Verdict. Every answer the API gives with a `200` reports its
//! `usage`, a refusal included, so the cloud caps can count spend from what
//! the API says rather than from an estimate.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::judgement::{EngineError, JudgementEngine, Prompt};
use crate::judgement_request::{ByteEstimate, Normalisation, RequestBuilder};
use crate::keychain::ClaudeKeyStore;

/// The one host the Claude API engine talks to. A release build has no other:
/// only a test constructor points the engine elsewhere.
pub const CLAUDE_API_ORIGIN: &str = "https://api.anthropic.com";

/// The path of the one request.
pub const MESSAGES_PATH: &str = "/v1/messages";

/// The API version the request is written against.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The budget a Judgement Request for the Claude API is built under, in
/// tokens as [`ByteEstimate`] counts them (spec section 4.4, "about 32K";
/// the owner's decision: three bytes per token, no `count_tokens` request).
pub const CLAUDE_REQUEST_BUDGET: usize = 32_000;

/// The bound on the tokens of one answer. A Verdict is a short JSON object;
/// the rest is room for the model's own thinking at low effort. An answer cut
/// off at the bound is no Verdict.
pub const CLAUDE_MAX_TOKENS: u64 = 4_096;

/// The effort the request asks for (spec section 4.4).
pub const CLAUDE_EFFORT: &str = "low";

/// How long one request may take, start to end.
pub const CLAUDE_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The longest `retry-after` a `429` is waited out for. A longer one is no
/// Verdict at once: the Item is retried on the next Scan instead of holding
/// the queue.
pub const LONGEST_RETRY_AFTER: Duration = Duration::from_secs(60);

/// The largest answer body read.
const LARGEST_ANSWER: u64 = 1024 * 1024;

/// The tokens one call to the Claude API took, as the API reports them in
/// `usage`. Spend is computed from these, never from an estimate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    /// `usage.input_tokens`.
    pub input_tokens: u64,
    /// `usage.output_tokens`.
    pub output_tokens: u64,
}

/// What one call came to: the engine's outcome, and the usage the API
/// reported with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeAnswer {
    /// The answer text, or why there is none.
    pub outcome: Result<String, EngineError>,
    /// The usage of every answer the API gave with a `200`, a refusal and an
    /// answer cut off at `max_tokens` included. `None` only when the API
    /// answered nothing billable (an error status, a `429` that was not
    /// followed by an answer, or no connection at all).
    pub usage: Option<Usage>,
}

/// Waits out a `retry-after`. The engine's only clock, so a test can see the
/// wait without taking it.
pub trait Pause: Send + Sync {
    /// Blocks for `duration`.
    fn pause(&self, duration: Duration);
}

/// The real clock: the calling thread sleeps.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sleep;

impl Pause for Sleep {
    fn pause(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// The Claude API engine.
pub struct ClaudeEngine {
    agent: ureq::Agent,
    url: String,
    model: String,
    keys: Arc<dyn ClaudeKeyStore + Send + Sync>,
    pause: Arc<dyn Pause>,
}

impl fmt::Debug for ClaudeEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaudeEngine")
            .field("url", &self.url)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

impl ClaudeEngine {
    /// The engine for `model` (the settings' model in use: the default, or
    /// the Developer override), with its key in `keys`. It asks the Claude
    /// API and nothing else, over https only.
    pub fn new(model: &str, keys: Arc<dyn ClaudeKeyStore + Send + Sync>) -> ClaudeEngine {
        ClaudeEngine::at(CLAUDE_API_ORIGIN, model, keys, Arc::new(Sleep))
    }

    /// The engine pointed at a stand-in for the API, with its own clock. For
    /// tests alone: a release build cannot compile it.
    #[cfg(test)]
    pub(crate) fn for_test(
        origin: &str,
        model: &str,
        keys: Arc<dyn ClaudeKeyStore + Send + Sync>,
        pause: Arc<dyn Pause>,
    ) -> ClaudeEngine {
        ClaudeEngine::at(origin, model, keys, pause)
    }

    fn at(
        origin: &str,
        model: &str,
        keys: Arc<dyn ClaudeKeyStore + Send + Sync>,
        pause: Arc<dyn Pause>,
    ) -> ClaudeEngine {
        let config = ureq::Agent::config_builder()
            .user_agent(user_agent())
            .http_status_as_error(false)
            .timeout_global(Some(CLAUDE_REQUEST_TIMEOUT))
            .https_only(origin.starts_with("https://"))
            .max_redirects(0)
            .proxy(None)
            .build();
        ClaudeEngine {
            agent: ureq::Agent::new_with_config(config),
            url: format!("{origin}{MESSAGES_PATH}"),
            model: model.to_string(),
            keys,
            pause,
        }
    }

    /// The model id the engine asks, for the Verdict cache key and the Event
    /// Log.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The builder for the engine's Judgement Requests: the shared builder
    /// under [`CLAUDE_REQUEST_BUDGET`] with the byte estimate.
    pub fn request_builder(normalisation: Normalisation) -> RequestBuilder<'static> {
        RequestBuilder::new(normalisation, CLAUDE_REQUEST_BUDGET, &ByteEstimate)
    }

    /// The request body for one Prompt: exactly the fields of spec section
    /// 4.4 and nothing else.
    pub fn body(&self, prompt: &Prompt) -> Value {
        json!({
            "model": self.model,
            "max_tokens": CLAUDE_MAX_TOKENS,
            "system": prompt.system(),
            "messages": [
                { "role": "user", "content": prompt.user() },
            ],
            "output_config": {
                "effort": CLAUDE_EFFORT,
                "format": { "type": "json_schema", "schema": prompt.schema() },
            },
        })
    }

    /// Asks the Claude API about the one Item in `prompt`, with the usage the
    /// API reported.
    pub fn ask(&self, prompt: &Prompt) -> ClaudeAnswer {
        let key = match self.keys.load() {
            Ok(Some(key)) => key,
            Ok(None) => {
                return ClaudeAnswer {
                    outcome: Err(EngineError::Unavailable(
                        "no Claude API key is set".to_string(),
                    )),
                    usage: None,
                };
            }
            Err(error) => {
                return ClaudeAnswer {
                    outcome: Err(EngineError::Unavailable(format!(
                        "the Claude API key could not be read: {error}"
                    ))),
                    usage: None,
                };
            }
        };
        let body = self.body(prompt).to_string();
        let first = self.send(key.expose(), &body);
        match first {
            Reply::RateLimited(Some(wait)) if wait <= LONGEST_RETRY_AFTER => {
                self.pause.pause(wait);
                self.send(key.expose(), &body).into_answer()
            }
            reply => reply.into_answer(),
        }
    }

    fn send(&self, key: &str, body: &str) -> Reply {
        let result = self
            .agent
            .post(&self.url)
            .header("x-api-key", key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .send(body);
        let mut response = match result {
            Ok(response) => response,
            Err(error) => return Reply::Failed(failure(error)),
        };
        let status = response.status().as_u16();
        match status {
            200 => {}
            429 => {
                let wait = response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .map(Duration::from_secs);
                return Reply::RateLimited(wait);
            }
            413 => return Reply::Failed(EngineError::ContextOverflow),
            500..=599 => {
                return Reply::Failed(EngineError::Unavailable(format!(
                    "the Claude API answered {status}"
                )));
            }
            _ => {
                return Reply::Failed(EngineError::Failed(format!(
                    "the Claude API answered {status}"
                )));
            }
        }
        let bytes = match response
            .body_mut()
            .with_config()
            .limit(LARGEST_ANSWER)
            .read_to_vec()
        {
            Ok(bytes) => bytes,
            Err(error) => return Reply::Failed(failure(error)),
        };
        read_message(&bytes)
    }
}

impl JudgementEngine for ClaudeEngine {
    fn judge(&self, prompt: &Prompt) -> Result<String, EngineError> {
        self.ask(prompt).outcome
    }
}

/// What one request came to.
enum Reply {
    /// A `200` with its usage: the answer text or why it is none.
    Answered(Result<String, EngineError>, Usage),
    /// A `429`, with the `retry-after` it stated in seconds, if any.
    RateLimited(Option<Duration>),
    /// Anything else, with nothing billable reported.
    Failed(EngineError),
}

impl Reply {
    fn into_answer(self) -> ClaudeAnswer {
        match self {
            Reply::Answered(outcome, usage) => ClaudeAnswer {
                outcome,
                usage: Some(usage),
            },
            Reply::RateLimited(_) => ClaudeAnswer {
                outcome: Err(EngineError::RateLimited),
                usage: None,
            },
            Reply::Failed(error) => ClaudeAnswer {
                outcome: Err(error),
                usage: None,
            },
        }
    }
}

/// Reads a `200` answer: its usage, its stop reason and its text blocks.
/// Only `end_turn` with text is an answer; the text is handed to the checks
/// of [`crate::judgement`] unread.
fn read_message(bytes: &[u8]) -> Reply {
    let Ok(message) = serde_json::from_slice::<Value>(bytes) else {
        return Reply::Failed(EngineError::Failed(
            "the Claude API answer is not JSON".to_string(),
        ));
    };
    let Some(usage) = message.get("usage").and_then(read_usage) else {
        return Reply::Failed(EngineError::Failed(
            "the Claude API answer reports no usage".to_string(),
        ));
    };
    let outcome = match message.get("stop_reason").and_then(Value::as_str) {
        Some("end_turn") => answer_text(&message),
        Some("refusal") => Err(EngineError::Refused),
        Some("max_tokens") => Err(EngineError::Failed(
            "the answer was cut off at max_tokens".to_string(),
        )),
        Some("model_context_window_exceeded") => Err(EngineError::ContextOverflow),
        Some(other) => Err(EngineError::Failed(format!(
            "the answer stopped for {}",
            plain_word(other)
        ))),
        None => Err(EngineError::Failed(
            "the answer states no stop reason".to_string(),
        )),
    };
    Reply::Answered(outcome, usage)
}

fn read_usage(usage: &Value) -> Option<Usage> {
    Some(Usage {
        input_tokens: usage.get("input_tokens")?.as_u64()?,
        output_tokens: usage.get("output_tokens")?.as_u64()?,
    })
}

/// The text blocks of an answer, joined. Thinking blocks are passed over.
fn answer_text(message: &Value) -> Result<String, EngineError> {
    let text: String = message
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect();
    match text.is_empty() {
        true => Err(EngineError::Failed("the answer holds no text".to_string())),
        false => Ok(text),
    }
}

/// A stop reason as a short word for an error: letters and underscores only,
/// at most 40 of them, so nothing the answer says reaches a log line.
fn plain_word(word: &str) -> String {
    word.chars()
        .filter(|c| c.is_ascii_alphabetic() || *c == '_')
        .take(40)
        .collect()
}

/// What a failed request says: its kind, never the address, the key or
/// anything the error carries beside it.
fn failure(error: ureq::Error) -> EngineError {
    match error {
        ureq::Error::Timeout(_) => EngineError::TimedOut,
        ureq::Error::HostNotFound => EngineError::Unavailable("the host was not found".to_string()),
        ureq::Error::ConnectionFailed => {
            EngineError::Unavailable("the connection failed".to_string())
        }
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) | ureq::Error::TlsRequired => {
            EngineError::Unavailable("the TLS handshake failed".to_string())
        }
        ureq::Error::Io(_) => EngineError::Unavailable("the connection broke off".to_string()),
        ureq::Error::BodyExceedsLimit(_) => {
            EngineError::Failed("the answer was larger than it may be".to_string())
        }
        _ => EngineError::Failed("the request failed".to_string()),
    }
}

/// The User-Agent: the product and its version, nothing else.
pub fn user_agent() -> String {
    format!("{}/{}", crate::NAME, crate::VERSION)
}

#[cfg(test)]
mod tests;
