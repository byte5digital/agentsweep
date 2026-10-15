//! The Apple on-device Judgement Engine (spec section 4.4): Apple's
//! Foundation Models, reached only through the Apple judgement helper beside
//! the executable that asks.
//!
//! The module exists only in a build with the `apple` feature, which the
//! daemon and the in-bundle CLI turn on: the crates.io build has no Apple
//! engine, because it has no helper beside it.
//!
//! The helper speaks one JSON object in on its stdin and one JSON object out
//! on its stdout, then exits. It is spawned once per call (`check`, `count`
//! or `judge`) with a deadline, and killed and reaped when the deadline
//! passes, so no helper outlives the call that started it. Nothing here runs
//! a shell, reads the helper's stderr or logs what went in or came out.
//!
//! The Judgement Request is built under Apple's budget: the 4,096 tokens of
//! the model's context less the instructions (the fixed system prompt, the
//! Verdict schema and the framing of the user turn) and the room kept for the
//! answer, each measured with the helper's own token count. The request is
//! measured the same way, so the builder windows it when it is over and
//! builds nothing when even the windows are; such a request never reaches the
//! helper's `judge`.
//!
//! Every helper error is no Verdict, never benign. On `rate_limited` the
//! engine waits and asks again, each wait twice the one before, and after
//! three tries gives up with no Verdict. The model identifier the Verdict
//! cache keys on is the one the helper's `check` names: the full macOS
//! version and build number.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::apple::{AppleAvailability, HELPER_MISSING, HELPER_NAME};
use crate::judgement::{
    EngineError, JudgementEngine, NONCE_CHARS, Prompt, SYSTEM_PROMPT, user_turn, verdict_schema,
};
use crate::judgement_request::{Normalisation, RequestBuilder, TokenCounter};

/// The context of Apple's on-device model, in tokens.
pub const APPLE_CONTEXT: usize = 4_096;

/// The tokens kept free for the answer: a Verdict of four fields, a reason of
/// at most a few sentences and a handful of short quotes.
pub const ANSWER_TOKENS: usize = 512;

/// How many times one judgement is asked while the model answers
/// `rate_limited`; after the last, no Verdict.
pub const RATE_LIMIT_TRIES: u32 = 3;

/// The wait before the second try. Each later wait is twice the one before.
pub const FIRST_BACKOFF: Duration = Duration::from_secs(5);

/// How long a `check` or a `count` may take, from spawn to exit.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one `judge` may take, from spawn to exit.
pub const JUDGE_TIMEOUT: Duration = Duration::from_secs(60);

/// The largest answer read from the helper. A Verdict or a count is far
/// smaller; anything larger is not an answer to what was asked.
const LARGEST_ANSWER: usize = 1024 * 1024;

/// How often a call looks whether the helper has exited.
const POLL: Duration = Duration::from_millis(5);

/// Waits out a backoff. The engine's only clock, so a test sees the waits
/// without taking them.
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

/// How long each kind of call may take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timeouts {
    /// For `check` and `count`.
    pub check: Duration,
    /// For `judge`.
    pub judge: Duration,
}

impl Default for Timeouts {
    fn default() -> Timeouts {
        Timeouts {
            check: CHECK_TIMEOUT,
            judge: JUDGE_TIMEOUT,
        }
    }
}

/// The wait before try `next` (the second try is 1): [`FIRST_BACKOFF`],
/// doubled for every try after the second.
pub fn backoff(next: u32) -> Duration {
    FIRST_BACKOFF.saturating_mul(1 << next.saturating_sub(1).min(16))
}

/// What the helper's error names come to: every one is no Verdict, and
/// `rate_limited` is the one the engine asks again on.
pub fn engine_error(name: &str) -> EngineError {
    match name {
        "rate_limited" => EngineError::RateLimited,
        "guardrail_violation" | "refusal" => EngineError::Refused,
        "context_window_exceeded" | "request_too_large" => EngineError::ContextOverflow,
        "model_unavailable" | "assets_unavailable" | "token_count_unavailable" => {
            EngineError::Unavailable(format!("the Apple model answered {name}"))
        }
        name if crate::apple::is_reason_word(name) => {
            EngineError::Failed(format!("the Apple judgement helper answered {name}"))
        }
        _ => EngineError::Failed("the Apple judgement helper answered an unknown error".into()),
    }
}

/// The Apple judgement helper at one path.
#[derive(Debug)]
pub struct AppleHelper {
    path: PathBuf,
    timeouts: Timeouts,
    last_pid: Mutex<Option<u32>>,
}

impl AppleHelper {
    /// The helper at `path`.
    pub fn at(path: impl Into<PathBuf>) -> AppleHelper {
        AppleHelper {
            path: path.into(),
            timeouts: Timeouts::default(),
            last_pid: Mutex::new(None),
        }
    }

    /// The helper beside this process's own executable, where the bundle
    /// places it beside the daemon and the CLI. Absent only when the
    /// executable's own path cannot be read.
    pub fn beside_this_executable() -> Option<AppleHelper> {
        let executable = std::env::current_exe().ok()?;
        Some(AppleHelper::at(executable.parent()?.join(HELPER_NAME)))
    }

    /// The same helper, waiting as long as `timeouts` say.
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> AppleHelper {
        self.timeouts = timeouts;
        self
    }

    /// Where the helper is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The process id of the last helper this one spawned, so a test can see
    /// that it is gone once the call has returned.
    pub fn last_pid(&self) -> Option<u32> {
        *self
            .last_pid
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether Apple's model can judge here. A helper that is not there, or
    /// cannot be started, is [`HELPER_MISSING`]; any other failure is
    /// `helper_failed`.
    pub fn check(&self) -> AppleAvailability {
        match self.call(&json!({ "command": "check" }), self.timeouts.check) {
            Ok(answer) => AppleAvailability::from_check(&answer),
            Err(Called::NotStarted) => AppleAvailability::Unavailable {
                reason: HELPER_MISSING.to_string(),
            },
            Err(Called::Failed(_)) => AppleAvailability::from_check(&Value::Null),
        }
    }

    /// The tokens `text` takes in Apple's model, as the framework counts
    /// them.
    pub fn count(&self, text: &str) -> Result<usize, EngineError> {
        let answer = self
            .call(
                &json!({ "command": "count", "text": text }),
                self.timeouts.check,
            )
            .map_err(Called::into_engine_error)?;
        answer
            .get("token_count")
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| EngineError::Failed("the count answer names no token count".into()))
    }

    /// One judgement of the one Item in `prompt`: the fixed instructions, the
    /// user turn and the Verdict schema, in a fresh session. The answer is
    /// the JSON the model produced under the schema, as text for the checks.
    pub fn judge(&self, prompt: &Prompt) -> Result<String, EngineError> {
        let answer = self
            .call(
                &json!({
                    "command": "judge",
                    "instructions": prompt.system(),
                    "prompt": prompt.user(),
                    "schema": prompt.schema(),
                }),
                self.timeouts.judge,
            )
            .map_err(Called::into_engine_error)?;
        match answer.get("answer") {
            Some(answer @ Value::Object(_)) => Ok(answer.to_string()),
            _ => Err(EngineError::Failed(
                "the judgement answer holds no answer".into(),
            )),
        }
    }

    /// Spawns the helper once, hands it `request`, and reads its one answer,
    /// all within `limit`. Past the deadline the helper is killed and reaped.
    fn call(&self, request: &Value, limit: Duration) -> Result<Value, Called> {
        let deadline = Instant::now() + limit;
        let body = serde_json::to_vec(request).map_err(|_| {
            Called::Failed(EngineError::Failed(
                "the request could not be written".into(),
            ))
        })?;
        let mut child = Command::new(&self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Called::NotStarted)?;
        *self
            .last_pid
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(child.id());

        // Writing and reading run beside the wait, so a helper that reads
        // nothing or answers slowly cannot hold the call past its deadline.
        if let Some(mut stdin) = child.stdin.take() {
            std::thread::spawn(move || {
                let _ = stdin.write_all(&body);
            });
        }
        let (sender, answer) = mpsc::channel();
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let read = stdout
                    .take(LARGEST_ANSWER as u64 + 1)
                    .read_to_end(&mut out)
                    .map(|_| out);
                let _ = sender.send(read);
            });
        }

        let out = match answer.recv_timeout(left(deadline)) {
            Ok(Ok(out)) => out,
            Ok(Err(_)) => {
                end(&mut child);
                return Err(Called::Failed(EngineError::Failed(
                    "the Apple judgement helper's answer could not be read".into(),
                )));
            }
            Err(_) => {
                end(&mut child);
                return Err(Called::Failed(EngineError::TimedOut));
            }
        };
        let succeeded = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
                _ => {
                    end(&mut child);
                    return Err(Called::Failed(EngineError::TimedOut));
                }
            }
        };
        if out.len() > LARGEST_ANSWER {
            return Err(Called::Failed(EngineError::Failed(
                "the Apple judgement helper's answer is larger than it may be".into(),
            )));
        }
        let value: Value = serde_json::from_slice(&out).map_err(|_| {
            Called::Failed(EngineError::Failed(
                "the Apple judgement helper's answer is not JSON".into(),
            ))
        })?;
        if let Some(name) = value.get("error") {
            return Err(Called::Failed(engine_error(name.as_str().unwrap_or(""))));
        }
        if !succeeded || !value.is_object() {
            return Err(Called::Failed(EngineError::Failed(
                "the Apple judgement helper failed without naming an error".into(),
            )));
        }
        Ok(value)
    }
}

/// What is left of the deadline.
fn left(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Kills the helper and reaps it, so it neither runs on nor lingers.
fn end(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Why one call to the helper came to nothing.
enum Called {
    /// The helper could not be started: it is not there, or not executable.
    NotStarted,
    /// It started and gave no answer.
    Failed(EngineError),
}

impl Called {
    fn into_engine_error(self) -> EngineError {
        match self {
            Called::NotStarted => {
                EngineError::Unavailable("the Apple judgement helper could not be started".into())
            }
            Called::Failed(error) => error,
        }
    }
}

/// Counts tokens with the helper for the request builder. A count that fails
/// counts as more than any budget, so the request is not built and the Item
/// gets no Verdict; the failure is kept for the caller to read.
#[derive(Debug)]
pub struct AppleCounter {
    helper: Arc<AppleHelper>,
    failure: Mutex<Option<EngineError>>,
}

impl AppleCounter {
    /// The last count that failed, taken away so the next build starts
    /// clean.
    pub fn take_failure(&self) -> Option<EngineError> {
        self.failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

impl TokenCounter for AppleCounter {
    fn tokens(&self, text: &str) -> usize {
        match self.helper.count(text) {
            Ok(count) => count,
            Err(error) => {
                *self
                    .failure
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
                usize::MAX
            }
        }
    }
}

/// The Apple on-device Judgement Engine: Apple's model through its helper,
/// asked one Item at a time.
pub struct AppleEngine {
    helper: Arc<AppleHelper>,
    counter: AppleCounter,
    model_version: String,
    pause: Arc<dyn Pause>,
    budget: OnceLock<usize>,
}

impl fmt::Debug for AppleEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppleEngine")
            .field("helper", &self.helper.path())
            .field("model_version", &self.model_version)
            .finish_non_exhaustive()
    }
}

impl AppleEngine {
    /// The engine, once the helper's `check` says the model is available. An
    /// unavailable model is an engine error naming the reason.
    pub fn new(helper: AppleHelper) -> Result<AppleEngine, EngineError> {
        let model_version = match helper.check() {
            AppleAvailability::Available { model_version, .. } => model_version,
            AppleAvailability::Unavailable { reason } => {
                return Err(EngineError::Unavailable(format!(
                    "Apple on-device is unavailable: {reason}"
                )));
            }
        };
        let helper = Arc::new(helper);
        Ok(AppleEngine {
            counter: AppleCounter {
                helper: Arc::clone(&helper),
                failure: Mutex::new(None),
            },
            helper,
            model_version,
            pause: Arc::new(Sleep),
            budget: OnceLock::new(),
        })
    }

    /// The same engine, waiting out its backoff on `pause`.
    pub fn with_pause(mut self, pause: Arc<dyn Pause>) -> AppleEngine {
        self.pause = pause;
        self
    }

    /// The model id the Verdict cache keys on: the OS model version the
    /// helper names, the full macOS version and build number.
    pub fn model_id(&self) -> &str {
        &self.model_version
    }

    /// The helper this engine asks.
    pub fn helper(&self) -> &AppleHelper {
        &self.helper
    }

    /// The tokens a Judgement Request may take: [`APPLE_CONTEXT`] less the
    /// system prompt, the Verdict schema and the framing of the user turn,
    /// each as the helper counts it, and less [`ANSWER_TOKENS`]. Measured
    /// once per engine, since none of it changes.
    pub fn budget(&self) -> Result<usize, EngineError> {
        if let Some(budget) = self.budget.get() {
            return Ok(*budget);
        }
        let schema = verdict_schema().to_string();
        let framing = user_turn(&"0".repeat(NONCE_CHARS), "");
        let mut taken = ANSWER_TOKENS;
        for text in [SYSTEM_PROMPT, schema.as_str(), framing.as_str()] {
            taken = taken.saturating_add(self.helper.count(text)?);
        }
        let budget = APPLE_CONTEXT.saturating_sub(taken);
        Ok(*self.budget.get_or_init(|| budget))
    }

    /// The Judgement Request builder for Apple: requests measured with the
    /// helper's token count against [`AppleEngine::budget`].
    pub fn request_builder(
        &self,
        normalisation: Normalisation,
    ) -> Result<RequestBuilder<'_>, EngineError> {
        Ok(RequestBuilder::new(
            normalisation,
            self.budget()?,
            &self.counter,
        ))
    }

    /// The counter the builder measures with, whose last failure says why a
    /// request was not built when a count failed.
    pub fn counter(&self) -> &AppleCounter {
        &self.counter
    }
}

impl JudgementEngine for AppleEngine {
    /// Asks the helper, and asks again after a growing wait while the model
    /// answers `rate_limited`, at most [`RATE_LIMIT_TRIES`] times in all.
    fn judge(&self, prompt: &Prompt) -> Result<String, EngineError> {
        let mut tries = 1;
        loop {
            match self.helper.judge(prompt) {
                Err(EngineError::RateLimited) if tries < RATE_LIMIT_TRIES => {
                    self.pause.pause(backoff(tries));
                    tries += 1;
                }
                outcome => return outcome,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crates.io build of the CLI has no Apple engine: only its `bundle`
    /// feature turns the core's `apple` feature on, and the daemon does.
    #[test]
    fn only_the_daemon_and_the_in_bundle_cli_build_the_apple_engine() {
        let cli = include_str!("../../cli/Cargo.toml");
        let bundle = cli
            .lines()
            .find(|line| line.starts_with("bundle = "))
            .expect("the CLI has a bundle feature");
        assert!(bundle.contains("\"agentsweep-core/apple\""), "{bundle}");
        assert!(cli.contains("default = []"));
        let core_line = cli
            .lines()
            .find(|line| line.starts_with("agentsweep-core"))
            .expect("the CLI names the core");
        assert!(!core_line.contains("apple"), "{core_line}");

        let daemon = include_str!("../../daemon/Cargo.toml");
        assert!(
            daemon
                .lines()
                .any(|line| line.starts_with("agentsweep-core = ") && line.contains("\"apple\""))
        );
    }

    #[test]
    fn each_wait_is_twice_the_one_before() {
        assert_eq!(backoff(1), FIRST_BACKOFF);
        assert_eq!(backoff(2), FIRST_BACKOFF * 2);
        assert_eq!(backoff(3), FIRST_BACKOFF * 4);
    }

    #[test]
    fn rate_limited_is_the_one_error_asked_again_and_none_is_benign() {
        assert_eq!(engine_error("rate_limited"), EngineError::RateLimited);
        assert_eq!(engine_error("refusal"), EngineError::Refused);
        assert_eq!(engine_error("guardrail_violation"), EngineError::Refused);
        assert_eq!(
            engine_error("context_window_exceeded"),
            EngineError::ContextOverflow
        );
        assert!(matches!(
            engine_error("model_unavailable"),
            EngineError::Unavailable(_)
        ));
        assert!(matches!(
            engine_error("Text <with> markup"),
            EngineError::Failed(detail) if !detail.contains("markup")
        ));
    }
}
