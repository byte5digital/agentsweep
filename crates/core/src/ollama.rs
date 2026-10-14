//! The Ollama Judgement Engine (spec section 4.4): Ollama on this Mac, asked
//! at the loopback address the settings name and nowhere else.
//!
//! Everything here is loopback, so nothing counts against the egress promise
//! of spec section 1.1. The address comes from the settings file, where it is
//! loopback by construction; `OLLAMA_HOST` is never read, and no proxy is
//! ever asked, because the client is a few lines of HTTP over one TCP
//! connection to that one address. AgentSweep never pulls a model and never
//! starts `ollama serve`: it only asks what is already there.
//!
//! Three requests exist:
//!
//! - `GET /api/version`, with a short timeout, tells whether Ollama is
//!   running at all;
//! - `GET /api/tags` lists the models already pulled, each with its
//!   parameter size and digest; a model under four billion parameters counts
//!   as absent for the onboarding suggestion;
//! - `POST /api/chat`, one per Item: a fresh session of two messages (the
//!   fixed system prompt and the user turn), no tools, no history, `stream`
//!   false, `temperature` 0, `format` set to the one Verdict schema,
//!   `options.num_ctx` 8192 stated explicitly and `keep_alive` five minutes.
//!
//! Connection refused, a timeout, an answer other than `200`, a
//! `done_reason` other than a finished answer and a reply that is not what
//! was asked for are each an engine error, and so no Verdict, never benign.
//! Neither the Prompt nor any Item content is ever put in an error, so
//! nothing a caller logs from here carries either.
//!
//! Ollama counts no tokens for AgentSweep beforehand, so the Judgement
//! Request is cut to the byte estimate of three bytes per token, 3 x 8192
//! bytes (the owner's decision). The prompt evaluation count Ollama reports
//! back is kept as a number, for the caller to log and for the eval report to
//! check the estimate against; it decides nothing.

use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::judgement::{EngineError, JudgementEngine, Prompt};
use crate::judgement_request::{ByteEstimate, Normalisation, RequestBuilder};
use crate::settings::OllamaAddress;

/// The context Ollama is told to give every judgement, stated explicitly
/// rather than left to the model's default.
pub const NUM_CTX: usize = 8192;

/// How long Ollama keeps the model loaded after a judgement, so the next
/// Item of the same batch does not load it again.
pub const KEEP_ALIVE: &str = "5m";

/// The smallest model, in billions of parameters, the onboarding suggestion
/// counts. A smaller model counts as absent.
pub const SUGGESTION_BILLIONS: f64 = 4.0;

/// How long detection and the model list wait, and how long any request
/// waits for its connection.
pub const DETECTION_TIMEOUT: Duration = Duration::from_secs(2);

/// How long one judgement waits for its answer, start to finish.
pub const JUDGEMENT_TIMEOUT: Duration = Duration::from_secs(120);

/// The largest answer read from Ollama. A model list or a Verdict is far
/// smaller; anything larger is not an answer to what was asked.
const LARGEST_ANSWER: usize = 4 * 1024 * 1024;

/// The byte estimate the Ollama budget is counted with.
static ESTIMATE: ByteEstimate = ByteEstimate;

/// The Judgement Request builder for Ollama: the budget is [`NUM_CTX`]
/// tokens at three bytes each, so the request is cut to 3 x 8192 bytes.
pub fn request_builder(normalisation: Normalisation) -> RequestBuilder<'static> {
    RequestBuilder::new(normalisation, NUM_CTX, &ESTIMATE)
}

/// How long the client waits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timeouts {
    /// For the connection, for detection and for the model list.
    pub detection: Duration,
    /// For one judgement, start to finish.
    pub judgement: Duration,
}

impl Default for Timeouts {
    fn default() -> Timeouts {
        Timeouts {
            detection: DETECTION_TIMEOUT,
            judgement: JUDGEMENT_TIMEOUT,
        }
    }
}

/// One model Ollama has already pulled, as `/api/tags` lists it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OllamaModel {
    /// The tag, such as `qwen3:8b`.
    pub name: String,
    /// The digest of the model's manifest.
    pub digest: String,
    /// The parameter size as Ollama writes it, such as `8.2B`; empty when it
    /// names none.
    pub parameter_size: String,
    /// True when the model has at least [`SUGGESTION_BILLIONS`] billion
    /// parameters. A model under that, or one whose size cannot be read,
    /// counts as absent for the onboarding suggestion.
    pub large_enough: bool,
}

/// Whether Ollama runs at the configured address, and what it holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OllamaPresence {
    /// Nothing answered `/api/version` in time.
    Absent,
    /// Ollama answered.
    Running {
        /// The version it reports.
        version: String,
        /// The models already pulled; empty when the list could not be read.
        models: Vec<OllamaModel>,
    },
}

/// Reads a parameter size such as `1.7B`, `26B` or `270M` as billions.
pub fn parameter_billions(size: &str) -> Option<f64> {
    let size = size.trim();
    let (number, per_billion) = match size.char_indices().last()? {
        (at, 'T' | 't') => (&size[..at], 1e-3),
        (at, 'B' | 'b') => (&size[..at], 1.0),
        (at, 'M' | 'm') => (&size[..at], 1e3),
        (at, 'K' | 'k') => (&size[..at], 1e6),
        _ => return None,
    };
    let number: f64 = number.trim().parse().ok()?;
    (number.is_finite() && number >= 0.0).then_some(number / per_billion)
}

/// The HTTP client for the one configured loopback address.
#[derive(Clone, Debug)]
pub struct OllamaClient {
    address: SocketAddr,
    host: String,
    timeouts: Timeouts,
}

/// One answer: the status and the body.
struct Answer {
    status: u16,
    body: Vec<u8>,
}

impl OllamaClient {
    /// A client for the address the settings name. `localhost` is taken as
    /// `127.0.0.1` without asking any resolver, so no name lookup can point it
    /// anywhere else.
    pub fn new(address: &OllamaAddress) -> OllamaClient {
        let text = address.as_str();
        let parsed = match text.strip_prefix("localhost:") {
            Some(port) => port
                .parse()
                .ok()
                .map(|port| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))),
            None => text.parse().ok(),
        };
        // An OllamaAddress is a loopback host and a port by construction; the
        // default stands in only if that ever stopped holding, and it is
        // loopback too.
        let address = parsed
            .filter(|parsed: &SocketAddr| parsed.ip().is_loopback())
            .unwrap_or(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                11434,
            )));
        OllamaClient {
            address,
            host: text.to_string(),
            timeouts: Timeouts::default(),
        }
    }

    /// The same client, waiting as long as `timeouts` say.
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> OllamaClient {
        self.timeouts = timeouts;
        self
    }

    /// The one address this client connects to.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The version Ollama reports at `/api/version`.
    pub fn version(&self) -> Result<String, EngineError> {
        let value =
            self.json(self.request("GET", "/api/version", None, self.timeouts.detection)?)?;
        value
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| EngineError::Failed("the version answer names no version".into()))
    }

    /// The models Ollama has already pulled, from `/api/tags`.
    pub fn models(&self) -> Result<Vec<OllamaModel>, EngineError> {
        let value =
            self.json(self.request("GET", "/api/tags", None, self.timeouts.detection)?)?;
        let Some(Value::Array(models)) = value.get("models") else {
            return Err(EngineError::Failed("the model list names no models".into()));
        };
        Ok(models
            .iter()
            .filter_map(|model| {
                let name = model
                    .get("name")
                    .or_else(|| model.get("model"))
                    .and_then(Value::as_str)?
                    .to_string();
                let digest = model
                    .get("digest")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let parameter_size = model
                    .pointer("/details/parameter_size")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let large_enough = parameter_billions(&parameter_size)
                    .is_some_and(|billions| billions >= SUGGESTION_BILLIONS);
                Some(OllamaModel {
                    name,
                    digest,
                    parameter_size,
                    large_enough,
                })
            })
            .collect())
    }

    /// Whether Ollama runs here, and the models it holds.
    pub fn presence(&self) -> OllamaPresence {
        match self.version() {
            Ok(version) => OllamaPresence::Running {
                version,
                models: self.models().unwrap_or_default(),
            },
            Err(_) => OllamaPresence::Absent,
        }
    }

    fn json(&self, answer: Answer) -> Result<Value, EngineError> {
        if answer.status != 200 {
            return Err(EngineError::Failed(format!(
                "Ollama answered {}",
                answer.status
            )));
        }
        serde_json::from_slice(&answer.body)
            .map_err(|_| EngineError::Failed("Ollama's answer is not JSON".into()))
    }

    /// One request on a connection of its own, to the configured address and
    /// nowhere else, finished within `limit`.
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        limit: Duration,
    ) -> Result<Answer, EngineError> {
        let deadline = Instant::now() + limit;
        let mut stream =
            TcpStream::connect_timeout(&self.address, self.timeouts.detection.min(limit)).map_err(
                |error| match error.kind() {
                    ErrorKind::TimedOut | ErrorKind::WouldBlock => EngineError::TimedOut,
                    _ => EngineError::Unavailable("Ollama did not answer on its address".into()),
                },
            )?;
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}/{}\r\n\
             Accept: application/json\r\nConnection: close\r\n",
            self.host,
            crate::NAME,
            crate::VERSION
        );
        if let Some(body) = body {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        head.push_str("\r\n");
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(broke_off)?;
        stream.write_all(head.as_bytes()).map_err(io_error)?;
        if let Some(body) = body {
            stream.write_all(body).map_err(io_error)?;
        }
        stream.flush().map_err(io_error)?;

        let mut received = Vec::new();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            if let Some(answer) = complete(&received)? {
                return Ok(answer);
            }
            stream
                .set_read_timeout(Some(remaining(deadline)?))
                .map_err(broke_off)?;
            let read = stream.read(&mut buffer).map_err(io_error)?;
            if read == 0 {
                return finished(&received);
            }
            received.extend_from_slice(&buffer[..read]);
            if received.len() > LARGEST_ANSWER {
                return Err(EngineError::Failed(
                    "Ollama's answer is larger than it may be".into(),
                ));
            }
        }
    }
}

/// What is left of the deadline, or a timeout once it has passed.
fn remaining(deadline: Instant) -> Result<Duration, EngineError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(EngineError::TimedOut)
}

fn io_error(error: std::io::Error) -> EngineError {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => EngineError::TimedOut,
        _ => broke_off(error),
    }
}

fn broke_off(_: std::io::Error) -> EngineError {
    EngineError::Unavailable("the connection to Ollama broke off".into())
}

/// The head of an answer: the status, where the body starts, and how its
/// length is told.
struct Head {
    status: u16,
    body_at: usize,
    length: Length,
}

enum Length {
    Fixed(usize),
    Chunked,
    UntilClosed,
}

fn head(received: &[u8]) -> Result<Option<Head>, EngineError> {
    let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&received[..end]).map_err(|_| not_http())?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(not_http)?;
    let mut parts = status_line.split(' ');
    if !parts
        .next()
        .is_some_and(|version| version.starts_with("HTTP/1."))
    {
        return Err(not_http());
    }
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(not_http)?;
    let mut length = Length::UntilClosed;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            length = Length::Chunked;
        } else if name.eq_ignore_ascii_case("content-length") && !matches!(length, Length::Chunked)
        {
            length = Length::Fixed(value.parse().map_err(|_| not_http())?);
        }
    }
    Ok(Some(Head {
        status,
        body_at: end + 4,
        length,
    }))
}

/// The answer, once all of it has arrived.
fn complete(received: &[u8]) -> Result<Option<Answer>, EngineError> {
    let Some(head) = head(received)? else {
        return Ok(None);
    };
    let body = &received[head.body_at..];
    match head.length {
        Length::Fixed(length) if body.len() >= length => Ok(Some(Answer {
            status: head.status,
            body: body[..length].to_vec(),
        })),
        Length::Chunked => Ok(dechunk(body)?.map(|body| Answer {
            status: head.status,
            body,
        })),
        _ => Ok(None),
    }
}

/// The answer when the connection closed: complete, or cut off.
fn finished(received: &[u8]) -> Result<Answer, EngineError> {
    if let Some(answer) = complete(received)? {
        return Ok(answer);
    }
    match head(received)? {
        Some(Head {
            status,
            body_at,
            length: Length::UntilClosed,
        }) => Ok(Answer {
            status,
            body: received[body_at..].to_vec(),
        }),
        _ => Err(EngineError::Unavailable(
            "the connection to Ollama broke off".into(),
        )),
    }
}

/// A chunked body, once its last chunk has arrived.
fn dechunk(mut body: &[u8]) -> Result<Option<Vec<u8>>, EngineError> {
    let mut out = Vec::new();
    loop {
        let Some(end) = body.windows(2).position(|window| window == b"\r\n") else {
            return Ok(None);
        };
        let size_text = std::str::from_utf8(&body[..end]).map_err(|_| not_http())?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| not_http())?;
        let rest = &body[end + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        if rest.len() < size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&rest[..size]);
        body = &rest[size + 2..];
    }
}

fn not_http() -> EngineError {
    EngineError::Failed("Ollama's answer is not HTTP".into())
}

/// The Ollama Judgement Engine: one model, already pulled, asked one Item at
/// a time.
#[derive(Debug)]
pub struct OllamaEngine {
    client: OllamaClient,
    model: String,
    digest: String,
    prompt_eval_count: Mutex<Option<u64>>,
}

impl OllamaEngine {
    /// The engine for the model the settings name, which must already be
    /// pulled: its digest is read from the model list, for the Verdict cache
    /// key. A model that is not there is an engine error; AgentSweep never
    /// pulls one.
    pub fn for_model(client: OllamaClient, model: &str) -> Result<OllamaEngine, EngineError> {
        if model.is_empty() {
            return Err(EngineError::Unavailable("no Ollama model is chosen".into()));
        }
        let latest = format!("{model}:latest");
        let found = client
            .models()?
            .into_iter()
            .find(|pulled| pulled.name == model || (!model.contains(':') && pulled.name == latest))
            .ok_or_else(|| {
                EngineError::Unavailable("the chosen model is not pulled in Ollama".into())
            })?;
        Ok(OllamaEngine {
            client,
            model: found.name,
            digest: found.digest,
            prompt_eval_count: Mutex::new(None),
        })
    }

    /// The model id the Verdict cache keys on: the Ollama tag and the digest
    /// of what it names, so a re-pulled tag is a different model.
    pub fn model_id(&self) -> String {
        format!("{}@{}", self.model, self.digest)
    }

    /// The prompt evaluation count Ollama reported for the last judgement
    /// that was answered, as a number only.
    pub fn last_prompt_eval_count(&self) -> Option<u64> {
        *self
            .prompt_eval_count
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The body of the one chat request for one Prompt.
    pub fn chat_body(&self, prompt: &Prompt) -> Value {
        json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": prompt.system() },
                { "role": "user", "content": prompt.user() },
            ],
            "stream": false,
            "format": prompt.schema(),
            "options": { "temperature": 0, "num_ctx": NUM_CTX },
            "keep_alive": KEEP_ALIVE,
        })
    }
}

impl JudgementEngine for OllamaEngine {
    fn judge(&self, prompt: &Prompt) -> Result<String, EngineError> {
        let body = serde_json::to_vec(&self.chat_body(prompt))
            .map_err(|_| EngineError::Failed("the chat request could not be written".into()))?;
        let answer = self.client.request(
            "POST",
            "/api/chat",
            Some(&body),
            self.client.timeouts.judgement,
        )?;
        let value = self.client.json(answer)?;
        if let Some(count) = value.get("prompt_eval_count").and_then(Value::as_u64) {
            *self
                .prompt_eval_count
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(count);
        }
        if value.get("done").and_then(Value::as_bool) != Some(true) {
            return Err(EngineError::Failed(
                "Ollama's answer is not finished".into(),
            ));
        }
        match value.get("done_reason").and_then(Value::as_str) {
            Some("stop") => {}
            Some("length") => return Err(EngineError::ContextOverflow),
            _ => {
                return Err(EngineError::Failed(
                    "Ollama's answer did not finish normally".into(),
                ));
            }
        }
        value
            .pointer("/message/content")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| EngineError::Failed("Ollama's answer holds no message".into()))
    }
}

impl fmt::Display for OllamaPresence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OllamaPresence::Absent => f.write_str("Ollama is not running"),
            OllamaPresence::Running { version, models } => {
                write!(f, "Ollama {version} with {} models", models.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_sizes_read_as_billions() {
        assert_eq!(parameter_billions("1.7B"), Some(1.7));
        assert_eq!(parameter_billions("4B"), Some(4.0));
        assert_eq!(parameter_billions("26B"), Some(26.0));
        assert_eq!(parameter_billions("270M"), Some(0.27));
        assert_eq!(parameter_billions(""), None);
        assert_eq!(parameter_billions("large"), None);
    }

    #[test]
    fn a_chunked_body_is_read_once_its_last_chunk_arrives() {
        assert_eq!(dechunk(b"4\r\nabcd\r\n2\r\nef\r\n").unwrap(), None);
        assert_eq!(
            dechunk(b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n").unwrap(),
            Some(b"abcdef".to_vec())
        );
    }

    #[test]
    fn localhost_is_taken_as_the_loopback_address_without_a_lookup() {
        let address = OllamaAddress::parse("localhost:4242").expect("a loopback address");
        assert_eq!(
            OllamaClient::new(&address).address(),
            "127.0.0.1:4242".parse().unwrap()
        );
        let address = OllamaAddress::parse("[::1]:4242").expect("a loopback address");
        assert_eq!(
            OllamaClient::new(&address).address(),
            "[::1]:4242".parse().unwrap()
        );
    }
}
