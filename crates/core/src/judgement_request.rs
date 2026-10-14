//! The Judgement Request: what AI Judgement hands a Judgement Engine for one
//! Item in the Ambiguous Band (spec section 4.4).
//!
//! There is one request, the same for every engine, built here from what a
//! Scan already holds: the Item's facts (kind, Scope, Provenance, Activation),
//! the Heuristics that fired with their `plain` sentence and a match excerpt,
//! and the content. An entry contributes its canonical serialised bytes, a
//! file the whole file, and a tree its entry point (`SKILL.md` for a skill)
//! together with only the files a Heuristic matched in.
//!
//! Redaction comes first, before anything is measured or hashed, and it is
//! identical for every engine:
//!
//! - the values the adapters mark sensitive (the `env` and `headers` blocks of
//!   MCP and settings entries, every value of an env file) become
//!   `<redacted:type:len>`;
//! - the credential patterns of Rule 0010, the plaintext-secret Exposure Rule,
//!   mask their hits in free text of every kind, and so do the matches of a
//!   Heuristic marked `sensitive`;
//! - the home directory and the username are normalised to `~` and `user`.
//!
//! The budget and the token counter are parameters, so each engine supplies
//! its own while the builder stays one code path. A request over the budget
//! has its content replaced by windows around each match, separated by
//! explicit elision markers; one still over the budget is not built at all,
//! and the caller records no Verdict. Nothing is ever cut silently.
//!
//! The builder also yields the request hash the Verdict cache keys on. Nothing
//! here sends anything.

use std::cmp::Reverse;
use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::sync::OnceLock;

use serde_json::{Map, Value};
use yara_x::{Compiler, Rules, Scanner};

use crate::baseline::sensitive_fields;
use crate::finding::FiredHeuristic;
use crate::finding_facts::EXCERPT_CHARS;
use crate::host::Host;
use crate::item::{FileType, Item, Kind, Shape, canonical_entry, sha256_hex};
use crate::rules::BUNDLED_RULES;
use crate::views::value_string;

/// How many bytes one token is estimated at where an engine cannot count
/// tokens itself: a conservative three, so a request cut to the estimate fits
/// the engine's context (the owner's decisions on Ollama and the Claude API).
pub const BYTES_PER_TOKEN: usize = 3;

/// How many bytes of context a window keeps on each side of a match when a
/// request over its budget is cut down to windows.
pub const WINDOW_CONTEXT_BYTES: usize = 200;

/// The origin prefix of Rule 0010 in the bundled Rule Pack, whose credential
/// patterns mask their hits in every request.
const CREDENTIAL_RULE: &str = "0010-";

/// Counts the tokens a text takes in one engine's context. Each engine ticket
/// supplies its own; the builder only ever asks.
pub trait TokenCounter {
    /// How many tokens the text takes.
    fn tokens(&self, text: &str) -> usize;
}

/// The byte estimate: [`BYTES_PER_TOKEN`] bytes to a token, rounded up.
#[derive(Clone, Copy, Debug, Default)]
pub struct ByteEstimate;

impl TokenCounter for ByteEstimate {
    fn tokens(&self, text: &str) -> usize {
        text.len().div_ceil(BYTES_PER_TOKEN)
    }
}

/// The home directory and the username a request normalises to `~` and
/// `user`, so neither leaves the machine.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Normalisation {
    home: String,
    user: String,
}

impl Normalisation {
    /// Normalises this home directory and this username.
    pub fn new(home: &Path, user: &str) -> Normalisation {
        let home = home.display().to_string();
        let home = home.trim_end_matches('/');
        Normalisation {
            home: home.to_string(),
            user: user.to_string(),
        }
    }

    /// Normalises a home directory and the username its last component names.
    pub fn of_home(home: &Path) -> Normalisation {
        let user = home
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        Normalisation::new(home, &user)
    }

    /// Normalises the home directory the Host hands the adapters, and the
    /// username it names. A Host with no home normalises nothing.
    pub fn of_host(host: &Host) -> Normalisation {
        host.home().map(Normalisation::of_home).unwrap_or_default()
    }

    /// Every place the home directory or the username appears in some bytes.
    fn spans(&self, bytes: &[u8]) -> Vec<Span> {
        let mut spans = Vec::new();
        if !self.home.is_empty() {
            let mut homes = vec![self.home.clone()];
            // A temporary directory on macOS is reached both through `/var` and
            // through `/private/var`; either spelling is the same home.
            if let Some(rest) = self.home.strip_prefix("/private") {
                homes.push(rest.to_string());
            } else if ["/var/", "/tmp/", "/etc/"]
                .iter()
                .any(|prefix| self.home.starts_with(prefix))
            {
                homes.push(format!("/private{}", self.home));
            }
            for home in homes {
                for start in occurrences(bytes, home.as_bytes()) {
                    let end = start + home.len();
                    let continues = bytes.get(end).is_some_and(|&next| {
                        next.is_ascii_alphanumeric() || b"_.-".contains(&next)
                    });
                    if !continues {
                        spans.push(Span {
                            range: start..end,
                            put: Put::Text("~"),
                        });
                    }
                }
            }
        }
        if !self.user.is_empty() {
            for start in occurrences(bytes, self.user.as_bytes()) {
                let end = start + self.user.len();
                let before = start
                    .checked_sub(1)
                    .and_then(|at| bytes.get(at))
                    .is_some_and(u8::is_ascii_alphanumeric);
                let after = bytes.get(end).is_some_and(u8::is_ascii_alphanumeric);
                if !before && !after {
                    spans.push(Span {
                        range: start..end,
                        put: Put::Text("user"),
                    });
                }
            }
        }
        spans
    }
}

/// Why no Judgement Request was built for an Item, so the caller records no
/// Verdict and the Item stays Ambiguous.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoRequest {
    /// Even cut down to windows around every match, the request is over the
    /// engine's budget.
    TooLarge {
        /// What the windowed request measured.
        tokens: usize,
        /// The budget it had to fit.
        budget: usize,
    },
    /// The credential patterns could not be run over the content, so the
    /// redaction cannot be vouched for.
    Redaction(String),
}

impl fmt::Display for NoRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoRequest::TooLarge { tokens, budget } => write!(
                f,
                "too large: the request takes {tokens} tokens even in windows, the budget is {budget}"
            ),
            NoRequest::Redaction(reason) => write!(f, "the redaction could not run: {reason}"),
        }
    }
}

impl std::error::Error for NoRequest {}

/// The facts about the Item a request carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestFacts {
    /// The Surface kind.
    pub kind: String,
    /// File, tree or entry.
    pub shape: String,
    /// Managed, User or Project, without the project root.
    pub scope: String,
    /// The Provenance class.
    pub provenance: String,
    /// The Activation.
    pub activation: String,
    /// Why the Item is inactive, empty unless it is.
    pub activation_reason: String,
}

/// One fired Heuristic as a request carries it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHeuristic {
    /// The integer id of the Heuristic.
    pub id: i64,
    /// The one sentence the Simple Posture shows.
    pub plain: String,
    /// The redacted text its first match landed on, empty when it matched no
    /// pattern.
    pub excerpt: String,
}

/// One piece of the Item's content in a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestContent {
    /// The file within a tree, empty for a file or an entry Item.
    pub file: String,
    /// The redacted text, whole or in windows.
    pub text: String,
    /// True when the text is windows around the matches with elision markers
    /// between them rather than the whole content.
    pub windowed: bool,
}

/// The one engine-independent Judgement Request for one Item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JudgementRequest {
    /// The Item's facts.
    pub facts: RequestFacts,
    /// The fired Heuristics, in id order.
    pub heuristics: Vec<RequestHeuristic>,
    /// The content, the entry point of a tree first.
    pub content: Vec<RequestContent>,
    serialised: String,
    hash: String,
}

impl JudgementRequest {
    /// The request in its one canonical serialisation: JSON with sorted keys
    /// and no insignificant whitespace. This is what is measured, what is
    /// hashed and what an engine is handed.
    pub fn serialised(&self) -> &str {
        &self.serialised
    }

    /// The sha256 of the canonical serialisation, lower-case hex: the part of
    /// the Verdict cache key that stands for the request.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// True when any piece of the content was cut down to windows.
    pub fn is_windowed(&self) -> bool {
        self.content.iter().any(|piece| piece.windowed)
    }

    fn assemble(
        facts: RequestFacts,
        heuristics: Vec<RequestHeuristic>,
        content: Vec<RequestContent>,
    ) -> JudgementRequest {
        let mut request = JudgementRequest {
            facts,
            heuristics,
            content,
            serialised: String::new(),
            hash: String::new(),
        };
        let bytes = canonical_entry(&request.to_value());
        request.hash = sha256_hex(&bytes);
        request.serialised = String::from_utf8_lossy(&bytes).to_string();
        request
    }

    fn to_value(&self) -> Value {
        let mut facts = Map::new();
        facts.insert(
            "activation".into(),
            Value::from(self.facts.activation.as_str()),
        );
        facts.insert(
            "activation_reason".into(),
            Value::from(self.facts.activation_reason.as_str()),
        );
        facts.insert("kind".into(), Value::from(self.facts.kind.as_str()));
        facts.insert(
            "provenance".into(),
            Value::from(self.facts.provenance.as_str()),
        );
        facts.insert("scope".into(), Value::from(self.facts.scope.as_str()));
        facts.insert("shape".into(), Value::from(self.facts.shape.as_str()));
        let heuristics = self
            .heuristics
            .iter()
            .map(|heuristic| {
                let mut line = Map::new();
                line.insert("excerpt".into(), Value::from(heuristic.excerpt.as_str()));
                line.insert("id".into(), Value::from(heuristic.id));
                line.insert("plain".into(), Value::from(heuristic.plain.as_str()));
                Value::Object(line)
            })
            .collect();
        let content = self
            .content
            .iter()
            .map(|piece| {
                let mut part = Map::new();
                part.insert("file".into(), Value::from(piece.file.as_str()));
                part.insert("text".into(), Value::from(piece.text.as_str()));
                part.insert("windowed".into(), Value::from(piece.windowed));
                Value::Object(part)
            })
            .collect();
        let mut request = Map::new();
        request.insert("content".into(), Value::Array(content));
        request.insert("facts".into(), Value::Object(facts));
        request.insert("heuristics".into(), Value::Array(heuristics));
        Value::Object(request)
    }
}

/// Builds Judgement Requests under one engine's budget and token counter.
pub struct RequestBuilder<'c> {
    normalisation: Normalisation,
    budget: usize,
    counter: &'c dyn TokenCounter,
}

impl fmt::Debug for RequestBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestBuilder")
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl<'c> RequestBuilder<'c> {
    /// A builder that normalises one home and username and fits requests into
    /// `budget` tokens as `counter` counts them.
    pub fn new(
        normalisation: Normalisation,
        budget: usize,
        counter: &'c dyn TokenCounter,
    ) -> RequestBuilder<'c> {
        RequestBuilder {
            normalisation,
            budget,
            counter,
        }
    }

    /// The request for one Item and the Threat Heuristics that fired on it,
    /// as a Scan's Assessment holds them.
    ///
    /// The whole content when it fits; windows around every match when it
    /// does not; [`NoRequest::TooLarge`] when even the windows do not.
    pub fn build(
        &self,
        item: &Item,
        fired: &[FiredHeuristic],
    ) -> Result<JudgementRequest, NoRequest> {
        let pieces = self.pieces(item, fired)?;
        let facts = RequestFacts {
            kind: item.kind.as_str().to_string(),
            shape: item.shape.as_str().to_string(),
            scope: item.scope.as_str().to_string(),
            provenance: item.provenance.as_str().to_string(),
            activation: item.activation.as_str().to_string(),
            activation_reason: item.activation.reason().to_string(),
        };
        let heuristics: Vec<RequestHeuristic> = fired
            .iter()
            .map(|heuristic| RequestHeuristic {
                id: heuristic.id,
                plain: heuristic.plain.clone(),
                excerpt: pieces
                    .iter()
                    .find(|piece| piece.file == heuristic.file)
                    .map(|piece| piece.excerpt(heuristic))
                    .unwrap_or_default(),
            })
            .collect();

        let whole = JudgementRequest::assemble(
            facts.clone(),
            heuristics.clone(),
            pieces.iter().map(Piece::whole).collect(),
        );
        if self.counter.tokens(whole.serialised()) <= self.budget {
            return Ok(whole);
        }
        let windowed = JudgementRequest::assemble(
            facts,
            heuristics,
            pieces.iter().map(Piece::windowed).collect(),
        );
        let tokens = self.counter.tokens(windowed.serialised());
        if tokens <= self.budget {
            return Ok(windowed);
        }
        Err(NoRequest::TooLarge {
            tokens,
            budget: self.budget,
        })
    }

    /// The redacted pieces of content the request carries, with every match
    /// of a fired Heuristic placed in the redacted text.
    fn pieces(&self, item: &Item, fired: &[FiredHeuristic]) -> Result<Vec<Piece>, NoRequest> {
        let mut pieces = Vec::new();
        for unit in selected_units(item, fired) {
            // A file name inside a tree is the user's to choose, so it is
            // normalised like the content.
            let label = unit.file.as_bytes();
            let file = Redacted::of(label, resolve(self.normalisation.spans(label))).text;
            if !is_text(unit.file_type) {
                pieces.push(Piece {
                    unit: unit.file.to_string(),
                    file,
                    redacted: Redacted::plain(format!(
                        "[not text: {}, {} bytes]",
                        unit.file_type.as_str(),
                        unit.bytes.len()
                    )),
                    matches: Vec::new(),
                });
                continue;
            }
            let mut spans = self.normalisation.spans(unit.bytes);
            spans.extend(credential_spans(unit.bytes)?);
            spans.extend(sensitive_match_spans(fired, unit.file, unit.bytes.len()));
            if item.shape != Shape::Tree {
                spans.extend(entry_spans(item));
                spans.extend(env_file_spans(item));
            }
            let redacted = Redacted::of(unit.bytes, resolve(spans));
            let matches = fired
                .iter()
                .filter(|heuristic| heuristic.file == unit.file)
                .flat_map(|heuristic| heuristic.matches.iter())
                .map(|found| redacted.place(found.range.clone()))
                .collect();
            pieces.push(Piece {
                unit: unit.file.to_string(),
                file,
                redacted,
                matches,
            });
        }
        Ok(pieces)
    }
}

/// One unit of the Item the request carries content from.
struct Unit<'a> {
    file: &'a str,
    bytes: &'a [u8],
    file_type: FileType,
}

/// The units the request carries: the canonical entry, the whole file, or a
/// tree's entry point followed by only the files a Heuristic matched in, in
/// path order.
fn selected_units<'a>(item: &'a Item, fired: &[FiredHeuristic]) -> Vec<Unit<'a>> {
    if item.shape != Shape::Tree {
        return vec![Unit {
            file: "",
            bytes: &item.content,
            file_type: item.facts.file_type,
        }];
    }
    let entry_point = entry_point(item.kind).filter(|path| item.tree.holds(path));
    let mut matched: Vec<&str> = fired
        .iter()
        .map(|heuristic| heuristic.file.as_str())
        .filter(|file| !file.is_empty() && Some(*file) != entry_point)
        .collect();
    matched.sort_unstable();
    matched.dedup();
    entry_point
        .into_iter()
        .chain(matched)
        .filter_map(|path| item.tree.file(path))
        .map(|file| Unit {
            file: &file.path,
            bytes: &file.content,
            file_type: file.facts.file_type,
        })
        .collect()
}

/// The file an Agent reads first in a tree of this kind.
fn entry_point(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Skill => Some("SKILL.md"),
        Kind::Plugin => Some(".claude-plugin/plugin.json"),
        Kind::Marketplace => Some(".claude-plugin/marketplace.json"),
        _ => None,
    }
}

/// True for the file types whose bytes are text worth reading. An archive, an
/// executable or an image is named by its type and size instead.
fn is_text(file_type: FileType) -> bool {
    matches!(file_type, FileType::Text | FileType::Unknown)
}

/// One unit of content, redacted, with the matches placed in the redacted
/// text.
struct Piece {
    /// The unit's file as the Heuristics name it.
    unit: String,
    /// The file as the request names it, normalised.
    file: String,
    redacted: Redacted,
    /// Every match of a fired Heuristic in this unit, in redacted offsets.
    matches: Vec<Range<usize>>,
}

impl Piece {
    fn whole(&self) -> RequestContent {
        RequestContent {
            file: self.file.clone(),
            text: self.redacted.text.clone(),
            windowed: false,
        }
    }

    fn windowed(&self) -> RequestContent {
        RequestContent {
            file: self.file.clone(),
            text: self.redacted.windows(&self.matches),
            windowed: true,
        }
    }

    /// The redacted text the first match of a Heuristic landed on, control
    /// characters as spaces, cut with a visible `...` past
    /// [`EXCERPT_CHARS`].
    fn excerpt(&self, heuristic: &FiredHeuristic) -> String {
        debug_assert_eq!(self.unit, heuristic.file);
        let Some(first) = heuristic
            .matches
            .iter()
            .min_by_key(|found| (found.range.start, found.range.end))
        else {
            return String::new();
        };
        let placed = self.redacted.place(first.range.clone());
        let text: String = self.redacted.text[placed]
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        match text.chars().count() > EXCERPT_CHARS {
            true => format!(
                "{}...",
                text.chars().take(EXCERPT_CHARS).collect::<String>()
            ),
            false => text,
        }
    }
}

/// The marker that stands where content was left out of a windowed request.
pub fn elision_marker(bytes: usize) -> String {
    format!("\n[... {bytes} bytes elided by AgentSweep ...]\n")
}

/// What one span of the original bytes is replaced with.
#[derive(Clone, Debug)]
enum Put {
    /// A redaction placeholder `<redacted:type:len>`. The length is the
    /// value's own where an adapter field states it, otherwise the characters
    /// the span covers. A quoted placeholder replaces a whole JSON string, so
    /// an entry stays JSON.
    Mask {
        kind: String,
        len: Option<usize>,
        quoted: bool,
    },
    /// A fixed replacement: `~` for the home directory, `user` for the name.
    Text(&'static str),
}

#[derive(Clone, Debug)]
struct Span {
    range: Range<usize>,
    put: Put,
}

impl Span {
    fn mask(range: Range<usize>, kind: &str) -> Span {
        Span {
            range,
            put: Put::Mask {
                kind: kind.to_string(),
                len: None,
                quoted: false,
            },
        }
    }

    fn is_mask(&self) -> bool {
        matches!(self.put, Put::Mask { .. })
    }
}

/// Turns overlapping spans into disjoint ones, in order.
///
/// A redaction always wins: spans that overlap a placeholder are folded into
/// one placeholder over all of them, so no part of a sensitive value and no
/// part of a home path next to one survives. Normalisations that overlap each
/// other keep the longest, which is how the username inside the home path
/// goes with the home path.
fn resolve(mut spans: Vec<Span>) -> Vec<Span> {
    spans.retain(|span| span.range.start < span.range.end);
    spans.sort_by_key(|span| (span.range.start, Reverse(span.range.end)));
    let mut resolved = Vec::new();
    let mut index = 0;
    while index < spans.len() {
        let start = spans[index].range.start;
        let mut end = spans[index].range.end;
        let mut last = index + 1;
        while last < spans.len() && spans[last].range.start < end {
            end = end.max(spans[last].range.end);
            last += 1;
        }
        let cluster = &spans[index..last];
        index = last;
        if let Some(first_mask) = cluster.iter().find(|span| span.is_mask()) {
            match cluster
                .iter()
                .find(|span| span.is_mask() && span.range == (start..end))
            {
                Some(covering) => resolved.push(covering.clone()),
                None => {
                    let Put::Mask { kind, .. } = &first_mask.put else {
                        unreachable!("a mask was found")
                    };
                    resolved.push(Span::mask(start..end, kind));
                }
            }
            continue;
        }
        let mut kept_end = 0;
        for span in cluster {
            if span.range.start >= kept_end {
                kept_end = span.range.end;
                resolved.push(span.clone());
            }
        }
    }
    resolved
}

/// One stretch of the redacted text and the stretch of original bytes it
/// came from.
#[derive(Clone, Debug)]
struct Segment {
    original: Range<usize>,
    redacted: Range<usize>,
    replaced: bool,
}

/// Bytes with every span replaced, and the map back to the original offsets.
#[derive(Clone, Debug)]
struct Redacted {
    original: Vec<u8>,
    text: String,
    segments: Vec<Segment>,
}

impl Redacted {
    /// A text with nothing to map: what stands in for a file that is not text.
    fn plain(text: String) -> Redacted {
        Redacted {
            original: Vec::new(),
            segments: Vec::new(),
            text,
        }
    }

    /// The bytes with the disjoint, ordered spans replaced.
    fn of(bytes: &[u8], spans: Vec<Span>) -> Redacted {
        let mut text = String::new();
        let mut segments = Vec::new();
        let mut at = 0;
        let copy = |range: Range<usize>, text: &mut String, segments: &mut Vec<Segment>| {
            if range.is_empty() {
                return;
            }
            let start = text.len();
            text.push_str(&String::from_utf8_lossy(&bytes[range.clone()]));
            segments.push(Segment {
                original: range,
                redacted: start..text.len(),
                replaced: false,
            });
        };
        for span in spans {
            let range = span.range.start.min(bytes.len())..span.range.end.min(bytes.len());
            if range.start < at || range.is_empty() {
                continue;
            }
            copy(at..range.start, &mut text, &mut segments);
            let start = text.len();
            match &span.put {
                Put::Mask { kind, len, quoted } => {
                    let len = len.unwrap_or_else(|| {
                        String::from_utf8_lossy(&bytes[range.clone()])
                            .chars()
                            .count()
                    });
                    let placeholder = format!("<redacted:{kind}:{len}>");
                    match quoted {
                        true => text.push_str(&format!("\"{placeholder}\"")),
                        false => text.push_str(&placeholder),
                    }
                }
                Put::Text(replacement) => text.push_str(replacement),
            }
            segments.push(Segment {
                original: range.clone(),
                redacted: start..text.len(),
                replaced: true,
            });
            at = range.end;
        }
        copy(at..bytes.len(), &mut text, &mut segments);
        Redacted {
            original: bytes.to_vec(),
            text,
            segments,
        }
    }

    /// Where a range of the original bytes lies in the redacted text. A range
    /// that touches a replacement takes the whole replacement with it, so a
    /// match never shows half a placeholder.
    fn place(&self, range: Range<usize>) -> Range<usize> {
        let start = self.offset(range.start, false);
        let end = self.offset(range.end, true).max(start);
        start..end
    }

    fn offset(&self, at: usize, is_end: bool) -> usize {
        let found = self.segments.iter().find(|segment| match is_end {
            false => segment.original.start <= at && at < segment.original.end,
            true => segment.original.start < at && at <= segment.original.end,
        });
        let Some(segment) = found else {
            return if at == 0 { 0 } else { self.text.len() };
        };
        if segment.replaced {
            return match is_end {
                false => segment.redacted.start,
                true => segment.redacted.end,
            };
        }
        let prefix = String::from_utf8_lossy(&self.original[segment.original.start..at]).len();
        let mut offset = (segment.redacted.start + prefix).min(segment.redacted.end);
        while !self.text.is_char_boundary(offset) {
            offset -= 1;
        }
        offset
    }

    /// The text cut down to windows of [`WINDOW_CONTEXT_BYTES`] around each
    /// match, with an elision marker wherever something was left out,
    /// including before the first window and after the last. A unit with no
    /// match is one marker.
    fn windows(&self, matches: &[Range<usize>]) -> String {
        let len = self.text.len();
        let mut windows: Vec<Range<usize>> = matches
            .iter()
            .map(|found| {
                let mut start = found.start.saturating_sub(WINDOW_CONTEXT_BYTES);
                let mut end = (found.end + WINDOW_CONTEXT_BYTES).min(len);
                for segment in self.segments.iter().filter(|segment| segment.replaced) {
                    let inside = segment.redacted.start + 1..segment.redacted.end;
                    if inside.contains(&start) {
                        start = segment.redacted.start;
                    }
                    if inside.contains(&end) {
                        end = segment.redacted.end;
                    }
                }
                while !self.text.is_char_boundary(start) {
                    start -= 1;
                }
                while !self.text.is_char_boundary(end) {
                    end += 1;
                }
                start..end
            })
            .collect();
        windows.sort_by_key(|window| window.start);
        let mut merged: Vec<Range<usize>> = Vec::new();
        for window in windows {
            match merged.last_mut() {
                Some(last) if window.start <= last.end => last.end = last.end.max(window.end),
                _ => merged.push(window),
            }
        }
        let mut out = String::new();
        let mut at = 0;
        for window in merged {
            if window.start > at {
                out.push_str(&elision_marker(window.start - at));
            }
            out.push_str(&self.text[window.clone()]);
            at = window.end;
        }
        if at < len {
            out.push_str(&elision_marker(len - at));
        }
        out
    }
}

/// Every start offset of a needle in some bytes, without overlaps.
fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() {
        return found;
    }
    let mut at = 0;
    while at + needle.len() <= haystack.len() {
        if &haystack[at..at + needle.len()] == needle {
            found.push(at);
            at += needle.len();
        } else {
            at += 1;
        }
    }
    found
}

/// The credential patterns of Rule 0010, compiled once into a rule that fires
/// on any of them in any bytes.
///
/// Rule 0010 itself only looks at MCP entries; its well-formed key patterns
/// are what the request masks in free text of every kind. They are read from
/// the bundled Rule Pack's own source, so the redaction and the Rule never
/// drift apart: a pattern added to Rule 0010 is masked here from that build on.
fn credential_rules() -> Result<&'static Rules, NoRequest> {
    static RULES: OnceLock<Result<Rules, String>> = OnceLock::new();
    RULES
        .get_or_init(|| {
            let source = credential_source().ok_or("Rule 0010 has no credential patterns")?;
            let mut compiler = Compiler::new();
            compiler
                .add_source(source.as_str())
                .map_err(|error| error.to_string())?;
            Ok(compiler.build())
        })
        .as_ref()
        .map_err(|reason| NoRequest::Redaction(reason.clone()))
}

/// The rule text that carries Rule 0010's `$key_*` patterns.
fn credential_source() -> Option<String> {
    let rule = BUNDLED_RULES
        .iter()
        .find(|source| source.origin.starts_with(CREDENTIAL_RULE))?;
    let patterns: Vec<&str> = rule
        .source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("$key_") && line.contains('='))
        .collect();
    if patterns.is_empty() {
        return None;
    }
    Some(format!(
        "rule credential_patterns {{\n  strings:\n    {}\n  condition:\n    any of them\n}}\n",
        patterns.join("\n    ")
    ))
}

/// A placeholder over every hit of a credential pattern, named after the
/// pattern (`$key_github` masks as `github`). A private key block is masked
/// from its first line to its last, not only the line the pattern knows.
fn credential_spans(bytes: &[u8]) -> Result<Vec<Span>, NoRequest> {
    let rules = credential_rules()?;
    let mut scanner = Scanner::new(rules);
    let results = scanner
        .scan(bytes)
        .map_err(|error| NoRequest::Redaction(error.to_string()))?;
    let mut spans = Vec::new();
    for rule in results.matching_rules() {
        for pattern in rule.patterns() {
            let kind = pattern.identifier().trim_start_matches("$key_");
            for found in pattern.matches() {
                let mut range = found.range();
                if bytes[range.clone()].starts_with(b"-----BEGIN") {
                    range.end = private_key_end(bytes, range.end);
                }
                spans.push(Span::mask(range, kind));
            }
        }
    }
    Ok(spans)
}

/// Where a private key block that starts before `from` ends: after its
/// `-----END ... PRIVATE KEY-----` line, or at the end of the bytes when the
/// block is never closed.
fn private_key_end(bytes: &[u8], from: usize) -> usize {
    let closing = b"PRIVATE KEY-----";
    occurrences(&bytes[from..], b"-----END")
        .into_iter()
        .find_map(|at| {
            let rest = &bytes[from + at..];
            let line_end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
            occurrences(&rest[..line_end], closing)
                .first()
                .map(|close| from + at + close + closing.len())
        })
        .unwrap_or(bytes.len())
}

/// A placeholder over every match of a fired Heuristic marked `sensitive` in
/// this unit, named after its pattern (the owner's decision of 2026-10-14):
/// the engine judges the context around it and never the value.
fn sensitive_match_spans(fired: &[FiredHeuristic], file: &str, len: usize) -> Vec<Span> {
    fired
        .iter()
        .filter(|heuristic| heuristic.sensitive && heuristic.file == file)
        .flat_map(|heuristic| heuristic.matches.iter())
        .map(|found| {
            let kind = found.pattern.trim_start_matches('$');
            let kind = if kind.is_empty() { "match" } else { kind };
            Span::mask(found.range.start.min(len)..found.range.end.min(len), kind)
        })
        .collect()
}

/// The fields of an entry whose values are credentials: the core's own list
/// for the kind, and the `http_headers` block a Codex MCP table writes its
/// headers in.
fn request_sensitive_fields(kind: Kind) -> Vec<&'static str> {
    let mut fields = sensitive_fields(kind).to_vec();
    if kind == Kind::McpServer {
        fields.push("http_headers");
    }
    fields
}

/// A quoted placeholder over every value inside a sensitive field of an
/// entry: a scalar below `env`, `headers` or `http_headers`, or every scalar
/// of an entry that is such a block or one member of it (a settings entry
/// `env.ANTHROPIC_BASE_URL`). The keys stay; they say what is configured
/// without saying the value.
///
/// The spans are found by writing the entry's canonical form again while
/// noting where each sensitive value lands. Where that does not give back the
/// Item's bytes exactly, the whole entry is masked: a value that might be a
/// secret is redacted rather than guessed about.
fn entry_spans(item: &Item) -> Vec<Span> {
    if item.shape != Shape::Entry {
        return Vec::new();
    }
    let names = request_sensitive_fields(item.kind);
    if names.is_empty() {
        return Vec::new();
    }
    let whole = vec![Span::mask(0..item.content.len(), "entry")];
    let Ok(value) = serde_json::from_slice::<Value>(&item.content) else {
        return whole;
    };
    let inherited = item
        .inside_file()
        .split(['/', '.'])
        .find(|segment| names.contains(segment))
        .map(str::to_string);
    let mut written = Vec::new();
    let mut spans = Vec::new();
    write_noting(&value, inherited, &names, &mut written, &mut spans);
    if written != item.content {
        return whole;
    }
    spans
}

fn write_noting(
    value: &Value,
    sensitive: Option<String>,
    names: &[&str],
    out: &mut Vec<u8>,
    spans: &mut Vec<Span>,
) {
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort();
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend(canonical_entry(&Value::String(key.clone())));
                out.push(b':');
                let below = sensitive.clone().or_else(|| {
                    key.split('.')
                        .find(|segment| names.contains(segment))
                        .map(str::to_string)
                });
                write_noting(&fields[key], below, names, out, spans);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_noting(item, sensitive.clone(), names, out, spans);
            }
            out.push(b']');
        }
        scalar => {
            let start = out.len();
            out.extend(canonical_entry(scalar));
            if let Some(kind) = sensitive {
                spans.push(Span {
                    range: start..out.len(),
                    put: Put::Mask {
                        kind,
                        len: Some(value_string(scalar).chars().count()),
                        quoted: true,
                    },
                });
            }
        }
    }
}

/// A placeholder over every value of an env file: what follows the `=` of an
/// assignment, a whole line that is not one, and the text of a comment, which
/// is where a key that was switched off still sits. The key names stay.
fn env_file_spans(item: &Item) -> Vec<Span> {
    if item.kind != Kind::EnvFile {
        return Vec::new();
    }
    if item.shape != Shape::File {
        return vec![Span::mask(0..item.content.len(), "env_value")];
    }
    let bytes = &item.content;
    let mut spans = Vec::new();
    let mut line_start = 0;
    while line_start < bytes.len() {
        let line_end = bytes[line_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|at| line_start + at)
            .unwrap_or(bytes.len());
        let line = &bytes[line_start..line_end];
        let trimmed_start = line
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(line.len());
        let trimmed_end = line
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map(|at| at + 1)
            .unwrap_or(0);
        if trimmed_start < trimmed_end {
            let content = &line[trimmed_start..trimmed_end];
            let (value_start, kind) = if content.starts_with(b"#") {
                (trimmed_start + 1, "env_comment")
            } else {
                match content.iter().position(|&b| b == b'=') {
                    Some(at) => (trimmed_start + at + 1, "env_value"),
                    None => (trimmed_start, "env_value"),
                }
            };
            if value_start < trimmed_end {
                spans.push(Span::mask(
                    line_start + value_start..line_start + trimmed_end,
                    kind,
                ));
            }
        }
        line_start = line_end + 1;
    }
    spans
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::item::{Activation, Provenance, Scope};

    #[test]
    fn the_credential_rule_carries_every_key_pattern_of_rule_0010() {
        let source = credential_source().expect("Rule 0010 is bundled");
        for pattern in [
            "$key_aws",
            "$key_github",
            "$key_github_pat",
            "$key_anthropic",
            "$key_openai",
            "$key_slack",
            "$key_google",
            "$key_pem",
            "$key_db_url",
        ] {
            assert!(source.contains(pattern), "{pattern} in {source}");
        }
        // A reference to a variable is not a credential, so it is not masked.
        assert!(!source.contains("$forward_anthropic"));
        assert!(credential_rules().is_ok());
        assert!(
            credential_spans(b"token = ${GITHUB_TOKEN}")
                .expect("a scan")
                .is_empty()
        );
    }

    #[test]
    fn a_mask_swallows_whatever_overlaps_it_and_the_longest_normalisation_wins() {
        let bytes = b"/home/kim/a sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx";
        let spans = vec![
            Span {
                range: 0..9,
                put: Put::Text("~"),
            },
            Span {
                range: 6..9,
                put: Put::Text("user"),
            },
            Span::mask(12..bytes.len(), "anthropic"),
            Span {
                range: 10..14,
                put: Put::Text("user"),
            },
        ];
        let redacted = Redacted::of(bytes, resolve(spans));
        assert_eq!(redacted.text, "~/<redacted:anthropic:33>");
        // A match inside the masked value is placed on the whole placeholder.
        assert_eq!(
            &redacted.text[redacted.place(20..24)],
            "<redacted:anthropic:33>"
        );
        assert_eq!(&redacted.text[redacted.place(9..10)], "/");
    }

    fn entry(kind: Kind, locator: &str, content: &[u8]) -> Item {
        Item::entry(
            "claude-code",
            Scope::User,
            kind,
            locator,
            PathBuf::from("/home/kim/.claude.json"),
            Provenance::Manual,
            Activation::Active,
            content.to_vec(),
        )
    }

    #[test]
    fn an_entry_whose_bytes_are_not_its_canonical_form_is_masked_whole() {
        let item = entry(
            Kind::McpServer,
            "~/.claude.json#/mcpServers/x",
            br#"{ "env": {"A": "plain-value"}, "command": "x" }"#,
        );
        let spans = entry_spans(&item);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].range, 0..item.content.len());
    }

    #[test]
    fn an_entry_of_a_kind_without_sensitive_fields_is_left_alone() {
        let item = entry(
            Kind::Hook,
            "~/.claude/settings.json#PreToolUse",
            &canonical_entry(&serde_json::json!({"env": {"A": "b"}})),
        );
        assert!(entry_spans(&item).is_empty());
    }

    #[test]
    fn an_env_file_keeps_its_keys_and_blank_lines() {
        let item = Item::file(
            "workspace",
            Scope::User,
            Kind::EnvFile,
            ".env",
            PathBuf::from("/home/kim/.env"),
            Provenance::Unknown,
            Activation::Active,
            b"A=1\n\n  B = two  \nC=\n".to_vec(),
        );
        let redacted = Redacted::of(&item.content, resolve(env_file_spans(&item)));
        assert_eq!(
            redacted.text,
            "A=<redacted:env_value:1>\n\n  B =<redacted:env_value:4>  \nC=\n"
        );
    }

    #[test]
    fn a_private_key_block_is_masked_to_its_closing_line() {
        let block = format!(
            "x\n-----BEGIN {0}-----\nbody\n-----END {0}-----\ny",
            "RSA PRIVATE KEY"
        );
        let spans = credential_spans(block.as_bytes()).expect("a scan");
        let redacted = Redacted::of(block.as_bytes(), resolve(spans));
        assert!(redacted.text.starts_with("x\n<redacted:pem:"));
        assert!(redacted.text.ends_with(">\ny"), "{}", redacted.text);
        assert!(!redacted.text.contains("body"));
    }

    #[test]
    fn the_byte_estimate_is_three_bytes_to_a_token_rounded_up() {
        assert_eq!(ByteEstimate.tokens(""), 0);
        assert_eq!(ByteEstimate.tokens("abc"), 1);
        assert_eq!(ByteEstimate.tokens("abcd"), 2);
    }
}
