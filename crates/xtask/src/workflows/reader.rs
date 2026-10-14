//! A reader for the subset of YAML a GitHub workflow is written in.
//!
//! The hardening rules read text and nothing else, so this is a reader, not a
//! YAML implementation: block maps and sequences by indentation, `- key:`
//! items, literal and folded block scalars, single line flow sequences and
//! maps, quoted and plain scalars, and comments, each node with the line it
//! starts on. Anchors, aliases, tags and multi-document streams are not read;
//! a workflow that needs them is reported as unreadable rather than guessed at.

/// A node of a workflow, with the line it starts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A scalar; an empty value is the empty scalar on its key's line.
    Scalar(Scalar),
    /// A block or flow map, entries in file order.
    Map(Vec<Entry>),
    /// A block or flow sequence, items in file order.
    Seq(Vec<Node>),
}

/// A scalar with the line its text starts on and its trailing comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar {
    /// The text, unquoted. A block scalar keeps one text line per file line.
    pub text: String,
    /// The line of the first text line, counted from one.
    pub line: usize,
    /// The trailing comment of the line, without the `#`, if there is one.
    pub comment: Option<String>,
}

/// One entry of a map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The key, unquoted.
    pub key: String,
    /// The line the key sits on, counted from one.
    pub line: usize,
    /// The value.
    pub value: Node,
}

impl Node {
    /// The value under `key` when this is a map.
    pub fn get(&self, key: &str) -> Option<&Entry> {
        match self {
            Node::Map(entries) => entries.iter().find(|entry| entry.key == key),
            _ => None,
        }
    }

    /// The text when this is a scalar.
    pub fn text(&self) -> Option<&str> {
        match self {
            Node::Scalar(scalar) => Some(&scalar.text),
            _ => None,
        }
    }

    /// The scalar texts of a sequence, or the one text of a scalar.
    pub fn texts(&self) -> Vec<&str> {
        match self {
            Node::Scalar(scalar) if scalar.text.is_empty() => Vec::new(),
            Node::Scalar(scalar) => vec![scalar.text.as_str()],
            Node::Seq(items) => items.iter().filter_map(Node::text).collect(),
            Node::Map(_) => Vec::new(),
        }
    }
}

struct Line {
    number: usize,
    indent: usize,
    text: String,
    comment: Option<String>,
    raw: String,
}

impl Line {
    fn is_structural(&self) -> bool {
        !self.text.is_empty()
    }
}

/// Reads a workflow's text into its root node.
pub fn read(text: &str) -> Result<Node, String> {
    let lines = text
        .lines()
        .enumerate()
        .map(|(index, raw)| {
            let indent = raw.len() - raw.trim_start_matches(' ').len();
            let (content, comment) = split_comment(&raw[indent..]);
            Line {
                number: index + 1,
                indent,
                text: content.trim_end().to_string(),
                comment,
                raw: raw.to_string(),
            }
        })
        .collect();
    let mut reader = Reader { lines, pos: 0 };
    let Some(first) = reader.next_structural() else {
        return Ok(Node::Map(Vec::new()));
    };
    if reader.lines[first].text == "---" {
        reader.pos = first + 1;
    }
    let Some(first) = reader.next_structural() else {
        return Ok(Node::Map(Vec::new()));
    };
    let indent = reader.lines[first].indent;
    let root = reader.node(indent)?;
    if let Some(left) = reader.next_structural() {
        return Err(format!(
            "line {}: unexpected indentation",
            reader.lines[left].number
        ));
    }
    Ok(root)
}

struct Reader {
    lines: Vec<Line>,
    pos: usize,
}

impl Reader {
    fn next_structural(&mut self) -> Option<usize> {
        while self.pos < self.lines.len() && !self.lines[self.pos].is_structural() {
            self.pos += 1;
        }
        (self.pos < self.lines.len()).then_some(self.pos)
    }

    fn node(&mut self, indent: usize) -> Result<Node, String> {
        let index = self.next_structural().expect("the caller saw a line");
        if is_seq_item(&self.lines[index].text) {
            self.seq(indent)
        } else {
            self.map(indent)
        }
    }

    fn seq(&mut self, indent: usize) -> Result<Node, String> {
        let mut items = Vec::new();
        while let Some(index) = self.next_structural() {
            let line = &self.lines[index];
            if line.indent != indent || !is_seq_item(&line.text) {
                break;
            }
            let after_dash = &line.text[1..];
            let rest = after_dash.trim_start();
            let offset = 1 + after_dash.len() - rest.len();
            if rest.is_empty() {
                let number = line.number;
                self.pos = index + 1;
                items.push(self.nested_or_empty(indent, number)?);
            } else if split_key(rest).is_some() {
                let rest = rest.to_string();
                let line = &mut self.lines[index];
                line.indent += offset;
                line.text = rest;
                let inner = line.indent;
                items.push(self.map(inner)?);
            } else {
                let rest = rest.to_string();
                self.pos = index + 1;
                items.push(self.inline_value(index, &rest, indent));
            }
        }
        Ok(Node::Seq(items))
    }

    fn map(&mut self, indent: usize) -> Result<Node, String> {
        let mut entries = Vec::new();
        while let Some(index) = self.next_structural() {
            let line = &self.lines[index];
            if line.indent < indent || (line.indent == indent && is_seq_item(&line.text)) {
                break;
            }
            if line.indent > indent {
                return Err(format!("line {}: unexpected indentation", line.number));
            }
            let Some((key, value)) = split_key(&line.text) else {
                return Err(format!("line {}: expected a `key:`", line.number));
            };
            let number = line.number;
            self.pos = index + 1;
            let value = if value.is_empty() {
                match self.next_structural() {
                    Some(next)
                        if self.lines[next].indent == indent
                            && is_seq_item(&self.lines[next].text) =>
                    {
                        self.seq(indent)?
                    }
                    _ => self.nested_or_empty(indent, number)?,
                }
            } else {
                self.inline_value(index, &value, indent)
            };
            entries.push(Entry {
                key,
                line: number,
                value,
            });
        }
        Ok(Node::Map(entries))
    }

    fn nested_or_empty(&mut self, indent: usize, number: usize) -> Result<Node, String> {
        match self.next_structural() {
            Some(next) if self.lines[next].indent > indent => {
                let inner = self.lines[next].indent;
                self.node(inner)
            }
            _ => Ok(Node::Scalar(Scalar {
                text: String::new(),
                line: number,
                comment: None,
            })),
        }
    }

    /// The value written after a key or a dash on line `index`, whose block
    /// sits at `indent`; `self.pos` is already past that line.
    fn inline_value(&mut self, index: usize, value: &str, indent: usize) -> Node {
        let number = self.lines[index].number;
        let comment = self.lines[index].comment.clone();
        if is_block_indicator(value) {
            return Node::Scalar(self.block_scalar(indent, number));
        }
        if value.starts_with('[') || value.starts_with('{') {
            let mut flow = value.to_string();
            while !balanced(&flow) {
                let Some(next) = self.next_structural() else {
                    break;
                };
                flow.push(' ');
                flow.push_str(&self.lines[next].text);
                self.pos = next + 1;
            }
            return flow_node(&flow, number);
        }
        let mut text = value.to_string();
        while let Some(next) = self.next_structural() {
            let line = &self.lines[next];
            if line.indent <= indent || split_key(&line.text).is_some() {
                break;
            }
            text.push(' ');
            text.push_str(&line.text);
            self.pos = next + 1;
        }
        Node::Scalar(Scalar {
            text: unquote(&text),
            line: number,
            comment,
        })
    }

    fn block_scalar(&mut self, indent: usize, number: usize) -> Scalar {
        let mut taken: Vec<&str> = Vec::new();
        let mut end = self.pos;
        let mut scan = self.pos;
        while scan < self.lines.len() {
            let raw = &self.lines[scan].raw;
            if raw.trim().is_empty() {
                taken.push("");
            } else if raw.len() - raw.trim_start_matches(' ').len() > indent {
                taken.push(raw);
                end = scan + 1;
            } else {
                break;
            }
            scan += 1;
        }
        let kept = end - self.pos;
        taken.truncate(kept);
        let block_indent = taken
            .iter()
            .filter(|raw| !raw.trim().is_empty())
            .map(|raw| raw.len() - raw.trim_start_matches(' ').len())
            .min()
            .unwrap_or(0);
        let text = taken
            .iter()
            .map(|raw| raw.get(block_indent..).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        self.pos = end;
        Scalar {
            text,
            line: number + 1,
            comment: None,
        }
    }
}

fn is_seq_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

fn is_block_indicator(value: &str) -> bool {
    (value.starts_with('|') || value.starts_with('>'))
        && value[1..]
            .chars()
            .all(|c| c == '+' || c == '-' || c.is_ascii_digit())
}

/// Splits a line into its content and its trailing comment. A quote opens a
/// quoted scalar only where a scalar can start, so an apostrophe inside a
/// plain scalar does not hide the comment after it.
fn split_comment(text: &str) -> (&str, Option<String>) {
    let mut quote: Option<char> = None;
    let mut previous: Option<char> = None;
    for (offset, c) in text.char_indices() {
        match quote {
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None => {
                if c == '#' && previous.is_none_or(char::is_whitespace) {
                    let comment = text[offset + 1..].trim().to_string();
                    return (&text[..offset], Some(comment));
                }
                if (c == '\'' || c == '"')
                    && previous.is_none_or(|p| p.is_whitespace() || "[{,:".contains(p))
                {
                    quote = Some(c);
                }
            }
        }
        previous = Some(c);
    }
    (text, None)
}

/// Splits `key: value` into the unquoted key and the value, or `None` when
/// the text is not a key.
fn split_key(text: &str) -> Option<(String, String)> {
    let (key, rest) = if let Some(open) = text.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let close = text[1..].find(open)? + 1;
        (text[1..close].to_string(), &text[close + 1..])
    } else {
        let mut split = None;
        for (offset, c) in text.char_indices() {
            if c == ':' && text[offset + 1..].chars().next().is_none_or(|n| n == ' ') {
                split = Some(offset);
                break;
            }
        }
        let offset = split?;
        let key = text[..offset].trim_end();
        if key.is_empty() || key.starts_with('[') || key.starts_with('{') {
            return None;
        }
        (key.to_string(), &text[offset..])
    };
    let value = rest.strip_prefix(':')?;
    if !value.is_empty() && !value.starts_with(' ') {
        return None;
    }
    Some((key, value.trim().to_string()))
}

fn unquote(text: &str) -> String {
    let text = text.trim();
    if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
        text[1..text.len() - 1].replace("\\\"", "\"")
    } else if text.len() >= 2 && text.starts_with('\'') && text.ends_with('\'') {
        text[1..text.len() - 1].replace("''", "'")
    } else {
        text.to_string()
    }
}

fn balanced(flow: &str) -> bool {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for c in flow.chars() {
        match quote {
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None => match c {
                '"' | '\'' => quote = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                _ => {}
            },
        }
    }
    depth <= 0
}

/// Splits the inside of a flow collection at its top level commas.
fn flow_items(inner: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut current = String::new();
    for c in inner.chars() {
        match quote {
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None => match c {
                '"' | '\'' => quote = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    items.push(std::mem::take(&mut current));
                    continue;
                }
                _ => {}
            },
        }
        current.push(c);
    }
    items.push(current);
    items
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn flow_node(flow: &str, line: usize) -> Node {
    let flow = flow.trim();
    let scalar = |text: &str| {
        Node::Scalar(Scalar {
            text: unquote(text),
            line,
            comment: None,
        })
    };
    if let Some(inner) = flow.strip_prefix('[').and_then(|f| f.strip_suffix(']')) {
        return Node::Seq(
            flow_items(inner)
                .iter()
                .map(|item| {
                    if item.starts_with('[') || item.starts_with('{') {
                        flow_node(item, line)
                    } else {
                        scalar(item)
                    }
                })
                .collect(),
        );
    }
    if let Some(inner) = flow.strip_prefix('{').and_then(|f| f.strip_suffix('}')) {
        return Node::Map(
            flow_items(inner)
                .iter()
                .map(|item| match split_key(item) {
                    Some((key, value)) => Entry {
                        key,
                        line,
                        value: if value.starts_with('[') || value.starts_with('{') {
                            flow_node(&value, line)
                        } else {
                            scalar(&value)
                        },
                    },
                    None => Entry {
                        key: unquote(item),
                        line,
                        value: scalar(""),
                    },
                })
                .collect(),
        );
    }
    scalar(flow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_at<'a>(node: &'a Node, path: &[&str]) -> &'a Scalar {
        let mut node = node;
        for key in path {
            node = &node.get(key).unwrap_or_else(|| panic!("no {key}")).value;
        }
        match node {
            Node::Scalar(scalar) => scalar,
            other => panic!("not a scalar: {other:?}"),
        }
    }

    #[test]
    fn maps_sequences_and_dash_items_keep_their_lines() {
        let text = "\
on:
  push:
    tags: ['v*', \"rules-v*\"]
jobs:
  build:
    steps:
      - name: Check out
        uses: actions/checkout@abc # v1.2.3
      - run: cargo test
";
        let root = read(text).expect("readable");
        let tags = &root.get("on").unwrap().value.get("push").unwrap().value;
        assert_eq!(
            tags.get("tags").unwrap().value.texts(),
            vec!["v*", "rules-v*"]
        );
        let steps = &root.get("jobs").unwrap().value.get("build").unwrap().value;
        let Node::Seq(steps) = &steps.get("steps").unwrap().value else {
            panic!("steps are a sequence");
        };
        assert_eq!(steps.len(), 2);
        let uses = scalar_at(&steps[0], &["uses"]);
        assert_eq!(uses.text, "actions/checkout@abc");
        assert_eq!(uses.line, 8);
        assert_eq!(uses.comment.as_deref(), Some("v1.2.3"));
        assert_eq!(scalar_at(&steps[1], &["run"]).line, 9);
    }

    #[test]
    fn a_block_scalar_keeps_one_text_line_per_file_line_and_ignores_hashes() {
        let text = "\
steps:
- run: |
    # a shell comment
    cargo build \\

      --locked
  name: after
";
        let root = read(text).expect("readable");
        let Node::Seq(steps) = &root.get("steps").unwrap().value else {
            panic!("a sequence at the key's indentation");
        };
        let run = scalar_at(&steps[0], &["run"]);
        assert_eq!(run.line, 3);
        assert_eq!(run.text, "# a shell comment\ncargo build \\\n\n  --locked");
        assert_eq!(scalar_at(&steps[0], &["name"]).text, "after");
    }

    #[test]
    fn an_apostrophe_in_a_plain_scalar_does_not_hide_a_comment() {
        let root = read("name: the daemon's job # note\n").expect("readable");
        let name = scalar_at(&root, &["name"]);
        assert_eq!(name.text, "the daemon's job");
        assert_eq!(name.comment.as_deref(), Some("note"));
    }

    #[test]
    fn flow_maps_and_quoted_keys_are_read() {
        let root = read("\"on\": push\nwith: { make_latest: false, tag_name: 'rules-v1' }\n")
            .expect("readable");
        assert_eq!(scalar_at(&root, &["on"]).text, "push");
        assert_eq!(scalar_at(&root, &["with", "make_latest"]).text, "false");
        assert_eq!(scalar_at(&root, &["with", "tag_name"]).text, "rules-v1");
    }

    #[test]
    fn a_stray_indentation_is_unreadable_rather_than_guessed_at() {
        assert!(read("a: 1\n    b: 2\n").is_err());
    }
}
