//! Reading one Codex configuration file and naming what is inside it.
//!
//! Codex writes its config layers in TOML and its hook files in JSON, and both
//! are read here into the one shape the rest of the adapter works in: a
//! `serde_json::Value`. That is deliberate. The normalised views a Rule sees
//! are agent neutral, so an `[mcp_servers.x]` table and a `"mcpServers": {"x":
//! …}` object have to arrive at [`agentsweep_core::views::McpView`] as the same
//! value, and a hook written as TOML and the same hook written as JSON have to
//! hash to one identity.
//!
//! A TOML date, time or date-time has no counterpart in JSON. Codex writes one
//! into `[marketplaces.<name>].last_updated`, so rather than let a parser
//! invent a shape for it, it is carried across as the string it was written
//! as.

use std::path::{Path, PathBuf};

use agentsweep_core::adapter::{Problem, ProblemReason};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Kind, Scope};
use serde_json::{Map, Value};

/// How a configuration file is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// Every config layer, `requirements.toml` and the legacy managed file.
    Toml,
    /// `hooks.json`, and the MCP files a plugin ships.
    Json,
}

/// One configuration file, read and parsed.
#[derive(Clone, Debug)]
pub struct Document {
    /// Where the file sits on disk.
    pub path: PathBuf,
    /// How the file is named in the locator of every Item read out of it.
    pub surface: String,
    /// What it holds.
    pub value: Value,
}

impl Document {
    /// A document built from a value already in hand, which is how an inline
    /// `[hooks]` table becomes a document of its own.
    pub fn inline(path: PathBuf, surface: String, value: Value) -> Document {
        Document {
            path,
            surface,
            value,
        }
    }

    /// The value at one dotted key path, absent when nothing is there.
    pub fn at(&self, key_path: &str) -> Option<&Value> {
        let mut current = &self.value;
        for segment in key_path.split('.') {
            current = current.get(segment)?;
        }
        Some(current)
    }

    /// The members of an object field, in sorted order so that two
    /// enumerations of one file yield their Items in the same order.
    pub fn members(&self, key_path: &str) -> Vec<(String, Value)> {
        let Some(object) = self.at(key_path).and_then(Value::as_object) else {
            return Vec::new();
        };
        let mut members: Vec<(String, Value)> = object
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        members.sort_by(|one, other| one.0.cmp(&other.0));
        members
    }

    /// A boolean at one key path, absent when the key is not set or is not a
    /// boolean.
    pub fn flag(&self, key_path: &str) -> Option<bool> {
        self.at(key_path).and_then(Value::as_bool)
    }

    /// A string at one key path, empty when the key is not set or is not a
    /// string.
    pub fn text(&self, key_path: &str) -> String {
        self.at(key_path)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }
}

/// Reads and parses one configuration file.
///
/// A file that is not there is not a Problem: nobody has to have one. A file
/// that cannot be read or cannot be parsed is, because Codex would have read
/// it and AgentSweep cannot say what is in it.
pub fn load(
    host: &Host,
    scope: &Scope,
    path: &Path,
    kind: Kind,
    format: Format,
) -> Result<Option<Document>, Problem> {
    if host.symlink_metadata(path).is_err() {
        return Ok(None);
    }
    let surface = surface_name(host, scope, path);
    let problem = |reason| Problem {
        surface: surface.clone(),
        path: path.to_path_buf(),
        kind: Some(kind),
        reason,
    };
    let bytes = host
        .read(path)
        .map_err(|_| problem(ProblemReason::Unreadable))?;
    let value = match format {
        Format::Json => {
            serde_json::from_slice(&bytes).map_err(|_| problem(ProblemReason::Unparseable))?
        }
        Format::Toml => {
            let text = String::from_utf8(bytes).map_err(|_| problem(ProblemReason::Unparseable))?;
            json_of(&parse_toml(&text).map_err(|_| problem(ProblemReason::Unparseable))?)
        }
    };
    Ok(Some(Document {
        path: path.to_path_buf(),
        surface,
        value,
    }))
}

/// How one file is named in the locator of the Items read out of it.
///
/// A file inside the project root is named relative to it, which is the
/// locator rule of spec section 3.3. A file in the home is named with a
/// leading `~/`, so a locator never carries where the home happens to be.
/// Anything else, the managed directory above all, is named by its absolute
/// path.
pub fn surface_name(host: &Host, scope: &Scope, path: &Path) -> String {
    if let Some(root) = scope.root()
        && let Ok(relative) = path.strip_prefix(root)
    {
        return slashed(relative);
    }
    if let Some(home) = host.home()
        && let Ok(relative) = path.strip_prefix(home)
    {
        return format!("~/{}", slashed(relative));
    }
    slashed(path)
}

/// One config layer as the parser reads it.
///
/// The whole text is one TOML document, which is not the same as one TOML
/// value: reading a config layer through the value parser would stop at the
/// first key and call the rest unexpected content.
pub fn parse_toml(text: &str) -> Result<toml::Value, toml::de::Error> {
    toml::from_str(text)
}

/// One TOML value as the JSON the views are written against.
///
/// A date, a time and a date-time become the string they were written as:
/// nothing in a Rule reads one, and inventing an object shape for it would put
/// a field in a canonical entry that is not in the file.
pub fn json_of(value: &toml::Value) -> Value {
    match value {
        toml::Value::String(text) => Value::String(text.clone()),
        toml::Value::Integer(number) => Value::from(*number),
        toml::Value::Float(number) => serde_json::Number::from_f64(*number)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(number.to_string())),
        toml::Value::Boolean(flag) => Value::Bool(*flag),
        toml::Value::Datetime(stamp) => Value::String(stamp.to_string()),
        toml::Value::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        toml::Value::Table(table) => {
            let mut fields = Map::new();
            for (name, value) in table {
                fields.insert(name.clone(), json_of(value));
            }
            Value::Object(fields)
        }
    }
}

/// One key path inside a document, kept as its segments so that the pointer
/// and the dotted form can never disagree about where a dot in a key name
/// belongs. A Codex key name holds dots, slashes and colons often enough:
/// `[projects."/Users/u/demo"]` and `[hooks.state."<file>:<event>:0:0"]` both
/// do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPath(Vec<String>);

impl KeyPath {
    /// A key path from a dotted declaration such as `skills.bundled.enabled`.
    pub fn declared(dotted: &str) -> KeyPath {
        KeyPath(dotted.split('.').map(str::to_string).collect())
    }

    /// The key path one segment further down.
    pub fn child(&self, segment: &str) -> KeyPath {
        let mut segments = self.0.clone();
        segments.push(segment.to_string());
        KeyPath(segments)
    }

    /// The dotted form a Rule reads as `settings.key_path`, an array index
    /// written as `.N`.
    pub fn dotted(&self) -> String {
        self.0.join(".")
    }

    /// The JSON pointer an ItemId carries after the `#`.
    pub fn pointer(&self) -> String {
        let mut out = String::new();
        for segment in &self.0 {
            out.push('/');
            out.push_str(&segment.replace('~', "~0").replace('/', "~1"));
        }
        out
    }
}

/// A path written with forward slashes, whatever the platform writes.
fn slashed(path: &Path) -> String {
    let mut out = String::new();
    for component in path.components() {
        let text = component.as_os_str().to_string_lossy();
        if !out.is_empty() && !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(text.trim_end_matches('/'));
        if out.is_empty() {
            out.push('/');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_table_becomes_the_json_the_views_are_written_against() {
        let written = parse_toml(
            "approval_policy = \"never\"\n\
             [mcp_servers.herd]\n\
             command = \"php\"\n\
             args = [\"artisan\", \"boost:mcp\"]\n\
             enabled = true\n",
        )
        .expect("a config layer");
        let value = json_of(&written);
        assert_eq!(value["approval_policy"], Value::String("never".to_string()));
        assert_eq!(value["mcp_servers"]["herd"]["command"], "php");
        assert_eq!(value["mcp_servers"]["herd"]["args"][1], "boost:mcp");
        assert_eq!(value["mcp_servers"]["herd"]["enabled"], Value::Bool(true));
    }

    /// Codex writes `last_updated` into a marketplace record as a date-time,
    /// which JSON has no shape for. It travels as what was written.
    #[test]
    fn a_date_time_travels_as_the_string_it_was_written_as() {
        let written = parse_toml("[marketplaces.demo]\nlast_updated = 2026-07-15T10:00:00Z\n")
            .expect("a marketplace record");
        assert_eq!(
            json_of(&written)["marketplaces"]["demo"]["last_updated"],
            "2026-07-15T10:00:00Z"
        );
    }

    #[test]
    fn a_key_path_renders_as_a_pointer_and_as_a_dotted_path() {
        let key = KeyPath::declared("model_providers")
            .child("proxy")
            .child("base_url");
        assert_eq!(key.dotted(), "model_providers.proxy.base_url");
        assert_eq!(key.pointer(), "/model_providers/proxy/base_url");
    }

    /// A Codex trust entry is keyed by an absolute path, and a hook state key
    /// carries one too. Neither may be taken apart on its dots.
    #[test]
    fn a_key_that_holds_a_slash_is_escaped_in_the_pointer() {
        let key = KeyPath::declared("projects").child("/Users/u/demo");
        assert_eq!(key.pointer(), "/projects/~1Users~1u~1demo");
        assert_eq!(key.dotted(), "projects./Users/u/demo");
    }

    #[test]
    fn a_file_in_the_project_is_named_relative_to_it_and_one_in_the_home_with_a_tilde() {
        let host = Host::new(
            PathBuf::from("/home/u"),
            vec![PathBuf::from("/home/u/src/demo")],
        );
        let scope = Scope::Project(PathBuf::from("/home/u/src/demo"));
        assert_eq!(
            surface_name(
                &host,
                &scope,
                Path::new("/home/u/src/demo/.codex/config.toml")
            ),
            ".codex/config.toml"
        );
        assert_eq!(
            surface_name(&host, &Scope::User, Path::new("/home/u/.codex/config.toml")),
            "~/.codex/config.toml"
        );
        assert_eq!(
            surface_name(&host, &Scope::Managed, Path::new("/etc/codex/config.toml")),
            "/etc/codex/config.toml"
        );
    }
}
