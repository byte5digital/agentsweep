//! Reading one configuration file and naming what is inside it.
//!
//! Every Surface of this adapter is a JSON document, and every entry Item read
//! out of one is named the same way: the file, a `#`, and the key path inside
//! it. This module is where a file becomes a parsed document or a Problem, and
//! where a key path becomes the two spellings the contract asks for: the JSON
//! pointer an [`agentsweep_core::item::ItemId`] carries (spec section 3.3) and
//! the dotted path a Rule reads as `settings.key_path`.

use std::path::{Path, PathBuf};

use agentsweep_core::adapter::{Problem, ProblemReason};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Kind, Scope};
use serde_json::Value;

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

    /// The strings of an array at one key path, empty when there is none.
    pub fn strings(&self, key_path: &str) -> Vec<String> {
        self.at(key_path)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Reads and parses one configuration file.
///
/// A file that is not there is not a Problem: nobody has to have one. A file
/// that cannot be read or cannot be parsed is, because Claude Code would have
/// read it and AgentSweep cannot say what is in it.
pub fn load(
    host: &Host,
    scope: &Scope,
    path: &Path,
    kind: Kind,
) -> Result<Option<Document>, Problem> {
    if host.symlink_metadata(path).is_err() {
        return Ok(None);
    }
    let surface = surface_name(host, scope, path);
    let bytes = host.read(path).map_err(|_| Problem {
        surface: surface.clone(),
        path: path.to_path_buf(),
        kind: Some(kind),
        reason: ProblemReason::Unreadable,
    })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| Problem {
        surface: surface.clone(),
        path: path.to_path_buf(),
        kind: Some(kind),
        reason: ProblemReason::Unparseable,
    })?;
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
/// leading `~/`, because the local-scope MCP servers of a project live in the
/// user's own `~/.claude.json` and a Project-scope Item has to name them
/// without depending on where the home happens to be. Anything else is named
/// by its absolute path.
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

/// One key path inside a document, kept as its segments so that the pointer
/// and the dotted form can never disagree about where a dot in a key name
/// belongs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPath(Vec<String>);

impl KeyPath {
    /// A key path from a dotted declaration such as `permissions.defaultMode`.
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

/// A path written with forward slashes, whatever the platform writes, with one
/// separator between components and none doubled after the root.
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
    fn a_key_path_renders_as_a_pointer_and_as_a_dotted_path() {
        let key = KeyPath::declared("permissions.allow").child("0");
        assert_eq!(key.dotted(), "permissions.allow.0");
        assert_eq!(key.pointer(), "/permissions/allow/0");
    }

    /// A marketplace name or an environment variable may hold the characters a
    /// JSON pointer gives a meaning to, and the segments keep them apart.
    #[test]
    fn a_key_that_holds_a_slash_or_a_tilde_is_escaped_in_the_pointer() {
        let key = KeyPath::declared("enabledPlugins").child("a/b~c");
        assert_eq!(key.pointer(), "/enabledPlugins/a~1b~0c");
        assert_eq!(key.dotted(), "enabledPlugins.a/b~c");
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
                Path::new("/home/u/src/demo/.claude/settings.json")
            ),
            ".claude/settings.json"
        );
        assert_eq!(
            surface_name(&host, &scope, Path::new("/home/u/.claude.json")),
            "~/.claude.json"
        );
        assert_eq!(
            surface_name(
                &host,
                &Scope::Managed,
                Path::new("/Library/Application Support/ClaudeCode/managed-settings.json")
            ),
            "/Library/Application Support/ClaudeCode/managed-settings.json"
        );
    }
}
