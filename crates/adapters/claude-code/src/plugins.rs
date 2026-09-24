//! Plugins, the versions on disk and the marketplaces they came from.
//!
//! Claude Code keeps three things side by side under the config directory: an
//! install registry that says which version of each plugin is in use, a
//! marketplace registry that says where each marketplace came from, and a
//! cache of version directories, one per version it ever installed. A plugin
//! Item is the version directory the install registry points at (spec section
//! 4.6.1); a version nothing points at any more is an Item of its own, inactive
//! and orphaned, because it is still on disk and still full of code.
//!
//! A marketplace clone is a tree Item named by the marketplace, with its git
//! internals left out: the workspace adapter yields Repository Metadata for the
//! clone, and hashing `.git` here would make every fetch look like Drift.
//!
//! A plugin brings its own MCP servers in a bundled file. Those are entry
//! Items like any other server, with Provenance Plugin, so one MCP Rule covers
//! them and a person can see which plugin brought one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agentsweep_core::adapter::Enumeration;
use agentsweep_core::drift;
use agentsweep_core::host::Host;
use agentsweep_core::item::{Activation, InactiveReason, Kind, Provenance, Scope};
use serde_json::Value;

use crate::document::{self, Document};
use crate::skills;
use crate::tree::{self, Placement};
use crate::{ClaudeCode, PROJECT_MCP_FILE};

/// The directory everything about plugins lives in, under the config
/// directory.
pub const DIRECTORY: &str = "plugins";

/// The install registry: which version of each plugin is in use.
pub const INSTALL_REGISTRY: &str = "installed_plugins.json";

/// The marketplace registry: where each known marketplace came from.
pub const MARKETPLACE_REGISTRY: &str = "known_marketplaces.json";

/// The directory the marketplace clones sit in.
pub const CLONES: &str = "marketplaces";

/// The directory the version directories sit in, by marketplace and plugin.
pub const CACHE: &str = "cache";

/// The marketplaces that are the vendor's own. A plugin from one of them is
/// what `item.provenance_official` is true for, which the Allowlist anchors on
/// (spec section 4.1), so the test is deliberately narrow: the vendor's
/// marketplace name, or a source in the vendor's own repository namespace.
pub const OFFICIAL_MARKETPLACES: [&str; 1] = ["claude-plugins-official"];

/// The repository namespace an official marketplace is served from.
const OFFICIAL_SOURCE_OWNER: &str = "anthropics/";

/// The host that namespace is on.
const OFFICIAL_SOURCE_HOST: &str = "github.com";

/// What the settings layers say about each plugin id, highest layer first.
pub type Enabled = BTreeMap<String, bool>;

/// One record of the install registry: the version of one plugin that one
/// scope installed, and where it put it.
#[derive(Clone, Debug)]
struct Record {
    /// The plugin id, `<name>@<marketplace>`.
    id: String,
    /// The version the record points at, a semantic version, a short commit or
    /// `unknown`.
    version: String,
    /// The directory that version lives in.
    install_path: PathBuf,
    /// The commit the record recorded, empty when it recorded none.
    commit: String,
}

impl Record {
    /// The plugin name, which is everything before the marketplace.
    fn name(&self) -> &str {
        self.id.split('@').next().unwrap_or_default()
    }

    /// The marketplace the plugin came from.
    fn marketplace(&self) -> &str {
        self.id.rsplit('@').next().unwrap_or_default()
    }
}

/// Every plugin version, every marketplace clone and every MCP server a plugin
/// brings with it.
pub fn enumerate(
    adapter: &ClaudeCode,
    host: &Host,
    config_dir: &Path,
    enabled: &Enabled,
    enumeration: &mut Enumeration,
) {
    let directory = config_dir.join(DIRECTORY);
    if !directory.is_dir() {
        return;
    }
    let known = registry(host, &directory, MARKETPLACE_REGISTRY, enumeration)
        .map(marketplaces_of)
        .unwrap_or_default();
    let installed = registry(host, &directory, INSTALL_REGISTRY, enumeration)
        .map(|document| records(&document))
        .unwrap_or_default();

    clones(adapter, host, &directory, &known, enumeration);
    versions(
        adapter,
        host,
        &directory,
        &installed,
        &known,
        enabled,
        enumeration,
    );
}

/// One of the two registries, parsed. An unreadable or unparseable one is a
/// Problem: Claude Code would have read it, and what is in it decides which
/// version of a plugin is the one in use.
fn registry(
    host: &Host,
    directory: &Path,
    name: &str,
    enumeration: &mut Enumeration,
) -> Option<Document> {
    match document::load(host, &Scope::User, &directory.join(name), Kind::Plugin) {
        Ok(document) => document,
        Err(problem) => {
            enumeration.problems.push(problem);
            None
        }
    }
}

/// The marketplaces the registry knows, whether or not the file wraps them in
/// a `marketplaces` key: the documentation shows the wrapper and the file on
/// disk does without it.
fn marketplaces_of(document: Document) -> BTreeMap<String, Value> {
    let members = match document.at("marketplaces").and_then(Value::as_object) {
        Some(_) => document.members("marketplaces"),
        None => document
            .value
            .as_object()
            .map(|fields| {
                fields
                    .iter()
                    .filter(|(_, value)| value.is_object())
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default(),
    };
    members.into_iter().collect()
}

/// Every record of the install registry, in plugin id order. The documentation
/// shows one record per plugin and the file on disk holds a list of them, one
/// per scope, so both are read.
fn records(document: &Document) -> Vec<Record> {
    let mut found = Vec::new();
    for (id, value) in document.members("plugins") {
        let written = match &value {
            Value::Array(records) => records.clone(),
            other => vec![other.clone()],
        };
        for record in written {
            let version = string(&record, "version");
            let install_path = string(&record, "installPath");
            if install_path.is_empty() {
                continue;
            }
            found.push(Record {
                id: id.clone(),
                version,
                install_path: PathBuf::from(install_path),
                commit: string(&record, "gitCommitSha"),
            });
        }
    }
    found
}

/// Every marketplace clone under the plugins directory.
fn clones(
    adapter: &ClaudeCode,
    host: &Host,
    directory: &Path,
    known: &BTreeMap<String, Value>,
    enumeration: &mut Enumeration,
) {
    for path in tree::directories_in(host, &directory.join(CLONES)) {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // A clone no registry lists any more is still on disk and is still
        // full of the sources it lists, so it is an Item; Claude Code would
        // not read it, so it is not an active one.
        let activation = match known.contains_key(&name) {
            true => Activation::Active,
            false => Activation::Inactive(InactiveReason::Orphaned),
        };
        let placement = Placement::user()
            .from(Provenance::Marketplace {
                name: name.clone(),
                pinned_ref: String::new(),
                official: is_official(&name, known),
            })
            .loaded(activation);
        // Spec section 4.6.1: a marketplace locates by name, which is the name
        // its clone directory carries and the key both registries use.
        let item = tree::read_as(
            host,
            adapter.caps,
            &placement,
            Kind::Marketplace,
            &name,
            &path,
        );
        let view = skills::marketplace_view(&item, &name);
        // Where the marketplace points is what a Drift decision compares: a
        // fetch rewrites the clone every time and says nothing, while a
        // marketplace that starts pointing somewhere else is the question
        // (spec section 4.6.5).
        let item = item
            .with_view(view)
            .noting(drift::SOURCE, source_hash(known.get(&name)));
        tree::yielded(host, enumeration, item);
    }
}

/// Every version directory: the ones the install registry points at, and the
/// ones nothing points at any more.
#[allow(clippy::too_many_arguments)]
fn versions(
    adapter: &ClaudeCode,
    host: &Host,
    directory: &Path,
    installed: &[Record],
    known: &BTreeMap<String, Value>,
    enabled: &Enabled,
    enumeration: &mut Enumeration,
) {
    let mut done: Vec<PathBuf> = Vec::new();
    let mut named: Vec<String> = Vec::new();
    for record in installed {
        if !record.install_path.is_dir() || done.contains(&record.install_path) {
            continue;
        }
        done.push(record.install_path.clone());
        // The first record for a plugin id is the plugin; a second scope
        // pointing at another version of it is that version, named so the two
        // never share an identity.
        let locator = match named.contains(&record.id) {
            false => record.id.clone(),
            true => format!("{}@{}", record.id, record.version),
        };
        named.push(record.id.clone());
        let activation = match enabled.get(&record.id) {
            Some(true) => Activation::Active,
            Some(false) => Activation::Inactive(InactiveReason::Disabled),
            // Nothing on disk says whether the plugin is switched on, which is
            // what a project-scope install looks like from here.
            None => Activation::Unknown,
        };
        version_item(
            adapter,
            host,
            &placement_of(record, known, activation),
            &locator,
            record,
            enumeration,
        );
    }

    for (path, id, version) in cached(host, &directory.join(CACHE)) {
        if done.contains(&path) {
            continue;
        }
        let record = Record {
            id: id.clone(),
            version: version.clone(),
            install_path: path,
            commit: String::new(),
        };
        let placement = placement_of(
            &record,
            known,
            Activation::Inactive(InactiveReason::Orphaned),
        );
        let locator = format!("{id}@{version}");
        version_item(adapter, host, &placement, &locator, &record, enumeration);
    }
}

/// One version directory as a Plugin Item, with the MCP servers it brings.
fn version_item(
    adapter: &ClaudeCode,
    host: &Host,
    placement: &Placement,
    locator: &str,
    record: &Record,
    enumeration: &mut Enumeration,
) {
    let item = tree::read_as(
        host,
        adapter.caps,
        placement,
        Kind::Plugin,
        locator,
        &record.install_path,
    );
    let view = skills::plugin_view(&item, record.name());
    // The three facts of spec section 4.6.1. A registry record that moved as a
    // whole is an update and raises no question; a tree that moved under a
    // record that did not is the question.
    let item = item
        .with_view(view)
        .noting(drift::VERSION, record.version.clone())
        .noting(
            drift::INSTALL_PATH,
            record.install_path.display().to_string(),
        )
        .noting(drift::COMMIT, record.commit.clone());
    tree::yielded(host, enumeration, item);
    bundled_servers(adapter, host, placement, record, enumeration);
}

/// The MCP servers one plugin version brings with it. They are Items of their
/// own, with Provenance Plugin, and they are not started unless the plugin is
/// loaded, so they carry the plugin's own Activation.
fn bundled_servers(
    adapter: &ClaudeCode,
    host: &Host,
    placement: &Placement,
    record: &Record,
    enumeration: &mut Enumeration,
) {
    if placement.activation == Activation::Inactive(InactiveReason::Orphaned) {
        return;
    }
    let path = record.install_path.join(PROJECT_MCP_FILE);
    let loaded = document::load(host, &Scope::User, &path, Kind::McpServer);
    let document = match loaded {
        Ok(Some(document)) => document,
        Ok(None) => return,
        Err(problem) => {
            enumeration.problems.push(problem);
            return;
        }
    };
    for (name, server) in document.members("mcpServers") {
        enumeration.items.push(adapter.server_item(
            host,
            &document,
            Scope::User,
            &name,
            &server,
            Provenance::Plugin {
                id: record.id.clone(),
            },
            placement.activation,
            true,
            Some(&record.install_path),
        ));
    }
}

/// Every version directory in the cache, with the plugin id its place spells
/// out: the marketplace, then the plugin, then the version.
fn cached(host: &Host, cache: &Path) -> Vec<(PathBuf, String, String)> {
    let mut found = Vec::new();
    for marketplace in tree::directories_in(host, cache) {
        let market = marketplace
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        for plugin in tree::directories_in(host, &marketplace) {
            let name = plugin.file_name().unwrap_or_default().to_string_lossy();
            for version in tree::directories_in(host, &plugin) {
                let spelled = version.file_name().unwrap_or_default().to_string_lossy();
                found.push((
                    version.clone(),
                    format!("{name}@{market}"),
                    spelled.to_string(),
                ));
            }
        }
    }
    found
}

/// Where one plugin version came from: the marketplace of its id, pinned to
/// the commit the install registry recorded or, failing that, to the version
/// it points at.
fn placement_of(
    record: &Record,
    known: &BTreeMap<String, Value>,
    activation: Activation,
) -> Placement {
    let pinned_ref = match record.commit.is_empty() {
        false => record.commit.clone(),
        true => record.version.clone(),
    };
    Placement::user()
        .from(Provenance::Marketplace {
            name: record.marketplace().to_string(),
            pinned_ref,
            official: is_official(record.marketplace(), known),
        })
        .loaded(activation)
}

/// Whether one marketplace is the vendor's own.
fn is_official(name: &str, known: &BTreeMap<String, Value>) -> bool {
    if OFFICIAL_MARKETPLACES.contains(&name) {
        return true;
    }
    let Some(source) = known.get(name).and_then(|entry| entry.get("source")) else {
        return false;
    };
    let repo = string(source, "repo");
    if repo.starts_with(OFFICIAL_SOURCE_OWNER) {
        return true;
    }
    let url = string(source, "url");
    agentsweep_core::views::url_host(&url) == OFFICIAL_SOURCE_HOST
        && url.contains(&format!("/{OFFICIAL_SOURCE_OWNER}"))
}

/// The hash of where one marketplace points, which is the fact a Drift
/// decision compares. A marketplace no registry lists has none.
fn source_hash(entry: Option<&Value>) -> String {
    let Some(source) = entry.and_then(|entry| entry.get("source")) else {
        return String::new();
    };
    agentsweep_core::item::sha256_hex(&agentsweep_core::item::canonical_entry(source))
}

fn string(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}
