//! Laying the fetched corpus out the way an Agent would hold it.
//!
//! A Rule reads the views a Surface Adapter computed, not just the bytes, so
//! scanning a downloaded repository as a pile of files would prove very little.
//! What is built here instead is a machine: a home with a Claude Code and a
//! Codex configuration directory in it, skills where skills live, plugins in
//! the install cache with the registry entry that points at them, marketplace
//! clones with the registry entry that knows them, and one project root per
//! instruction file. The real adapters then enumerate it, and every view is
//! populated because every Item was found where that Agent finds it.
//!
//! Nothing here touches a real home: everything lands under a working
//! directory the caller chose, which is `target/` and therefore never
//! committed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::{fs, io};

use agentsweep_core::item::sha256_hex;
use serde_json::{Value, json};

use crate::benign::manifest::{Agent, Presentation, Source};

/// The files taken from one source, by path relative to what was taken.
pub type Content = BTreeMap<String, Vec<u8>>;

/// The instruction file of each Agent, which is what a README and a committed
/// instruction file are both presented as.
const INSTRUCTION_FILES: [(Agent, &str); 2] = [
    (Agent::ClaudeCode, "CLAUDE.md"),
    (Agent::Codex, "AGENTS.md"),
];

/// The version a plugin without a readable manifest is installed as.
const UNVERSIONED: &str = "0.0.0";

/// Reads a `tar.gz` archive and keeps the files under the given paths.
///
/// GitHub wraps an archive in one directory named after the repository and the
/// commit; that wrapper is stripped, so a path here is the path in the
/// repository. An empty path takes everything. Anything that is not a regular
/// file, and any entry whose path tries to leave the archive, is left out.
pub fn taken(archive: &[u8], paths: &[String]) -> Result<Content, String> {
    let decoder = flate2::read::GzDecoder::new(archive);
    let mut reader = tar::Archive::new(decoder);
    let mut content = Content::new();
    let entries = reader
        .entries()
        .map_err(|error| format!("the archive could not be read: {error}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| format!("an archive entry is broken: {error}"))?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry
            .path()
            .map_err(|error| format!("an archive entry has no usable path: {error}"))?
            .to_string_lossy()
            .to_string();
        let Some(relative) = strip_wrapper(&path) else {
            continue;
        };
        if !paths.iter().any(|wanted| covers(wanted, &relative)) {
            continue;
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|error| format!("{relative} could not be read: {error}"))?;
        content.insert(relative, bytes);
    }
    if content.is_empty() {
        return Err(format!("the archive holds none of {paths:?}"));
    }
    Ok(content)
}

/// The digest that pins one source's content.
///
/// It is taken over the paths and their bytes rather than over the transfer,
/// because the tarball GitHub generates is not promised to be byte-stable
/// while its content is. A file source hashes its one file the same way.
pub fn digest(content: &Content) -> String {
    let mut rendered = String::new();
    for (path, bytes) in content {
        rendered.push_str(path);
        rendered.push(' ');
        rendered.push_str(&sha256_hex(bytes));
        rendered.push('\n');
    }
    sha256_hex(rendered.as_bytes())
}

/// Strips the one directory GitHub wraps an archive in.
fn strip_wrapper(path: &str) -> Option<String> {
    let relative = path.split_once('/').map(|(_, rest)| rest)?;
    if relative.is_empty()
        || relative
            .split('/')
            .any(|part| part == ".." || part.is_empty())
    {
        return None;
    }
    Some(relative.to_string())
}

/// True when a wanted path is the file itself or a directory above it.
fn covers(wanted: &str, path: &str) -> bool {
    wanted.is_empty() || path == wanted || path.starts_with(&format!("{wanted}/"))
}

/// The part of one source's content that sits under a path, with the paths
/// made relative to it. A path that names one file yields that one file under
/// its own name.
pub fn under(content: &Content, path: &str) -> Content {
    if path.is_empty() {
        return content.clone();
    }
    if let Some(bytes) = content.get(path) {
        let name = path.rsplit('/').next().unwrap_or(path).to_string();
        return Content::from([(name, bytes.clone())]);
    }
    let prefix = format!("{path}/");
    content
        .iter()
        .filter_map(|(held, bytes)| {
            held.strip_prefix(&prefix)
                .map(|rest| (rest.to_string(), bytes.clone()))
        })
        .collect()
}

/// The names of the directories directly inside one content tree.
fn directories(content: &Content) -> BTreeSet<String> {
    content
        .keys()
        .filter_map(|path| path.split_once('/').map(|(head, _)| head.to_string()))
        .collect()
}

/// The machine the corpus was laid out on.
#[derive(Clone, Debug)]
pub struct Machine {
    /// The home directory the adapters read.
    pub home: PathBuf,
    /// The project roots, one per instruction file.
    pub project_roots: Vec<PathBuf>,
}

/// The machine while it is being laid out.
#[derive(Debug)]
pub struct Ground {
    home: PathBuf,
    projects: PathBuf,
    project_roots: Vec<PathBuf>,
    marketplaces: serde_json::Map<String, Value>,
    installed: serde_json::Map<String, Value>,
}

impl Ground {
    /// An empty machine under one working directory, replacing whatever was
    /// there before so a run never inherits a source the manifest dropped.
    pub fn fresh(root: &Path) -> io::Result<Ground> {
        let _ = fs::remove_dir_all(root);
        let home = root.join("home");
        let projects = root.join("projects");
        fs::create_dir_all(home.join(".claude"))?;
        fs::create_dir_all(home.join(".codex"))?;
        fs::create_dir_all(&projects)?;
        Ok(Ground {
            home,
            projects,
            project_roots: Vec::new(),
            marketplaces: serde_json::Map::new(),
            installed: serde_json::Map::new(),
        })
    }

    /// Lays one path of one source out under the presentation it declares.
    pub fn plant(
        &mut self,
        source: &Source,
        content: &Content,
        present: Presentation,
        agent: Agent,
    ) -> io::Result<usize> {
        match present {
            Presentation::Marketplace => self.marketplace(source, content),
            Presentation::PluginTrees => self.plugin_trees(source, content),
            Presentation::SkillTree => self.skill(agent, &source.name, content),
            Presentation::SkillTrees => self.skill_trees(agent, content),
            Presentation::InstructionFile => self.instruction_file(source, content, agent),
        }
    }

    /// Writes the two plugin registries and hands back what the adapters read.
    pub fn finish(self) -> io::Result<Machine> {
        let plugins = self.home.join(".claude").join("plugins");
        fs::create_dir_all(&plugins)?;
        write_json(
            &plugins.join("known_marketplaces.json"),
            &Value::Object(self.marketplaces),
        )?;
        write_json(
            &plugins.join("installed_plugins.json"),
            &json!({ "version": 2, "plugins": Value::Object(self.installed) }),
        )?;
        Ok(Machine {
            home: self.home,
            project_roots: self.project_roots,
        })
    }

    /// A marketplace clone, plus the registry entry that makes it known. The
    /// entry names the repository it came from, which is what tells the
    /// adapter whether the marketplace is the vendor's own.
    fn marketplace(&mut self, source: &Source, content: &Content) -> io::Result<usize> {
        let clone = self
            .home
            .join(".claude")
            .join("plugins")
            .join("marketplaces")
            .join(&source.name);
        let written = write_tree(&clone, content)?;
        self.marketplaces.insert(
            source.name.clone(),
            json!({
                "source": { "source": "github", "repo": format!("{}/{}", source.owner, source.repo) },
                "installLocation": clone.display().to_string(),
            }),
        );
        Ok(written)
    }

    /// Every immediate subdirectory as one installed plugin of this source's
    /// marketplace, in the install cache and in the install registry.
    fn plugin_trees(&mut self, source: &Source, content: &Content) -> io::Result<usize> {
        let mut written = 0;
        for name in directories(content) {
            let files = under(content, &name);
            let version = plugin_version(&files);
            let install = self
                .home
                .join(".claude")
                .join("plugins")
                .join("cache")
                .join(&source.name)
                .join(&name)
                .join(&version);
            written += write_tree(&install, &files)?;
            self.installed.insert(
                format!("{name}@{}", source.name),
                json!([{
                    "scope": "user",
                    "version": version,
                    "installPath": install.display().to_string(),
                }]),
            );
        }
        Ok(written)
    }

    /// Every immediate subdirectory as one skill of that Agent.
    fn skill_trees(&mut self, agent: Agent, content: &Content) -> io::Result<usize> {
        let mut written = 0;
        for name in directories(content) {
            written += self.skill(agent, &name, &under(content, &name))?;
        }
        Ok(written)
    }

    /// One skill directory of that Agent.
    fn skill(&mut self, agent: Agent, name: &str, content: &Content) -> io::Result<usize> {
        let directory = match agent {
            Agent::ClaudeCode => self.home.join(".claude").join("skills"),
            Agent::Codex => self.home.join(".codex").join("skills"),
        };
        write_tree(&directory.join(name), content)
    }

    /// One instruction file at a project root of its own, named the way that
    /// Agent names it.
    fn instruction_file(
        &mut self,
        source: &Source,
        content: &Content,
        agent: Agent,
    ) -> io::Result<usize> {
        let Some((_, bytes)) = content.iter().next() else {
            return Ok(0);
        };
        let name = INSTRUCTION_FILES
            .iter()
            .find(|(whose, _)| *whose == agent)
            .map(|(_, name)| *name)
            .unwrap_or("CLAUDE.md");
        let root = self.projects.join(&source.name);
        fs::create_dir_all(&root)?;
        fs::write(root.join(name), bytes)?;
        self.project_roots.push(root);
        Ok(1)
    }
}

/// The version a plugin declares, or a placeholder when it declares none.
fn plugin_version(content: &Content) -> String {
    content
        .get(".claude-plugin/plugin.json")
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .and_then(|manifest| {
            manifest
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| UNVERSIONED.to_string())
}

/// Writes one content tree under one directory.
fn write_tree(root: &Path, content: &Content) -> io::Result<usize> {
    for (path, bytes) in content {
        let target = root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, bytes)?;
    }
    Ok(content.len())
}

fn write_json(path: &Path, value: &Value) -> io::Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content(files: &[(&str, &str)]) -> Content {
        files
            .iter()
            .map(|(path, body)| (path.to_string(), body.as_bytes().to_vec()))
            .collect()
    }

    fn source(name: &str) -> Source {
        Source {
            name: name.to_string(),
            owner: "anthropics".to_string(),
            repo: "demo".to_string(),
            commit: "0".repeat(40),
            sha256: String::new(),
            shape: crate::benign::manifest::Shape::Archive { take: Vec::new() },
        }
    }

    fn ground(name: &str) -> (PathBuf, Ground) {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-benign-plant-{name}-{}",
            std::process::id()
        ));
        let ground = Ground::fresh(&root).expect("a fresh machine");
        (root, ground)
    }

    #[test]
    fn the_wrapper_directory_of_a_github_archive_is_stripped() {
        assert_eq!(
            strip_wrapper("skills-34040c9/skills/pdf/SKILL.md").as_deref(),
            Some("skills/pdf/SKILL.md")
        );
        assert_eq!(strip_wrapper("skills-34040c9/").as_deref(), None);
        assert_eq!(strip_wrapper("skills-34040c9/../escape").as_deref(), None);
    }

    #[test]
    fn a_taken_path_covers_the_file_and_everything_below_it() {
        assert!(covers("", "anything"));
        assert!(covers("skills", "skills/pdf/SKILL.md"));
        assert!(covers("README.md", "README.md"));
        assert!(!covers("skills", "skillsets/x"));
    }

    #[test]
    fn the_digest_is_over_the_content_and_not_over_the_order_it_arrived_in() {
        let one = content(&[("a", "1"), ("b", "2")]);
        let other = content(&[("b", "2"), ("a", "1")]);
        assert_eq!(digest(&one), digest(&other));
        assert_ne!(digest(&one), digest(&content(&[("a", "1"), ("b", "3")])));
    }

    #[test]
    fn a_skill_lands_where_its_agent_reads_skills() {
        let (root, mut ground) = ground("skills");
        let files = content(&[("SKILL.md", "---\nname: demo\n---\n")]);
        ground
            .plant(
                &source("demo"),
                &files,
                Presentation::SkillTree,
                Agent::Codex,
            )
            .expect("the skill is planted");
        let machine = ground.finish().expect("the machine is finished");
        assert!(
            machine.home.join(".codex/skills/demo/SKILL.md").is_file(),
            "{}",
            machine.home.display()
        );
        fs::remove_dir_all(&root).expect("the machine goes away");
    }

    #[test]
    fn a_plugin_lands_in_the_install_cache_with_the_registry_entry_that_finds_it() {
        let (root, mut ground) = ground("plugins");
        let files = content(&[
            (
                "notes/.claude-plugin/plugin.json",
                "{\"version\":\"1.2.0\"}",
            ),
            ("notes/.mcp.json", "{\"mcpServers\":{}}"),
        ]);
        ground
            .plant(
                &source("demo-marketplace"),
                &files,
                Presentation::PluginTrees,
                Agent::ClaudeCode,
            )
            .expect("the plugin is planted");
        let machine = ground.finish().expect("the machine is finished");

        let install = machine
            .home
            .join(".claude/plugins/cache/demo-marketplace/notes/1.2.0");
        assert!(install.join(".mcp.json").is_file(), "{}", install.display());
        let registry: Value = serde_json::from_slice(
            &fs::read(machine.home.join(".claude/plugins/installed_plugins.json"))
                .expect("the registry"),
        )
        .expect("the registry is JSON");
        assert_eq!(registry["version"], 2);
        assert_eq!(
            registry["plugins"]["notes@demo-marketplace"][0]["installPath"],
            Value::String(install.display().to_string())
        );
        fs::remove_dir_all(&root).expect("the machine goes away");
    }

    #[test]
    fn a_marketplace_clone_is_registered_with_the_repository_it_came_from() {
        let (root, mut ground) = ground("marketplace");
        let files = content(&[(".claude-plugin/marketplace.json", "{\"name\":\"demo\"}")]);
        ground
            .plant(
                &source("demo"),
                &files,
                Presentation::Marketplace,
                Agent::ClaudeCode,
            )
            .expect("the clone is planted");
        let machine = ground.finish().expect("the machine is finished");

        let known: Value = serde_json::from_slice(
            &fs::read(machine.home.join(".claude/plugins/known_marketplaces.json"))
                .expect("the registry"),
        )
        .expect("the registry is JSON");
        assert_eq!(known["demo"]["source"]["repo"], "anthropics/demo");
        fs::remove_dir_all(&root).expect("the machine goes away");
    }

    #[test]
    fn an_instruction_file_becomes_a_project_root_named_the_way_its_agent_names_it() {
        let (root, mut ground) = ground("instruction");
        ground
            .plant(
                &source("bun"),
                &content(&[("CLAUDE.md", "# bun\n")]),
                Presentation::InstructionFile,
                Agent::ClaudeCode,
            )
            .expect("the instruction file is planted");
        ground
            .plant(
                &source("rust"),
                &content(&[("AGENTS.md", "# rust\n")]),
                Presentation::InstructionFile,
                Agent::Codex,
            )
            .expect("the instruction file is planted");
        let machine = ground.finish().expect("the machine is finished");

        assert_eq!(machine.project_roots.len(), 2);
        assert!(machine.project_roots[0].join("CLAUDE.md").is_file());
        assert!(machine.project_roots[1].join("AGENTS.md").is_file());
        fs::remove_dir_all(&root).expect("the machine goes away");
    }
}
