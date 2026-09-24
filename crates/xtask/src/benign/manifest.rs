//! The benign corpus manifest: which public sources it is made of, how each
//! one is presented to the Surface Adapters, and the digest that pins it.
//!
//! The file is `corpus/benign/manifest.toml` and it is committed. Everything it
//! names is public, pinned to a commit and fetched at test time; nothing it
//! names is ever committed to this repository.

use std::fmt;
use std::fs;
use std::path::Path;

/// Where the manifest lives, relative to the repository root.
pub const MANIFEST: &str = "corpus/benign/manifest.toml";

/// Whose Surfaces a source is laid out on.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Agent {
    /// Claude Code, the default.
    #[default]
    ClaudeCode,
    /// Codex.
    Codex,
}

impl Agent {
    /// The spelling the manifest uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "claude-code",
            Agent::Codex => "codex",
        }
    }

    fn parse(text: &str) -> Option<Agent> {
        match text {
            "claude-code" => Some(Agent::ClaudeCode),
            "codex" => Some(Agent::Codex),
            _ => None,
        }
    }
}

/// How one path of a source is laid out, so that the Surface Adapter sees it
/// the way it would see the real thing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presentation {
    /// A marketplace clone, registered in the Agent's marketplace registry.
    Marketplace,
    /// Each immediate subdirectory is one installed plugin.
    PluginTrees,
    /// The path itself is one skill directory.
    SkillTree,
    /// Each immediate subdirectory is one skill directory.
    SkillTrees,
    /// The file is the instruction file of a project root of its own.
    InstructionFile,
}

impl Presentation {
    /// The spelling the manifest uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Presentation::Marketplace => "marketplace",
            Presentation::PluginTrees => "plugin-trees",
            Presentation::SkillTree => "skill-tree",
            Presentation::SkillTrees => "skill-trees",
            Presentation::InstructionFile => "instruction-file",
        }
    }

    fn parse(text: &str) -> Option<Presentation> {
        match text {
            "marketplace" => Some(Presentation::Marketplace),
            "plugin-trees" => Some(Presentation::PluginTrees),
            "skill-tree" => Some(Presentation::SkillTree),
            "skill-trees" => Some(Presentation::SkillTrees),
            "instruction-file" => Some(Presentation::InstructionFile),
            _ => None,
        }
    }
}

/// One path of an archive and how it is presented.
#[derive(Clone, Debug)]
pub struct Take {
    /// The path inside the archive, empty for the archive root.
    pub path: String,
    /// How it is laid out.
    pub present: Presentation,
    /// Whose Surfaces it is laid out on.
    pub agent: Agent,
}

/// One source of the corpus, pinned to a commit.
#[derive(Clone, Debug)]
pub struct Source {
    /// The name the corpus knows it by, which is also the name of the
    /// marketplace clone or the project root it becomes.
    pub name: String,
    /// The repository owner.
    pub owner: String,
    /// The repository.
    pub repo: String,
    /// The commit it is pinned to.
    pub commit: String,
    /// The digest of the content taken from it, empty until it is recorded.
    pub sha256: String,
    /// What is taken from it.
    pub shape: Shape,
}

/// The two shapes a source comes in.
#[derive(Clone, Debug)]
pub enum Shape {
    /// The repository's archive at that commit, with the paths to take.
    Archive {
        /// Which paths are taken and how each is presented.
        take: Vec<Take>,
    },
    /// One file of the repository at that commit.
    File {
        /// The path of the file in the repository.
        path: String,
        /// How it is presented.
        present: Presentation,
        /// Whose Surfaces it is laid out on.
        agent: Agent,
    },
}

impl Source {
    /// Where the content is fetched from. An archive comes from the codeload
    /// host and a file from the raw host; neither ever runs a git binary.
    pub fn url(&self) -> String {
        match &self.shape {
            Shape::Archive { .. } => format!(
                "https://codeload.github.com/{}/{}/tar.gz/{}",
                self.owner, self.repo, self.commit
            ),
            Shape::File { path, .. } => format!(
                "https://raw.githubusercontent.com/{}/{}/{}/{}",
                self.owner, self.repo, self.commit, path
            ),
        }
    }

    /// The name of the cached download, which carries the commit so a re-pin
    /// never reads the previous one.
    pub fn cache_name(&self) -> String {
        let suffix = match &self.shape {
            Shape::Archive { .. } => "tar.gz".to_string(),
            Shape::File { path, .. } => path.replace(['/', '\\'], "-"),
        };
        format!(
            "{}-{}-{suffix}",
            self.name,
            &self.commit[..12.min(self.commit.len())]
        )
    }

    /// How the source is named in a report: the pin a person can go and look
    /// at.
    pub fn pin(&self) -> String {
        format!(
            "{}/{}@{}",
            self.owner,
            self.repo,
            &self.commit[..7.min(self.commit.len())]
        )
    }
}

/// Everything the benign corpus is made of, in the order the manifest lists
/// it.
#[derive(Clone, Debug, Default)]
pub struct Manifest {
    /// The sources, archives first.
    pub sources: Vec<Source>,
}

/// What is wrong with the manifest.
#[derive(Clone, Debug)]
pub struct ManifestError {
    /// Where the problem is, the file or one source of it.
    pub at: String,
    /// What is wrong.
    pub problem: String,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.problem)
    }
}

impl std::error::Error for ManifestError {}

impl Manifest {
    /// Reads the committed manifest under one repository root.
    pub fn of(root: &Path) -> Result<Manifest, ManifestError> {
        let path = root.join(MANIFEST);
        let text = fs::read_to_string(&path).map_err(|error| ManifestError {
            at: MANIFEST.to_string(),
            problem: format!("could not be read: {error}"),
        })?;
        Manifest::parse(&text)
    }

    /// Reads one manifest from its text.
    pub fn parse(text: &str) -> Result<Manifest, ManifestError> {
        let table: toml::Table = text.parse().map_err(|error| ManifestError {
            at: MANIFEST.to_string(),
            problem: format!("is not TOML: {error}"),
        })?;

        let mut sources = Vec::new();
        for (key, shape) in [("archive", true), ("file", false)] {
            let Some(listed) = table.get(key) else {
                continue;
            };
            let listed = listed.as_array().ok_or_else(|| ManifestError {
                at: key.to_string(),
                problem: "is not a list of sources".to_string(),
            })?;
            for entry in listed {
                sources.push(source(entry, shape)?);
            }
        }
        if sources.is_empty() {
            return Err(ManifestError {
                at: MANIFEST.to_string(),
                problem: "names no source".to_string(),
            });
        }
        Ok(Manifest { sources })
    }

    /// The manifest text with the digests of what was fetched written into it.
    ///
    /// The rewrite is line by line rather than a re-serialisation, so the
    /// comments that say what each source is and why survive it.
    pub fn with_recorded(text: &str, recorded: &[(String, String)]) -> String {
        let mut out = String::with_capacity(text.len());
        let mut current = String::new();
        for line in text.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("name = ") {
                current = rest.trim().trim_matches('"').to_string();
            }
            if trimmed.starts_with("sha256 = ")
                && let Some((_, digest)) = recorded.iter().find(|(name, _)| *name == current)
            {
                out.push_str(&format!("sha256 = \"{digest}\"\n"));
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

/// Reads one `[[archive]]` or `[[file]]` entry.
fn source(entry: &toml::Value, archive: bool) -> Result<Source, ManifestError> {
    let table = entry.as_table().ok_or_else(|| ManifestError {
        at: MANIFEST.to_string(),
        problem: "a source is not a table".to_string(),
    })?;
    let name = text(table, "name", "a source")?;
    let at = format!("source {name}");
    let owner = text(table, "owner", &at)?;
    let repo = text(table, "repo", &at)?;
    let commit = text(table, "commit", &at)?;
    if commit.len() != 40 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ManifestError {
            at,
            problem: "`commit` is not a full commit hash, and only a commit pins a source"
                .to_string(),
        });
    }
    let sha256 = table
        .get("sha256")
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_string();

    let shape = if archive {
        let listed = table
            .get("take")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| ManifestError {
                at: at.clone(),
                problem: "`take` names the paths an archive contributes".to_string(),
            })?;
        let mut take = Vec::new();
        for entry in listed {
            let entry = entry.as_table().ok_or_else(|| ManifestError {
                at: at.clone(),
                problem: "a `take` entry is not a table".to_string(),
            })?;
            take.push(Take {
                path: entry
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                present: presentation(entry, &at)?,
                agent: agent(entry, &at)?,
            });
        }
        if take.is_empty() {
            return Err(ManifestError {
                at,
                problem: "takes nothing from its archive".to_string(),
            });
        }
        Shape::Archive { take }
    } else {
        Shape::File {
            path: text(table, "path", &at)?,
            present: presentation(table, &at)?,
            agent: agent(table, &at)?,
        }
    };

    Ok(Source {
        name,
        owner,
        repo,
        commit,
        sha256,
        shape,
    })
}

fn text(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    at: &str,
) -> Result<String, ManifestError> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ManifestError {
            at: at.to_string(),
            problem: format!("has no `{key}`"),
        })
}

fn presentation(
    table: &toml::map::Map<String, toml::Value>,
    at: &str,
) -> Result<Presentation, ManifestError> {
    let spelling = text(table, "present", at)?;
    Presentation::parse(&spelling).ok_or_else(|| ManifestError {
        at: at.to_string(),
        problem: format!("`{spelling}` is not a presentation"),
    })
}

fn agent(table: &toml::map::Map<String, toml::Value>, at: &str) -> Result<Agent, ManifestError> {
    match table.get("agent").and_then(toml::Value::as_str) {
        None => Ok(Agent::default()),
        Some(spelling) => Agent::parse(spelling).ok_or_else(|| ManifestError {
            at: at.to_string(),
            problem: format!("`{spelling}` is not an Agent of this corpus"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo_root;

    #[test]
    fn the_committed_manifest_pins_every_source_to_a_commit() {
        let manifest = Manifest::of(&repo_root()).expect("the manifest reads");
        assert!(manifest.sources.len() >= 33, "{}", manifest.sources.len());
        for source in &manifest.sources {
            assert_eq!(source.commit.len(), 40, "{}", source.name);
            assert!(source.url().contains(&source.commit), "{}", source.name);
        }
    }

    /// Two sources of one name would share a project root or a marketplace
    /// clone, and the corpus would quietly shrink.
    #[test]
    fn every_source_of_the_committed_manifest_has_its_own_name() {
        let manifest = Manifest::of(&repo_root()).expect("the manifest reads");
        let mut names: Vec<&str> = manifest
            .sources
            .iter()
            .map(|source| source.name.as_str())
            .collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "two sources share a name");
    }

    #[test]
    fn the_committed_manifest_covers_every_presentation() {
        let manifest = Manifest::of(&repo_root()).expect("the manifest reads");
        let mut seen: Vec<&str> = Vec::new();
        for source in &manifest.sources {
            match &source.shape {
                Shape::Archive { take } => {
                    seen.extend(take.iter().map(|take| take.present.as_str()))
                }
                Shape::File { present, .. } => seen.push(present.as_str()),
            }
        }
        for present in [
            "marketplace",
            "plugin-trees",
            "skill-tree",
            "skill-trees",
            "instruction-file",
        ] {
            assert!(seen.contains(&present), "{present} is never used");
        }
    }

    #[test]
    fn a_source_pinned_to_a_branch_rather_than_a_commit_is_refused() {
        let problem = Manifest::parse(
            "[[file]]\nname = \"x\"\nowner = \"o\"\nrepo = \"r\"\ncommit = \"main\"\npath = \"README.md\"\npresent = \"instruction-file\"\n",
        )
        .expect_err("a branch does not pin");
        assert!(problem.problem.contains("commit"), "{problem}");
    }

    #[test]
    fn a_presentation_the_corpus_does_not_know_is_refused() {
        let problem = Manifest::parse(
            "[[file]]\nname = \"x\"\nowner = \"o\"\nrepo = \"r\"\ncommit = \"0123456789012345678901234567890123456789\"\npath = \"README.md\"\npresent = \"hook\"\n",
        )
        .expect_err("an unknown presentation does not load");
        assert!(problem.problem.contains("hook"), "{problem}");
    }

    #[test]
    fn recording_a_digest_leaves_the_prose_of_the_manifest_alone() {
        let text = "# why this source is here\n[[file]]\nname = \"demo\"\nsha256 = \"\"\n";
        let recorded = Manifest::with_recorded(text, &[("demo".to_string(), "abc".to_string())]);
        assert!(recorded.contains("# why this source is here"), "{recorded}");
        assert!(recorded.contains("sha256 = \"abc\""), "{recorded}");
    }
}
