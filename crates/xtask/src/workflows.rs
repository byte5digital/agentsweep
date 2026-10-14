//! The pipeline hardening rules every workflow is held to (spec section 9.2).
//!
//! Each rule is easy to break in a one-line edit and invisible in review:
//! an Action named by a tag, a cargo build without `--locked`, a release
//! secret reachable from a pull request, a Rule Pack release that becomes
//! the latest release and so takes `releases/latest/download/latest.json`
//! away from the app's updater (section 9.4). The rules read the workflow
//! files as text; nothing is fetched and no Action runs. A violation names
//! the file, the job and the line.
//!
//! What text cannot show is out of reach here: that the `v*` and `rules-v*`
//! tags are protected and that the `release` environment requires reviewers
//! are repository settings (section 9.8, item 3).

mod reader;

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub use reader::{Entry, Node, Scalar};

/// The directory of the workflows under a repository root.
pub fn directory(root: &Path) -> PathBuf {
    root.join(".github").join("workflows")
}

/// The job name a violation outside every job carries.
pub const WORKFLOW_LEVEL: &str = "(workflow)";

/// The name of the GitHub environment that holds every release secret.
pub const RELEASE_ENVIRONMENT: &str = "release";

/// Actions known to create a GitHub release.
const RELEASE_ACTIONS: [&str; 4] = [
    "softprops/action-gh-release",
    "ncipollo/release-action",
    "actions/create-release",
    "tauri-apps/tauri-action",
];

/// The cargo commands that resolve dependencies and so must carry `--locked`.
const LOCKED_COMMANDS: [&str; 5] = ["build", "test", "clippy", "install", "auditable"];

/// Triggers that run on code from outside the repository's maintainers.
const PULL_REQUEST_TRIGGERS: [&str; 3] = ["pull_request", "pull_request_target", "workflow_run"];

/// One pipeline hardening rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningRule {
    /// Every `uses:` names its Action by a forty hex digit commit SHA with a
    /// trailing comment naming the version; local actions are exempt.
    PinnedActions,
    /// Every `cargo build`, `test`, `clippy`, `install` and `auditable` in a
    /// `run:` carries `--locked`.
    LockedCargo,
    /// The `release` environment and every secret other than `GITHUB_TOKEN`
    /// are reached only from a workflow started by a `v*` or `rules-v*` tag
    /// push or a published release; a pull-request workflow names no secret
    /// and no environment.
    ReleaseReach,
    /// Every step that creates a release from a `rules-v*` tag sets
    /// `make_latest` to false.
    RulePackNotLatest,
}

impl HardeningRule {
    /// Every rule.
    pub const ALL: [HardeningRule; 4] = [
        HardeningRule::PinnedActions,
        HardeningRule::LockedCargo,
        HardeningRule::ReleaseReach,
        HardeningRule::RulePackNotLatest,
    ];

    /// The violations of this rule in one workflow.
    pub fn check(self, workflow: &Workflow) -> Vec<Violation> {
        let mut found = Vec::new();
        let mut report = |job: &str, line: usize, message: String| {
            found.push(Violation {
                rule: self,
                file: workflow.file.clone(),
                job: job.to_string(),
                line,
                message,
            });
        };
        match self {
            HardeningRule::PinnedActions => pinned_actions(workflow, &mut report),
            HardeningRule::LockedCargo => locked_cargo(workflow, &mut report),
            HardeningRule::ReleaseReach => release_reach(workflow, &mut report),
            HardeningRule::RulePackNotLatest => rule_pack_not_latest(workflow, &mut report),
        }
        found
    }
}

impl fmt::Display for HardeningRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HardeningRule::PinnedActions => "every Action pinned by commit SHA",
            HardeningRule::LockedCargo => "every cargo build --locked",
            HardeningRule::ReleaseReach => "release secrets reached only from a release tag",
            HardeningRule::RulePackNotLatest => "Rule Pack releases never the latest release",
        })
    }
}

/// A broken rule, with where it broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The rule that broke.
    pub rule: HardeningRule,
    /// The workflow's file name.
    pub file: String,
    /// The job id, or [`WORKFLOW_LEVEL`] outside every job.
    pub job: String,
    /// The line, counted from one.
    pub line: usize,
    /// What is wrong, in a sentence.
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: job `{}`: {} ({})",
            self.file, self.line, self.job, self.message, self.rule
        )
    }
}

/// One workflow file, read.
#[derive(Debug, Clone)]
pub struct Workflow {
    file: String,
    root: Node,
}

impl Workflow {
    /// Reads a workflow from its text; `file` is the name violations carry.
    pub fn parse(file: &str, text: &str) -> Result<Self, String> {
        let root = reader::read(text).map_err(|error| format!("{file}: {error}"))?;
        Ok(Workflow {
            file: file.to_string(),
            root,
        })
    }

    /// The file name violations carry.
    pub fn file(&self) -> &str {
        &self.file
    }

    fn jobs(&self) -> &[Entry] {
        match self.root.get("jobs").map(|jobs| &jobs.value) {
            Some(Node::Map(jobs)) => jobs,
            _ => &[],
        }
    }

    /// Calls `visit` with every map entry, and the job it sits in.
    fn each_entry(&self, mut visit: impl FnMut(&str, &Entry)) {
        let Node::Map(entries) = &self.root else {
            return;
        };
        for entry in entries {
            if entry.key == "jobs" {
                for job in self.jobs() {
                    visit(WORKFLOW_LEVEL, job);
                    walk_entries(&job.value, &mut |inner| visit(&job.key, inner));
                }
            } else {
                visit(WORKFLOW_LEVEL, entry);
                walk_entries(&entry.value, &mut |inner| visit(WORKFLOW_LEVEL, inner));
            }
        }
    }

    /// Calls `visit` with every scalar, the key it sits under, and its job.
    fn each_scalar(&self, mut visit: impl FnMut(&str, &str, &Scalar)) {
        self.each_entry(|job, entry| match &entry.value {
            Node::Scalar(scalar) => visit(job, &entry.key, scalar),
            Node::Seq(items) => {
                for item in items {
                    if let Node::Scalar(scalar) = item {
                        visit(job, &entry.key, scalar);
                    }
                }
            }
            Node::Map(_) => {}
        });
    }

    /// Calls `visit` with every map that is a step: one with `uses` or `run`.
    fn each_step(&self, mut visit: impl FnMut(&str, &Node)) {
        for job in self.jobs() {
            if let Some(steps) = job.value.get("steps")
                && let Node::Seq(steps) = &steps.value
            {
                for step in steps {
                    visit(&job.key, step);
                }
            }
        }
    }

    fn triggers(&self) -> Vec<Trigger<'_>> {
        let Some(on) = self.root.get("on") else {
            return Vec::new();
        };
        let bare = |text: &str, line: usize| Trigger {
            event: text.to_string(),
            line,
            filters: None,
        };
        match &on.value {
            Node::Scalar(scalar) => vec![bare(&scalar.text, on.line)],
            Node::Seq(items) => items
                .iter()
                .filter_map(Node::text)
                .map(|text| bare(text, on.line))
                .collect(),
            Node::Map(entries) => entries
                .iter()
                .map(|entry| Trigger {
                    event: entry.key.clone(),
                    line: entry.line,
                    filters: Some(&entry.value),
                })
                .collect(),
        }
    }
}

fn walk_entries(node: &Node, visit: &mut dyn FnMut(&Entry)) {
    match node {
        Node::Map(entries) => {
            for entry in entries {
                visit(entry);
                walk_entries(&entry.value, visit);
            }
        }
        Node::Seq(items) => {
            for item in items {
                walk_entries(item, visit);
            }
        }
        Node::Scalar(_) => {}
    }
}

struct Trigger<'a> {
    event: String,
    line: usize,
    filters: Option<&'a Node>,
}

impl Trigger<'_> {
    fn filter(&self, key: &str) -> Option<Vec<&str>> {
        self.filters
            .and_then(|filters| filters.get(key))
            .map(|entry| entry.value.texts())
    }

    /// The tag patterns of a push that is started by tags, positive ones only.
    fn tag_patterns(&self) -> Vec<&str> {
        if self.event != "push" {
            return Vec::new();
        }
        self.filter("tags")
            .unwrap_or_default()
            .into_iter()
            .filter(|pattern| !pattern.starts_with('!'))
            .collect()
    }

    /// Why this trigger may not start a workflow that reaches a release
    /// secret, or `None` when it may.
    fn release_refusal(&self) -> Option<String> {
        match self.event.as_str() {
            "push" => {
                for key in ["branches", "branches-ignore", "tags-ignore"] {
                    if self.filter(key).is_some() {
                        return Some(format!("a push filtered by `{key}`"));
                    }
                }
                let patterns = self.tag_patterns();
                if patterns.is_empty() {
                    return Some("a push not limited to tags".to_string());
                }
                patterns
                    .iter()
                    .find(|pattern| !(pattern.starts_with('v') || pattern.starts_with("rules-v")))
                    .map(|pattern| format!("a push of tags matching `{pattern}`"))
            }
            "release" => {
                let types = self.filter("types").unwrap_or_default();
                (types != ["published"])
                    .then(|| "a release event other than exactly `types: [published]`".to_string())
            }
            other => Some(format!("`{other}`")),
        }
    }
}

fn pinned_actions(workflow: &Workflow, report: &mut dyn FnMut(&str, usize, String)) {
    workflow.each_entry(|job, entry| {
        if entry.key != "uses" {
            return;
        }
        let Node::Scalar(uses) = &entry.value else {
            return;
        };
        let name = uses.text.trim();
        if name.starts_with("./") {
            return;
        }
        let pinned = if let Some(image) = name.strip_prefix("docker://") {
            match image.rsplit_once("@sha256:") {
                Some((_, digest)) if is_hex(digest, 64) => None,
                _ => Some(format!(
                    "`{name}` names a container image by tag, not by its sha256 digest"
                )),
            }
        } else {
            match name.rsplit_once('@') {
                Some((_, git_ref)) if is_hex(git_ref, 40) => None,
                Some((_, git_ref)) => Some(format!(
                    "`{name}` is pinned to `{git_ref}`, a tag, a branch or a short SHA, not a forty hex digit commit SHA"
                )),
                None => Some(format!("`{name}` names no ref at all")),
            }
        };
        if let Some(message) = pinned {
            report(job, uses.line, message);
            return;
        }
        let names_version = uses
            .comment
            .as_deref()
            .and_then(|comment| comment.split_whitespace().next())
            .map(|word| word.strip_prefix('v').unwrap_or(word))
            .is_some_and(|word| word.starts_with(|c: char| c.is_ascii_digit()));
        if !names_version {
            report(
                job,
                uses.line,
                format!("`{name}` has no trailing comment naming the version, like `# v1.2.3`"),
            );
        }
    });
}

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// One shell command of a `run:` script: its line and its words, quotes
/// stripped, cut at a shell comment.
struct Command {
    line: usize,
    words: Vec<String>,
}

impl Command {
    fn has(&self, words: &[&str]) -> bool {
        self.words
            .windows(words.len())
            .any(|window| window == words)
    }
}

/// Splits a `run:` script into commands at line ends (after joining `\`
/// continuations), `&&`, `||`, `;`, `|`, parentheses and backticks.
fn commands(script: &Scalar) -> Vec<Command> {
    let mut logical: Vec<(usize, String)> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (offset, line) in script.text.split('\n').enumerate() {
        let (start, mut text) = pending
            .take()
            .unwrap_or((script.line + offset, String::new()));
        let code = match line.find(" #") {
            Some(cut) => &line[..cut],
            None if line.trim_start().starts_with('#') => "",
            None => line,
        };
        if let Some(joined) = code.trim_end().strip_suffix('\\') {
            text.push_str(joined);
            text.push(' ');
            pending = Some((start, text));
        } else {
            text.push_str(code);
            logical.push((start, text));
        }
    }
    if let Some(rest) = pending {
        logical.push(rest);
    }
    let mut found = Vec::new();
    for (line, text) in logical {
        let mut text = text;
        for separator in ["&&", "||", ";", "|", "(", ")", "`"] {
            text = text.replace(separator, "\n");
        }
        for segment in text.split('\n') {
            let words: Vec<String> = segment
                .split_whitespace()
                .map(|word| word.trim_matches(|c| c == '"' || c == '\'').to_string())
                .collect();
            if !words.is_empty() {
                found.push(Command { line, words });
            }
        }
    }
    found
}

fn locked_cargo(workflow: &Workflow, report: &mut dyn FnMut(&str, usize, String)) {
    workflow.each_scalar(|job, key, scalar| {
        if key != "run" {
            return;
        }
        for command in commands(scalar) {
            let Some(cargo) = command
                .words
                .iter()
                .position(|word| word == "cargo" || word.ends_with("/cargo"))
            else {
                continue;
            };
            let arguments: Vec<&str> = command.words[cargo + 1..]
                .iter()
                .map(String::as_str)
                .take_while(|word| *word != "--")
                .collect();
            let Some(subcommand) = arguments
                .iter()
                .find(|word| !word.starts_with('+') && !word.starts_with('-'))
            else {
                continue;
            };
            if !LOCKED_COMMANDS.contains(subcommand) {
                continue;
            }
            let asks_version = *subcommand != "install"
                && arguments
                    .iter()
                    .any(|word| *word == "--version" || *word == "-V");
            if asks_version || arguments.contains(&"--locked") {
                continue;
            }
            report(
                job,
                command.line,
                format!("`cargo {subcommand}` runs without `--locked`"),
            );
        }
    });
}

/// Secrets other than `GITHUB_TOKEN` named in the expressions of one scalar:
/// each with its line and how it is named.
fn secrets_in(key: &str, scalar: &Scalar) -> Vec<(usize, String)> {
    let text = &scalar.text;
    let mut expressions: Vec<(usize, &str)> = Vec::new();
    if key == "if" {
        expressions.push((0, text));
    }
    let mut from = 0;
    while let Some(open) = text[from..].find("${{") {
        let start = from + open + 3;
        let end = text[start..]
            .find("}}")
            .map_or(text.len(), |close| start + close);
        expressions.push((start, &text[start..end]));
        from = end;
    }
    let mut found = Vec::new();
    for (base, expression) in expressions {
        let mut from = 0;
        while let Some(at) = expression[from..].find("secrets") {
            let start = from + at;
            let end = start + "secrets".len();
            from = end;
            let ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
            let before = expression[..start].chars().next_back();
            if before.is_some_and(|c| ident(c) || c == '.') {
                continue;
            }
            let rest = &expression[end..];
            if rest.starts_with(ident) {
                continue;
            }
            let name: String = if let Some(dotted) = rest.strip_prefix('.') {
                dotted.chars().take_while(|c| ident(*c)).collect()
            } else if let Some(indexed) = rest.strip_prefix('[') {
                indexed
                    .trim_start_matches(['\'', '"'])
                    .chars()
                    .take_while(|c| ident(*c))
                    .collect()
            } else {
                String::new()
            };
            if name.eq_ignore_ascii_case("GITHUB_TOKEN") {
                continue;
            }
            let line = scalar.line + text[..base + start].matches('\n').count();
            let named = if name.is_empty() {
                "every secret through the `secrets` context".to_string()
            } else {
                format!("the secret `{name}`")
            };
            found.push((line, named));
        }
    }
    found
}

/// Where a workflow reaches past `GITHUB_TOKEN`: job, line, what it names,
/// and whether that is the `release` environment or a secret (as opposed
/// to another environment).
struct Reach {
    job: String,
    line: usize,
    named: String,
    release: bool,
}

fn reaches(workflow: &Workflow) -> Vec<Reach> {
    let mut found = Vec::new();
    for job in workflow.jobs() {
        let Some(environment) = job.value.get("environment") else {
            continue;
        };
        let (name, line) = match &environment.value {
            Node::Scalar(scalar) => (scalar.text.clone(), scalar.line),
            map => match map.get("name") {
                Some(name) => (name.value.text().unwrap_or("").to_string(), name.line),
                None => (String::new(), environment.line),
            },
        };
        let release = name.eq_ignore_ascii_case(RELEASE_ENVIRONMENT) || name.contains("${{");
        found.push(Reach {
            job: job.key.clone(),
            line,
            named: format!("the environment `{name}`"),
            release,
        });
    }
    workflow.each_scalar(|job, key, scalar| {
        if key == "secrets" && scalar.text == "inherit" {
            found.push(Reach {
                job: job.to_string(),
                line: scalar.line,
                named: "every secret through `secrets: inherit`".to_string(),
                release: true,
            });
        }
        for (line, named) in secrets_in(key, scalar) {
            found.push(Reach {
                job: job.to_string(),
                line,
                named,
                release: true,
            });
        }
    });
    found
}

fn release_reach(workflow: &Workflow, report: &mut dyn FnMut(&str, usize, String)) {
    let triggers = workflow.triggers();
    let reaches = reaches(workflow);
    let refusals: Vec<(String, usize)> = triggers
        .iter()
        .filter_map(|trigger| trigger.release_refusal().map(|why| (why, trigger.line)))
        .collect();
    for reach in reaches.iter().filter(|reach| reach.release) {
        if triggers.is_empty() {
            report(
                &reach.job,
                reach.line,
                format!("names {}, but the workflow states no trigger", reach.named),
            );
        }
        for (why, line) in &refusals {
            report(
                &reach.job,
                reach.line,
                format!(
                    "names {}, but the workflow is started by {why} (line {line}); only a `v*` or `rules-v*` tag push or a published release may start it",
                    reach.named
                ),
            );
        }
    }
    for trigger in &triggers {
        if !PULL_REQUEST_TRIGGERS.contains(&trigger.event.as_str()) {
            continue;
        }
        for reach in &reaches {
            report(
                &reach.job,
                reach.line,
                format!(
                    "names {} in a workflow started by `{}` (line {})",
                    reach.named, trigger.event, trigger.line
                ),
            );
        }
    }
}

fn rule_pack_not_latest(workflow: &Workflow, report: &mut dyn FnMut(&str, usize, String)) {
    let rule_pack_tags = workflow.triggers().iter().any(|trigger| {
        trigger
            .tag_patterns()
            .iter()
            .any(|pattern| glob_matches(pattern, "rules-v1") || glob_matches(pattern, "rules-v12"))
    });
    workflow.each_step(|job, step| {
        if let Some(uses) = step.get("uses")
            && let Some(name) = uses.value.text()
        {
            let action = name.split('@').next().unwrap_or("").to_ascii_lowercase();
            if RELEASE_ACTIONS.contains(&action.as_str()) {
                let with = step.get("with").map(|with| &with.value);
                let tag_names_rules = with.is_some_and(|with| {
                    ["tag_name", "tag", "tagName"].iter().any(|key| {
                        with.get(key)
                            .and_then(|entry| entry.value.text())
                            .is_some_and(|tag| tag.contains("rules-v"))
                    })
                });
                let make_latest = with
                    .and_then(|with| with.get("make_latest"))
                    .and_then(|entry| entry.value.text())
                    .map(|text| text.trim().to_ascii_lowercase());
                if (rule_pack_tags || tag_names_rules) && make_latest.as_deref() != Some("false") {
                    report(
                        job,
                        uses.line,
                        format!(
                            "`{action}` creates a release from a `rules-v*` tag without `make_latest: false`"
                        ),
                    );
                }
            }
        }
        let Some(Node::Scalar(script)) = step.get("run").map(|run| &run.value) else {
            return;
        };
        for command in commands(script) {
            let names_rules = command.words.iter().any(|word| word.contains("rules-v"));
            if !(rule_pack_tags || names_rules) {
                continue;
            }
            if command.has(&["gh", "release", "create"])
                && !command.words.iter().any(|word| word == "--latest=false")
            {
                report(
                    job,
                    command.line,
                    "`gh release create` makes a `rules-v*` release without `--latest=false`"
                        .to_string(),
                );
            }
            if command.has(&["gh", "api"]) && creates_release_through_the_api(&command) {
                let compact: String = command
                    .words
                    .concat()
                    .chars()
                    .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
                    .collect();
                if !(compact.contains("make_latest=false") || compact.contains("make_latest:false"))
                {
                    report(
                        job,
                        command.line,
                        "`gh api` creates a `rules-v*` release without `make_latest=false`"
                            .to_string(),
                    );
                }
            }
        }
    });
}

fn creates_release_through_the_api(command: &Command) -> bool {
    let names_releases = command.words.iter().any(|word| {
        word.trim_end_matches('/').ends_with("/releases") || word.ends_with("/releases?")
    });
    let writes = command.words.iter().enumerate().any(|(index, word)| {
        matches!(
            word.as_str(),
            "-f" | "-F" | "--field" | "--raw-field" | "--input" | "-XPOST"
        ) || ((word == "-X" || word == "--method")
            && command
                .words
                .get(index + 1)
                .is_some_and(|method| method.eq_ignore_ascii_case("POST")))
            || word.eq_ignore_ascii_case("--method=POST")
    });
    names_releases && writes
}

/// Whether a GitHub filter pattern matches a tag name: `*` and `**` any run
/// of characters, `?` one, `+` one or more of the one before, `[...]` a class.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    glob_from(&pattern, &name)
}

fn glob_from(pattern: &[char], name: &[char]) -> bool {
    let Some((&first, rest)) = pattern.split_first() else {
        return name.is_empty();
    };
    if first == '*' {
        let rest = if rest.first() == Some(&'*') {
            &rest[1..]
        } else {
            rest
        };
        return (0..=name.len()).any(|skip| glob_from(rest, &name[skip..]));
    }
    let (matches_one, after): (Box<dyn Fn(char) -> bool>, &[char]) = match first {
        '?' => (Box::new(|_| true), rest),
        '[' => match rest.iter().position(|c| *c == ']') {
            Some(close) => {
                let class: Vec<char> = rest[..close].to_vec();
                (Box::new(move |c| in_class(&class, c)), &rest[close + 1..])
            }
            None => (Box::new(move |c| c == first), rest),
        },
        literal => (Box::new(move |c| c == literal), rest),
    };
    if after.first() == Some(&'+') {
        let after = &after[1..];
        let mut taken = 0;
        while taken < name.len() && matches_one(name[taken]) {
            taken += 1;
            if glob_from(after, &name[taken..]) {
                return true;
            }
        }
        return false;
    }
    match name.split_first() {
        Some((&c, tail)) if matches_one(c) => glob_from(after, tail),
        _ => false,
    }
}

fn in_class(class: &[char], c: char) -> bool {
    let mut index = 0;
    while index < class.len() {
        if index + 2 < class.len() && class[index + 1] == '-' {
            if (class[index]..=class[index + 2]).contains(&c) {
                return true;
            }
            index += 3;
        } else {
            if class[index] == c {
                return true;
            }
            index += 1;
        }
    }
    false
}

/// Reads every `.yml` and `.yaml` file of a directory, in name order.
pub fn load_directory(directory: &Path) -> Result<Vec<Workflow>, String> {
    let entries =
        fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension == "yml" || extension == "yaml")
        })
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let text =
                fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            Workflow::parse(&name, &text)
        })
        .collect()
}

/// The violations of one rule across every workflow of a directory.
pub fn check_directory(directory: &Path, rule: HardeningRule) -> Result<Vec<Violation>, String> {
    Ok(load_directory(directory)?
        .iter()
        .flat_map(|workflow| rule.check(workflow))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_patterns_match_the_way_github_filters_do() {
        assert!(glob_matches("rules-v*", "rules-v1"));
        assert!(glob_matches("*", "rules-v1"));
        assert!(glob_matches("**", "rules-v1"));
        assert!(glob_matches("rules-v[0-9]+", "rules-v12"));
        assert!(!glob_matches("v*", "rules-v1"));
        assert!(!glob_matches("rules-v[0-9]", "rules-v12"));
        assert!(glob_matches("v[0-9]+.[0-9]+.[0-9]+", "v0.1.0"));
    }

    #[test]
    fn secrets_are_found_in_expressions_only() {
        let scalar = Scalar {
            text: "echo our secrets\nkey=${{ secrets.TAP_TOKEN }} t=${{ secrets.GITHUB_TOKEN }}\n${{ toJSON(secrets) }} ${{ secrets['APPLE_KEY'] }}".to_string(),
            line: 10,
            comment: None,
        };
        let found = secrets_in("run", &scalar);
        assert_eq!(
            found,
            vec![
                (11, "the secret `TAP_TOKEN`".to_string()),
                (12, "every secret through the `secrets` context".to_string()),
                (12, "the secret `APPLE_KEY`".to_string()),
            ]
        );
        let condition = Scalar {
            text: "secrets.SIGNING_KEY != ''".to_string(),
            line: 3,
            comment: None,
        };
        assert_eq!(secrets_in("if", &condition).len(), 1);
    }

    #[test]
    fn a_script_splits_into_commands_with_their_lines() {
        let script = Scalar {
            text: "cargo build \\\n  --locked && cargo test # not --locked\n# cargo build\necho $(cargo clippy)".to_string(),
            line: 5,
            comment: None,
        };
        let found: Vec<(usize, String)> = commands(&script)
            .into_iter()
            .map(|command| (command.line, command.words.join(" ")))
            .collect();
        assert_eq!(
            found,
            vec![
                (5, "cargo build --locked".to_string()),
                (5, "cargo test".to_string()),
                (8, "echo $".to_string()),
                (8, "cargo clippy".to_string()),
            ]
        );
    }
}
