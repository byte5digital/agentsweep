//! How a Finding reads in the Simple Posture (spec section 8.4): a verdict
//! sentence about a named thing as its title, the body lines in their fixed
//! order, the Severity as one of four words on a red or an amber chip, and,
//! on a Managed Item, the message the user can hand their administrator.
//!
//! Everything here is a pure function of one Finding as the daemon sends it,
//! facts included: the title is built from the Item's kind, its name and the
//! verdict phrase of the Rule behind it, and every fixed sentence is written
//! once, below. Nothing the Simple Posture shows carries an id, a Rule
//! number, a Score, a path or a content hash: names are read off the Item id
//! down to the part a person knows (a file name, a server name, a settings
//! key, a hook's event), never the locator itself. Sensitive values never
//! reach this module in the first place; the daemon redacts them.
//!
//! The technical table that **Show technical details** opens is here too,
//! because it is the same table for both Postures: the Simple Posture opens it
//! for one Finding, the Developer Posture shows it always.

use std::path::Path;

use agentsweep_core::finding::{Category, FindingState, RuleStatus, Severity, Tier};
use agentsweep_core::finding_facts::{HeuristicLine, WhyNothingHappened};
use agentsweep_core::item::Kind;
use agentsweep_core::pack::Bands;
use agentsweep_core::rules::PHRASE_ITEM;
use agentsweep_core::settings::Posture;
use agentsweep_core::state::RecordedFinding;
use serde_json::{Value, json};

use crate::findings::probation;
use crate::verdict::{Verdict, ai_block};

/// The colour of the Severity chip: red for a Threat, amber for an Exposure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chip {
    /// A Threat.
    Red,
    /// An Exposure.
    Amber,
}

impl Chip {
    /// The name the window styles the chip by.
    pub fn as_str(self) -> &'static str {
        match self {
            Chip::Red => "red",
            Chip::Amber => "amber",
        }
    }
}

/// Which line of the body a sentence is, in the order spec section 8.4 fixes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Part {
    /// The Rule's `plain` sentence.
    Plain,
    /// One fired Heuristic's `plain` line, one per Heuristic, shown as a list.
    Heuristic,
    /// The muted "Also noticed" line under a Probation Rule Finding.
    AlsoNoticed,
    /// The AI block of a malicious Verdict: "AI explanation, from <engine>"
    /// and the engine's contained reason ([`crate::verdict`]).
    Ai,
    /// Whether the Agent would use the Item.
    Activation,
    /// Why AgentSweep did not act by itself.
    WhyNothingHappened,
    /// That git will show the change in a project.
    Project,
    /// How the Item stands against its Baseline.
    Drift,
}

impl Part {
    /// The name the window renders the line by.
    pub fn as_str(self) -> &'static str {
        match self {
            Part::Plain => "plain",
            Part::Heuristic => "heuristic",
            Part::AlsoNoticed => "also",
            Part::Ai => "ai",
            Part::Activation => "activation",
            Part::WhyNothingHappened => "why",
            Part::Project => "project",
            Part::Drift => "drift",
        }
    }
}

/// One line of the body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Line {
    /// Which line it is.
    pub part: Part,
    /// What it says.
    pub text: String,
}

/// One Finding as the Simple Posture words it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wording {
    /// The verdict sentence about a named thing.
    pub title: String,
    /// Dangerous, Risky, Worth fixing or Tidy-up.
    pub severity: &'static str,
    /// Red for a Threat, amber for an Exposure.
    pub chip: Chip,
    /// The body, in the fixed order.
    pub lines: Vec<Line>,
    /// The message **Copy a message for your admin** puts on the clipboard,
    /// present on a Managed Finding only.
    pub admin_message: Option<String>,
}

impl Wording {
    /// Every string the Simple Posture shows for this Finding.
    pub fn strings(&self) -> Vec<&str> {
        let mut strings = vec![self.title.as_str(), self.severity];
        strings.extend(self.lines.iter().map(|line| line.text.as_str()));
        strings.extend(self.admin_message.as_deref());
        strings
    }

    /// The value the window receives.
    pub fn to_value(&self) -> Value {
        json!({
            "title": self.title,
            "severity": self.severity,
            "chip": self.chip.as_str(),
            "lines": lines_value(&self.lines),
            "admin": self.admin_message.is_some(),
        })
    }
}

/// The project line of spec section 8.4.
pub const PROJECT_LINE: &str =
    "This file belongs to a project, so git will show the change. Restore undoes it.";

/// The note on a Probation Rule Finding.
pub const WHY_PROBATION: &str = "The check that caught this is new and still proving itself, so \
     AgentSweep asks you instead of acting by itself.";

/// The note on a T2 or T3 Finding.
pub const WHY_HEURISTIC_OR_AI: &str = "AgentSweep only acts by itself when it is certain, and \
     signs like these can have innocent explanations.";

/// The note on a project's git settings, a never-auto kind.
pub const WHY_NEVER_AUTO_GIT: &str = "AgentSweep never edits a project's git settings by itself. \
     One click switches off the single line that would run the command; the rest of the file \
     stays as it is.";

/// The note on a project's env file, the other never-auto kind.
pub const WHY_NEVER_AUTO_ENV: &str = "AgentSweep never edits a project's env file by itself. One \
     click switches off the single line that would point the agent elsewhere; the rest of the \
     file stays as it is.";

/// The note on a Managed Item.
pub const WHY_MANAGED: &str = "This is controlled by whoever administers this Mac. AgentSweep \
     can see it but cannot change it. If you did not expect it, show them this message.";

/// The note on an Exposure.
pub const WHY_EXPOSURE: &str =
    "This is your own setup, not an attack, so AgentSweep never moves it.";

/// The Severity as the Simple Posture says it.
pub fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Dangerous",
        Severity::High => "Risky",
        Severity::Medium => "Worth fixing",
        Severity::Low => "Tidy-up",
    }
}

/// The Severity chip's colour.
pub fn chip(category: Category) -> Chip {
    match category {
        Category::Threat => Chip::Red,
        Category::Exposure => Chip::Amber,
    }
}

/// One Finding, worded for the Simple Posture.
pub fn simple(finding: &RecordedFinding) -> Wording {
    let named = Named::of(finding);
    Wording {
        title: title(finding, &named),
        severity: severity_word(finding.severity),
        chip: chip(finding.category),
        lines: body(finding, &named, Posture::Simple),
        admin_message: managed(finding).then(|| admin_message(finding, &named)),
    }
}

/// The body lines in the Developer Posture: the Simple Posture's, with the
/// model added to the AI block's label (spec section 8.4).
pub fn developer_lines(finding: &RecordedFinding) -> Vec<Line> {
    body(finding, &Named::of(finding), Posture::Developer)
}

/// Body lines as the window receives them.
pub fn lines_value(lines: &[Line]) -> Value {
    Value::Array(
        lines
            .iter()
            .map(|line| json!({ "part": line.part.as_str(), "text": line.text }))
            .collect(),
    )
}

/// The body in its fixed order (spec section 8.4); the Posture changes only
/// the AI block's label.
fn body(finding: &RecordedFinding, named: &Named, posture: Posture) -> Vec<Line> {
    let mut lines = Vec::new();
    let line = |part: Part, text: String| Line { part, text };

    let rated = finding.source.starts_with("score") || finding.tier == Tier::AiJudgement;
    if rated && !finding.facts.heuristics.is_empty() {
        lines.extend(
            finding
                .facts
                .heuristics
                .iter()
                .map(|heuristic| line(Part::Heuristic, heuristic.plain.clone())),
        );
    } else if finding.source != "keeps coming back" && !finding.plain.is_empty() {
        // The note of an Item that keeps coming back says all its own
        // sentence would.
        lines.push(line(Part::Plain, finding.plain.clone()));
    }
    if !rated
        && finding.tier == Tier::Rules
        && finding.status == RuleStatus::Probation
        && !finding.facts.heuristics.is_empty()
    {
        let noticed: Vec<&str> = finding
            .facts
            .heuristics
            .iter()
            .map(|heuristic| heuristic.plain.as_str())
            .collect();
        lines.push(line(
            Part::AlsoNoticed,
            format!("Also noticed: {}", noticed.join(" ")),
        ));
    }
    if let Some(text) = Verdict::of(finding).and_then(|verdict| ai_block(&verdict, posture)) {
        lines.push(line(Part::Ai, text));
    }
    if let Some(text) = activation(finding, named) {
        lines.push(line(Part::Activation, text));
    }
    if let Some(text) = why_nothing_happened(finding, named) {
        lines.push(line(Part::WhyNothingHappened, text));
    }
    if named.project {
        lines.push(line(Part::Project, PROJECT_LINE.to_string()));
    }
    if let Some(text) = drift_line(&finding.drift) {
        lines.push(line(Part::Drift, text));
    }
    lines
}

/// The message a user hands whoever administers their Mac about a Managed
/// Finding: what was flagged, where, and why, in the Rule's own sentence.
/// Names and sentences only; no value of the setting, which may be
/// sensitive, and nothing technical.
pub fn admin_message(finding: &RecordedFinding, named: &Named) -> String {
    let agent = named.agent.unwrap_or("an agent");
    let why = match finding.plain.is_empty() {
        true => String::new(),
        false => format!(" It says: \"{}\"", finding.plain),
    };
    format!(
        "Hello, AgentSweep, the checker for coding agents on my Mac, flagged {} in {agent}. It \
         comes from the settings this Mac is managed with, so AgentSweep cannot change it and I \
         cannot either.{why} Could you check whether it is meant to be there?",
        named.item(),
    )
}

/// True when the Finding is about a Managed Item.
fn managed(finding: &RecordedFinding) -> bool {
    finding.facts.scope == "managed" || finding.item_id.in_scope("managed")
}

/// What a Finding's title and sentences call its Item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Named {
    /// The Agent's name, absent for the workspace, which belongs to no Agent.
    pub agent: Option<&'static str>,
    /// What kind of thing it is, in words.
    pub noun: &'static str,
    /// The part of its id a person knows it by.
    pub name: String,
    /// The plugin it came with, empty unless it did.
    pub plugin: String,
    /// The project's folder name, for a project's git settings.
    pub project_name: String,
    /// True for a Project-scope Item.
    pub project: bool,
    /// Its kind.
    pub kind: Kind,
}

impl Named {
    /// How one Finding names its Item.
    pub fn of(finding: &RecordedFinding) -> Named {
        let project = match finding.facts.scope.as_str() {
            "" => finding.item_id.is_project(),
            scope => scope == "project",
        };
        let id = finding.item_id.as_str();
        Named {
            agent: match id.split('/').next() {
                Some("claude-code") => Some("Claude Code"),
                Some("codex") => Some("Codex"),
                _ => None,
            },
            noun: noun(finding.kind, project),
            name: name(finding.kind, id),
            plugin: match finding.kind {
                Kind::Plugin => String::new(),
                _ => finding.facts.plugin.clone(),
            },
            project_name: Path::new(&finding.facts.project_root)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            project,
            kind: finding.kind,
        }
    }

    /// The Item in the middle of a sentence: "the skill 'pdf-helper'".
    pub fn item(&self) -> String {
        if !self.plugin.is_empty() {
            return format!("the {} from the plugin '{}'", self.noun, self.plugin);
        }
        if self.kind == Kind::RepositoryMetadata && !self.project_name.is_empty() {
            return format!("the git settings of the project '{}'", self.project_name);
        }
        format!("the {} '{}'", self.noun, self.name)
    }

    /// The Item opening a sentence.
    fn item_first(&self) -> String {
        capitalised(&self.item())
    }

    /// The Agent in the middle of a sentence.
    fn agent_or(&self, otherwise: &'static str) -> &'static str {
        self.agent.unwrap_or(otherwise)
    }
}

/// What a kind is called in a sentence. An instruction file of a project is
/// "the project file", as spec section 8.4 calls it.
pub(crate) fn noun(kind: Kind, project: bool) -> &'static str {
    match kind {
        Kind::InstructionFile if project => "project file",
        Kind::InstructionFile => "instruction file",
        Kind::Skill => "skill",
        Kind::Plugin => "plugin",
        Kind::Marketplace => "marketplace",
        Kind::McpServer => "MCP server",
        Kind::Hook => "hook",
        Kind::SettingsEntry => "setting",
        Kind::ExecPolicy => "command policy",
        Kind::Subagent => "subagent",
        Kind::Workflow => "workflow",
        Kind::RepositoryMetadata => "git settings",
        Kind::EnvFile => "env file",
        Kind::Generic => "file",
    }
}

/// The part of an Item id a person knows the Item by, as the daemon names it
/// in an un-notified change too ([`agentsweep_ipc::notifications::item_name`]).
pub(crate) fn name(kind: Kind, id: &str) -> String {
    agentsweep_ipc::notifications::item_name(kind, id)
}

/// The title: a verdict sentence about a named thing, or a question for
/// Drift (spec section 8.4).
fn title(finding: &RecordedFinding, named: &Named) -> String {
    if finding.source == "drift" {
        return drift_title(finding, named);
    }
    if finding.state == FindingState::Stopped {
        return format!("Stopped: {}", named.item());
    }
    if finding.source == "keeps coming back" {
        return format!(
            "A {} {} keeps coming back",
            severity_word(finding.severity).to_lowercase(),
            named.noun
        );
    }
    if finding.source.starts_with("problem") {
        return format!("AgentSweep could not check {}", named.item());
    }
    if finding.tier == Tier::AiJudgement {
        return format!("{} looks malicious", named.item_first());
    }
    if finding.source.starts_with("score") {
        return format!(
            "{} shows several signs of being malicious",
            named.item_first()
        );
    }
    let phrase = finding.facts.phrase.as_str();
    match (phrase.is_empty(), phrase.contains(PHRASE_ITEM)) {
        (true, _) => format!("{} needs your attention", named.item_first()),
        (false, true) => capitalised(&phrase.replacen(PHRASE_ITEM, &named.item(), 1)),
        (false, false) => format!("{} {phrase}", named.item_first()),
    }
}

/// The question a Drift Finding asks, by what moved.
fn drift_title(finding: &RecordedFinding, named: &Named) -> String {
    let agent = named.agent_or("your agent");
    let name = &named.name;
    match (finding.facts.drift_change.as_str(), named.kind) {
        ("added", _) => format!(
            "A new {} '{name}' was added to {agent}. Was that you?",
            named.noun
        ),
        ("unreadable", _) => format!(
            "{} can no longer be read. Was that you?",
            named.item_first()
        ),
        (_, Kind::McpServer) => {
            format!("The command that starts the MCP server '{name}' changed. Was that you?")
        }
        (_, Kind::Hook) => format!("The command the hook '{name}' runs changed. Was that you?"),
        (_, Kind::Marketplace) => format!(
            "{} now fetches plugins for '{name}' from a different place. Was that you?",
            capitalised(agent)
        ),
        (_, Kind::Plugin) => format!("Files inside plugin '{name}' changed without an update"),
        _ => format!("{} changed. Was that you?", named.item_first()),
    }
}

/// The Activation sentence, one of three fixed cases: a quarantined Item, an
/// active one, and one planted in a project the Agent does not trust yet.
/// Any other Activation has no sentence.
fn activation(finding: &RecordedFinding, named: &Named) -> Option<String> {
    if finding.state == FindingState::Stopped {
        return Some(match named.agent {
            Some(agent) => {
                format!(
                    "It would have been used the next time you opened {agent}. It cannot be now."
                )
            }
            None => "It would have been used the next time an agent opened this project. It \
                     cannot be now."
                .to_string(),
        });
    }
    match (
        finding.facts.activation.as_str(),
        finding.facts.inactive_reason.as_str(),
    ) {
        ("active", _) => Some(format!(
            "{} would use this the next time you open {}.",
            named.agent_or("An agent"),
            match named.project {
                true => "this project",
                false => "it",
            }
        )),
        ("inactive", "untrusted_project") => Some(format!(
            "It is planted but dormant: {} has not been told to trust this project, so nothing \
             runs yet.",
            named.agent_or("no agent")
        )),
        _ => None,
    }
}

/// The one fixed note on why AgentSweep did not act by itself, while the
/// Finding still asks the user.
fn why_nothing_happened(finding: &RecordedFinding, named: &Named) -> Option<String> {
    if !finding.is_open() {
        return None;
    }
    Some(match finding.facts.why_nothing_happened? {
        WhyNothingHappened::Probation => WHY_PROBATION.to_string(),
        WhyNothingHappened::HeuristicOrAi => WHY_HEURISTIC_OR_AI.to_string(),
        WhyNothingHappened::NeverAuto => match named.kind {
            Kind::EnvFile => WHY_NEVER_AUTO_ENV.to_string(),
            _ => WHY_NEVER_AUTO_GIT.to_string(),
        },
        WhyNothingHappened::KeepsComingBack => format!(
            "AgentSweep removed it three times in the last hour and something put it back each \
             time, most likely an agent session that is still open. Close all {} windows, then \
             quarantine it once more.",
            named.agent_or("agent")
        ),
        WhyNothingHappened::Managed => WHY_MANAGED.to_string(),
        WhyNothingHappened::Exposure => WHY_EXPOSURE.to_string(),
    })
}

/// The Drift context line as a sentence: "Changed since your last Scan on
/// 2026-10-01." The reason a path stopped being readable is a technical
/// word and stays in the technical details.
fn drift_line(drift: &str) -> Option<String> {
    let line = match drift.rfind(" (") {
        Some(at) if drift.ends_with(')') => &drift[..at],
        _ => drift,
    };
    match line.trim() {
        "" => None,
        line => Some(format!("{}.", capitalised(line))),
    }
}

/// The text with its first letter in upper case.
pub(crate) fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The technical table of one Finding: what **Show technical details** opens
/// in the Simple Posture and what the Developer Posture shows always. Ids,
/// paths, hashes, Scores and the redacted excerpts belong here and only here.
pub fn technical(finding: &RecordedFinding) -> Vec<(String, String)> {
    let facts = &finding.facts;
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut row = |label: &str, value: String| {
        if !value.is_empty() {
            rows.push((label.to_string(), value));
        }
    };
    row("Item", finding.item_id.as_str().to_string());
    row("Kind", finding.kind.to_string());
    row("Finding", finding.id.as_str().to_string());
    row("Source", finding.source.clone());
    row("Tier", finding.tier.to_string());
    row("Category", finding.category.to_string());
    row("Severity", finding.severity.to_string());
    row("Rule status", probation(finding.status).to_string());
    row("State", finding.state.as_str().to_string());
    row("Scope", facts.scope.clone());
    row("Project", facts.project_root.clone());
    row(
        "Activation",
        match facts.inactive_reason.as_str() {
            "" => facts.activation.clone(),
            reason => format!("{} ({reason})", facts.activation),
        },
    );
    row("Provenance", facts.provenance.clone());
    row("Plugin", facts.plugin.clone());
    row("Path", facts.path.clone());
    row("File", finding.file.clone());
    row("Content hash", finding.content_hash.clone());
    row("Receipt", finding.receipt_id.clone());
    row(
        "Stopped by",
        facts
            .actor
            .map(|actor| actor.as_str().to_string())
            .unwrap_or_default(),
    );
    if finding.rule_id > 0 {
        row("Rule", format!("{:04}", finding.rule_id));
    }
    if facts.rule_withdrawn {
        row(
            "Rule withdrawn",
            "withdrawn from the Rule Pack in force".to_string(),
        );
    }
    row("Excerpt", facts.excerpt.clone());
    if facts.score > 0 {
        row("Score", facts.score.to_string());
    }
    row("Band", facts.band.clone());
    if let Some(bands) = facts.bands {
        row("Band thresholds", thresholds(bands));
    }
    for heuristic in &facts.heuristics {
        let (label, value) = heuristic_row(heuristic);
        row(&label, value);
    }
    row("Drift", finding.drift.clone());
    rows
}

/// The Band thresholds on one line, as the pack manifest sets them.
pub fn thresholds(bands: Bands) -> String {
    format!(
        "Ambiguous from {}, Suspicious from {}",
        bands.ambiguous_at, bands.suspicious_at
    )
}

/// One fired Heuristic as a row of a technical table: its id, its Weight
/// and the redacted excerpt.
pub fn heuristic_row(heuristic: &HeuristicLine) -> (String, String) {
    (
        format!("Heuristic {:04}", heuristic.id),
        match heuristic.excerpt.as_str() {
            "" => format!("weight {}", heuristic.weight),
            excerpt => format!("weight {} · {excerpt}", heuristic.weight),
        },
    )
}

/// The technical table as the window receives it.
pub fn technical_value(finding: &RecordedFinding) -> Value {
    rows_value(technical(finding))
}

/// Rows of a technical table as the window receives them.
pub fn rows_value(rows: Vec<(String, String)>) -> Value {
    Value::Array(
        rows.into_iter()
            .map(|(label, value)| json!({ "label": label, "value": value }))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::eventlog::Actor;

    use crate::findings::tests::recorded;

    const HASH: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    /// A Finding of a source on an Item, with the facts the daemon would
    /// send beside it filled for the Item's Scope.
    fn finding(item: &str, kind: Kind, source: &str, category: Category) -> RecordedFinding {
        let mut finding = recorded(item, kind, source, category, FindingState::Open);
        finding.content_hash = HASH.to_string();
        finding.facts.scope = match item.split('/').nth(1) {
            Some(scope) if scope.starts_with("project:") => "project".to_string(),
            Some(scope) => scope.to_string(),
            None => String::new(),
        };
        if finding.facts.scope == "project" {
            finding.facts.project_root = "/Users/me/code/vendor-sdk".to_string();
        }
        finding.facts.activation = "active".to_string();
        finding
    }

    fn heuristic(id: i64, plain: &str, excerpt: &str) -> HeuristicLine {
        HeuristicLine {
            id,
            weight: 2,
            plain: plain.to_string(),
            excerpt: excerpt.to_string(),
        }
    }

    const CLAUDE_MD: &str = "claude-code/project:/Users/me/code/acme/instruction-file/CLAUDE.md";
    const PDF_HELPER: &str = "claude-code/user/skill/~/.claude/skills/pdf-helper";
    const HOOK: &str = "claude-code/user/hook/~/.claude/settings.json#SessionStart//8e05d7c5d51f";
    const GITHUB: &str = "claude-code/user/mcp-server/~/.claude.json#github";
    const SHIPIT_SKILL: &str =
        "claude-code/user/skill/~/.claude/plugins/cache/community/shipit/2.4.0/skills/notes";
    const NOTES_SYNC: &str = "codex/user/mcp-server/~/.codex/config.toml#notes-sync";
    const MCP_X: &str = "claude-code/user/mcp-server/~/.claude.json#x";
    const MARKET_X: &str = "claude-code/user/marketplace/x";
    const PLUGIN_X: &str = "claude-code/user/plugin/X@community@1.2.0";
    const MANAGED: &str = "claude-code/managed/settings-entry/<root>/Library/Application \
         Support/ClaudeCode/managed-settings.json#/env/ANTHROPIC_BASE_URL";
    const GIT: &str = "workspace/project:/Users/me/code/vendor-sdk/repository-metadata/.git/config#core.fsmonitor";
    const ENV: &str = "workspace/project:/Users/me/code/vendor-sdk/env-file/.env";

    fn title_of(finding: &RecordedFinding) -> String {
        simple(finding).title
    }

    #[test]
    fn a_rule_finding_on_a_project_file_reads_as_its_phrase() {
        let mut planted = finding(
            CLAUDE_MD,
            Kind::InstructionFile,
            "rule 0003",
            Category::Threat,
        );
        planted.facts.phrase = "contains hidden instructions".to_string();
        assert_eq!(
            title_of(&planted),
            "The project file 'CLAUDE.md' contains hidden instructions"
        );
    }

    #[test]
    fn a_stopped_item_reads_as_stopped() {
        let mut stopped = finding(PDF_HELPER, Kind::Skill, "rule 0001", Category::Threat);
        stopped.state = FindingState::Stopped;
        stopped.facts.phrase = "downloads and runs hidden code".to_string();
        assert_eq!(title_of(&stopped), "Stopped: the skill 'pdf-helper'");
    }

    #[test]
    fn an_item_that_keeps_coming_back_says_so() {
        let mut back = finding(HOOK, Kind::Hook, "keeps coming back", Category::Threat);
        back.severity = Severity::Critical;
        assert_eq!(title_of(&back), "A dangerous hook keeps coming back");
    }

    #[test]
    fn a_phrase_with_a_place_for_the_item_puts_it_there() {
        let mut secret = finding(GITHUB, Kind::McpServer, "rule 0010", Category::Exposure);
        secret.facts.phrase = "A password is written out in {item}".to_string();
        assert_eq!(
            title_of(&secret),
            "A password is written out in the MCP server 'github'"
        );
    }

    #[test]
    fn a_suspicious_part_of_a_plugin_is_named_by_its_plugin() {
        let mut suspicious = finding(SHIPIT_SKILL, Kind::Skill, "score 5", Category::Threat);
        suspicious.facts.plugin = "shipit".to_string();
        assert_eq!(
            title_of(&suspicious),
            "The skill from the plugin 'shipit' shows several signs of being malicious"
        );
    }

    #[test]
    fn a_malicious_verdict_reads_as_looking_malicious() {
        let mut judged = finding(NOTES_SYNC, Kind::McpServer, "score 3", Category::Threat);
        judged.tier = Tier::AiJudgement;
        assert_eq!(
            title_of(&judged),
            "The MCP server 'notes-sync' looks malicious"
        );
    }

    fn drift(item: &str, kind: Kind, change: &str) -> RecordedFinding {
        let mut moved = finding(item, kind, "drift", Category::Threat);
        moved.tier = Tier::Heuristics;
        moved.facts.drift_change = change.to_string();
        moved
    }

    #[test]
    fn a_changed_mcp_server_asks_about_its_command() {
        assert_eq!(
            title_of(&drift(MCP_X, Kind::McpServer, "changed")),
            "The command that starts the MCP server 'x' changed. Was that you?"
        );
    }

    #[test]
    fn a_new_mcp_server_asks_whether_it_was_added_by_the_user() {
        assert_eq!(
            title_of(&drift(MCP_X, Kind::McpServer, "added")),
            "A new MCP server 'x' was added to Claude Code. Was that you?"
        );
    }

    #[test]
    fn a_moved_marketplace_asks_about_where_plugins_come_from() {
        assert_eq!(
            title_of(&drift(MARKET_X, Kind::Marketplace, "changed")),
            "Claude Code now fetches plugins for 'x' from a different place. Was that you?"
        );
    }

    #[test]
    fn a_plugin_changed_in_place_says_it_changed_without_an_update() {
        assert_eq!(
            title_of(&drift(PLUGIN_X, Kind::Plugin, "changed")),
            "Files inside plugin 'X' changed without an update"
        );
    }

    #[test]
    fn the_kin_of_the_drift_questions_name_what_moved() {
        assert_eq!(
            title_of(&drift(HOOK, Kind::Hook, "changed")),
            "The command the hook 'SessionStart' runs changed. Was that you?"
        );
        let setting =
            "claude-code/user/settings-entry/~/.claude/settings.json#/permissions/allow/0";
        assert_eq!(
            title_of(&drift(setting, Kind::SettingsEntry, "changed")),
            "The setting 'permissions.allow' changed. Was that you?"
        );
        assert_eq!(
            title_of(&drift(MCP_X, Kind::McpServer, "unreadable")),
            "The MCP server 'x' can no longer be read. Was that you?"
        );
    }

    #[test]
    fn severity_is_one_of_four_words_on_a_red_or_amber_chip() {
        let mut threat = finding(PDF_HELPER, Kind::Skill, "rule 0001", Category::Threat);
        for (severity, word) in [
            (Severity::Critical, "Dangerous"),
            (Severity::High, "Risky"),
            (Severity::Medium, "Worth fixing"),
            (Severity::Low, "Tidy-up"),
        ] {
            threat.severity = severity;
            assert_eq!(simple(&threat).severity, word);
        }
        assert_eq!(simple(&threat).chip, Chip::Red);
        let exposure = finding(GITHUB, Kind::McpServer, "rule 0010", Category::Exposure);
        assert_eq!(simple(&exposure).chip, Chip::Amber);
    }

    fn texts(wording: &Wording, part: Part) -> Vec<String> {
        wording
            .lines
            .iter()
            .filter(|line| line.part == part)
            .map(|line| line.text.clone())
            .collect()
    }

    #[test]
    fn the_body_keeps_the_fixed_order() {
        let mut probation = finding(
            CLAUDE_MD,
            Kind::InstructionFile,
            "rule 0003",
            Category::Threat,
        );
        probation.facts.why_nothing_happened = Some(WhyNothingHappened::Probation);
        probation.facts.heuristics = vec![
            heuristic(520, "It tells the agent to drop its instructions.", ""),
            heuristic(521, "It asks the agent to keep a secret.", ""),
        ];
        probation.drift = "changed since your last Scan on 2026-10-01".to_string();
        let wording = simple(&probation);
        let parts: Vec<Part> = wording.lines.iter().map(|line| line.part).collect();
        assert_eq!(
            parts,
            vec![
                Part::Plain,
                Part::AlsoNoticed,
                Part::Activation,
                Part::WhyNothingHappened,
                Part::Project,
                Part::Drift
            ]
        );
        assert_eq!(texts(&wording, Part::Plain), vec!["What rule 0003 saw."]);
        assert_eq!(
            texts(&wording, Part::AlsoNoticed),
            vec![
                "Also noticed: It tells the agent to drop its instructions. It asks the agent to \
                 keep a secret."
            ]
        );
        assert_eq!(
            texts(&wording, Part::Drift),
            vec!["Changed since your last Scan on 2026-10-01."]
        );

        let mut suspicious = finding(SHIPIT_SKILL, Kind::Skill, "score 5", Category::Threat);
        suspicious.facts.heuristics = probation.facts.heuristics.clone();
        let wording = simple(&suspicious);
        assert_eq!(
            texts(&wording, Part::Heuristic),
            vec![
                "It tells the agent to drop its instructions.",
                "It asks the agent to keep a secret."
            ],
            "a Suspicious Finding lists its Heuristics' lines instead of one sentence"
        );
        assert!(texts(&wording, Part::Plain).is_empty());
        assert!(texts(&wording, Part::AlsoNoticed).is_empty());
    }

    /// The Activation sentence of each case, and none where no case fits.
    #[test]
    fn each_activation_sentence_appears_for_its_case_only() {
        let sentence = |finding: &RecordedFinding| texts(&simple(finding), Part::Activation);

        let user = finding(PDF_HELPER, Kind::Skill, "rule 0001", Category::Threat);
        assert_eq!(
            sentence(&user),
            vec!["Claude Code would use this the next time you open it."]
        );

        let project = finding(
            CLAUDE_MD,
            Kind::InstructionFile,
            "rule 0003",
            Category::Threat,
        );
        assert_eq!(
            sentence(&project),
            vec!["Claude Code would use this the next time you open this project."]
        );

        let mut dormant = project.clone();
        dormant.facts.activation = "inactive".to_string();
        dormant.facts.inactive_reason = "untrusted_project".to_string();
        assert_eq!(
            sentence(&dormant),
            vec![
                "It is planted but dormant: Claude Code has not been told to trust this project, \
                 so nothing runs yet."
            ]
        );

        let mut stopped = user.clone();
        stopped.state = FindingState::Stopped;
        stopped.facts.activation = String::new();
        assert_eq!(
            sentence(&stopped),
            vec!["It would have been used the next time you opened Claude Code. It cannot be now."]
        );

        let mut disabled = user.clone();
        disabled.facts.activation = "inactive".to_string();
        disabled.facts.inactive_reason = "disabled".to_string();
        assert!(sentence(&disabled).is_empty(), "no fixed sentence for it");
        let mut unknown = user.clone();
        unknown.facts.activation = "unknown".to_string();
        assert!(sentence(&unknown).is_empty(), "no fixed sentence for it");
    }

    /// Each fixed note for its case, nothing for a Finding that fits none,
    /// and nothing once the Finding no longer asks the user.
    #[test]
    fn each_why_nothing_happened_note_appears_for_its_case_only() {
        let note = |finding: &RecordedFinding| texts(&simple(finding), Part::WhyNothingHappened);
        let cases: Vec<(RecordedFinding, WhyNothingHappened, String)> = vec![
            (
                finding(PDF_HELPER, Kind::Skill, "rule 0001", Category::Threat),
                WhyNothingHappened::Probation,
                WHY_PROBATION.to_string(),
            ),
            (
                finding(SHIPIT_SKILL, Kind::Skill, "score 5", Category::Threat),
                WhyNothingHappened::HeuristicOrAi,
                WHY_HEURISTIC_OR_AI.to_string(),
            ),
            (
                finding(GIT, Kind::RepositoryMetadata, "rule 0009", Category::Threat),
                WhyNothingHappened::NeverAuto,
                WHY_NEVER_AUTO_GIT.to_string(),
            ),
            (
                finding(ENV, Kind::EnvFile, "rule 0007", Category::Threat),
                WhyNothingHappened::NeverAuto,
                WHY_NEVER_AUTO_ENV.to_string(),
            ),
            (
                finding(HOOK, Kind::Hook, "keeps coming back", Category::Threat),
                WhyNothingHappened::KeepsComingBack,
                "AgentSweep removed it three times in the last hour and something put it back \
                 each time, most likely an agent session that is still open. Close all Claude \
                 Code windows, then quarantine it once more."
                    .to_string(),
            ),
            (
                finding(MANAGED, Kind::SettingsEntry, "rule 0567", Category::Threat),
                WhyNothingHappened::Managed,
                WHY_MANAGED.to_string(),
            ),
            (
                finding(GITHUB, Kind::McpServer, "rule 0010", Category::Exposure),
                WhyNothingHappened::Exposure,
                WHY_EXPOSURE.to_string(),
            ),
        ];
        let every_note: Vec<String> = cases.iter().map(|(_, _, text)| text.clone()).collect();
        for (mut case, why, text) in cases {
            case.facts.why_nothing_happened = Some(why);
            assert_eq!(note(&case), vec![text.clone()], "{why:?}");
            for other in every_note.iter().filter(|other| **other != text) {
                assert!(
                    !simple(&case).strings().contains(&other.as_str()),
                    "{why:?} carries another case's note"
                );
            }
            case.state = FindingState::Trusted;
            assert!(note(&case).is_empty(), "a decided Finding has no note");
        }
        let automatic = finding(PDF_HELPER, Kind::Skill, "rule 0001", Category::Threat);
        assert!(note(&automatic).is_empty(), "a Finding that fits no case");
    }

    #[test]
    fn only_a_project_finding_carries_the_git_line() {
        let project = finding(
            CLAUDE_MD,
            Kind::InstructionFile,
            "rule 0003",
            Category::Threat,
        );
        assert_eq!(texts(&simple(&project), Part::Project), vec![PROJECT_LINE]);
        let user = finding(PDF_HELPER, Kind::Skill, "rule 0001", Category::Threat);
        assert!(texts(&simple(&user), Part::Project).is_empty());
        assert!(!simple(&user).strings().contains(&PROJECT_LINE));
    }

    /// A Managed Finding whose evidence holds a secret, as a match on a
    /// sensitive field would before the daemon redacts it.
    fn managed() -> RecordedFinding {
        let mut managed = finding(MANAGED, Kind::SettingsEntry, "rule 0567", Category::Threat);
        managed.plain =
            "Settings your organisation controls send the agent's traffic to another server."
                .to_string();
        managed.facts.why_nothing_happened = Some(WhyNothingHappened::Managed);
        managed.facts.phrase =
            "sends traffic elsewhere or runs a command you cannot change".to_string();
        managed.facts.heuristics = vec![heuristic(567, "p", "sk-ant-api03-secretvalue")];
        managed
    }

    #[test]
    fn the_message_for_the_admin_names_the_item_and_why_and_no_value() {
        let managed = managed();
        let message = simple(&managed)
            .admin_message
            .expect("a Managed Finding has one");
        assert!(
            message.contains("the setting 'env.ANTHROPIC_BASE_URL'"),
            "{message}"
        );
        assert!(message.contains("Claude Code"), "{message}");
        assert!(message.contains(&managed.plain), "it says why: {message}");
        assert!(!message.contains("sk-ant"), "no value: {message}");
        assert!(!message.contains('/'), "no path: {message}");
        assert_eq!(simple(&managed).to_value()["admin"], true);
        assert_eq!(
            texts(&simple(&managed), Part::WhyNothingHappened),
            vec![WHY_MANAGED]
        );
    }

    #[test]
    fn only_a_managed_finding_offers_a_message_for_the_admin() {
        let mut others = vec![
            finding(PDF_HELPER, Kind::Skill, "rule 0001", Category::Threat),
            finding(
                CLAUDE_MD,
                Kind::InstructionFile,
                "rule 0003",
                Category::Threat,
            ),
            finding(GITHUB, Kind::McpServer, "rule 0010", Category::Exposure),
        ];
        others[0].facts.why_nothing_happened = Some(WhyNothingHappened::Probation);
        for other in &others {
            assert_eq!(simple(other).admin_message, None);
            assert_eq!(simple(other).to_value()["admin"], false);
        }
    }

    /// The technical table is the one Finding's own: its id, hash and
    /// excerpts, and nothing of another Finding.
    #[test]
    fn the_technical_table_is_the_findings_alone() {
        let mut suspicious = finding(SHIPIT_SKILL, Kind::Skill, "score 5", Category::Threat);
        suspicious.facts.score = 5;
        suspicious.facts.band = "Suspicious".to_string();
        suspicious.facts.heuristics = vec![heuristic(521, "p", "do not tell the user")];
        let other = finding(PDF_HELPER, Kind::Skill, "rule 0001", Category::Threat);

        let rows = technical(&suspicious);
        let value = |label: &str| {
            rows.iter()
                .find(|(name, _)| name == label)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(value("Item").as_deref(), Some(SHIPIT_SKILL));
        assert_eq!(value("Content hash").as_deref(), Some(HASH));
        assert_eq!(value("Score").as_deref(), Some("5"));
        assert_eq!(value("Band").as_deref(), Some("Suspicious"));
        assert_eq!(
            value("Heuristic 0521").as_deref(),
            Some("weight 2 · do not tell the user")
        );
        assert!(
            rows.iter()
                .all(|(_, value)| !value.contains(other.item_id.as_str())),
            "nothing of another Finding"
        );
        let card = crate::findings::card(&suspicious);
        assert_eq!(card["technical"], technical_value(&suspicious));
        assert_eq!(card["simple"], simple(&suspicious).to_value());
    }

    /// The technical table of a fixture Finding carries every field the
    /// Developer Posture names (spec section 8.2): the Item id, the path, the
    /// file inside a tree, the content hash, the Provenance, the Rule and
    /// Heuristic ids with their Weights, the Score and the Band thresholds,
    /// and the excerpts; a sensitive excerpt only as its hash.
    #[test]
    fn the_technical_table_carries_every_field_and_a_sensitive_excerpt_redacted() {
        const SECRET: &str = "sk-not-a-real-token-0000";
        let redacted = "sha256:0123456789ab";
        let mut probation = finding(PDF_HELPER, Kind::Skill, "rule 0001", Category::Threat);
        probation.file = "scripts/setup.sh".to_string();
        probation.facts.provenance = "manual".to_string();
        probation.facts.path = "/Users/me/.claude/skills/pdf-helper".to_string();
        probation.facts.excerpt = "curl -k https://paste.example.invalid/x".to_string();
        probation.facts.score = 5;
        probation.facts.band = "Suspicious".to_string();
        probation.facts.bands = Some(Bands::V1);
        probation.facts.heuristics = vec![
            heuristic(521, "p", "do not tell the user"),
            heuristic(534, "p", redacted),
        ];

        let rows = technical(&probation);
        let value = |label: &str| {
            rows.iter()
                .find(|(name, _)| name == label)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value("Item"), Some(PDF_HELPER));
        assert_eq!(value("Path"), Some("/Users/me/.claude/skills/pdf-helper"));
        assert_eq!(value("File"), Some("scripts/setup.sh"));
        assert_eq!(value("Content hash"), Some(HASH));
        assert_eq!(value("Provenance"), Some("manual"));
        assert_eq!(value("Rule"), Some("0001"));
        assert_eq!(
            value("Excerpt"),
            Some("curl -k https://paste.example.invalid/x")
        );
        assert_eq!(value("Score"), Some("5"));
        assert_eq!(
            value("Band thresholds"),
            Some("Ambiguous from 2, Suspicious from 4")
        );
        assert_eq!(
            value("Heuristic 0521"),
            Some("weight 2 · do not tell the user")
        );
        assert_eq!(
            value("Heuristic 0534"),
            Some("weight 2 · sha256:0123456789ab")
        );
        let serialised = technical_value(&probation).to_string();
        assert!(!serialised.contains(SECRET));
    }

    /// Every case a Finding can be in, on every kind and Scope.
    fn every_case() -> Vec<RecordedFinding> {
        let mut cases = Vec::new();
        let items = [
            (CLAUDE_MD, Kind::InstructionFile),
            (PDF_HELPER, Kind::Skill),
            (HOOK, Kind::Hook),
            (GITHUB, Kind::McpServer),
            (SHIPIT_SKILL, Kind::Skill),
            (NOTES_SYNC, Kind::McpServer),
            (MARKET_X, Kind::Marketplace),
            (PLUGIN_X, Kind::Plugin),
            (MANAGED, Kind::SettingsEntry),
            (GIT, Kind::RepositoryMetadata),
            (ENV, Kind::EnvFile),
            (
                "claude-code/user/settings-entry/~/.claude/settings.json#/permissions/allow/0",
                Kind::SettingsEntry,
            ),
            (
                "codex/user/exec-policy/~/.codex/rules/default.rules",
                Kind::ExecPolicy,
            ),
            (
                "claude-code/user/subagent/~/.claude/agents/reviewer.md",
                Kind::Subagent,
            ),
            (
                "claude-code/user/workflow/~/.claude/workflows/release.js",
                Kind::Workflow,
            ),
            (
                "instruction-file//Users/me/broken/CLAUDE.md",
                Kind::InstructionFile,
            ),
        ];
        let sources = [
            ("rule 0003", Category::Threat, Tier::Rules),
            ("rule 0010", Category::Exposure, Tier::Rules),
            ("score 13", Category::Threat, Tier::Heuristics),
            ("score 13", Category::Threat, Tier::AiJudgement),
            ("drift", Category::Threat, Tier::Heuristics),
            ("keeps coming back", Category::Threat, Tier::Rules),
            ("problem unreadable", Category::Exposure, Tier::Rules),
        ];
        for (item, kind) in items {
            for (source, category, tier) in sources {
                for state in [
                    FindingState::Open,
                    FindingState::Stopped,
                    FindingState::Trusted,
                ] {
                    for why in WhyNothingHappened::ALL.map(Some).into_iter().chain([None]) {
                        let mut case = finding(item, kind, source, category);
                        case.tier = tier;
                        case.state = state;
                        case.receipt_id = "q-0123456789abcdef0123456789abcdef".to_string();
                        case.file = "scripts/deploy.sh".to_string();
                        case.plain = "This file hides instructions to the agent.".to_string();
                        case.drift = "could not be read this time, and was readable on \
                                      2026-10-01 (unreadable)"
                            .to_string();
                        case.facts.why_nothing_happened = why;
                        case.facts.phrase = match source {
                            "rule 0010" => "A password is written out in {item}".to_string(),
                            _ => "contains hidden instructions".to_string(),
                        };
                        case.facts.plugin = match item {
                            SHIPIT_SKILL => "shipit".to_string(),
                            _ => String::new(),
                        };
                        case.facts.provenance = "repository".to_string();
                        case.facts.score = 13;
                        case.facts.band = "Suspicious".to_string();
                        case.facts.actor = Some(Actor::Auto);
                        case.facts.drift_change = "changed".to_string();
                        case.facts.heuristics =
                            vec![heuristic(521, "It asks the agent to keep a secret.", "x")];
                        cases.push(case.clone());
                        case.facts.activation = "inactive".to_string();
                        case.facts.inactive_reason = "untrusted_project".to_string();
                        cases.push(case);
                    }
                }
            }
        }
        cases
    }

    #[test]
    fn no_simple_string_holds_an_id_a_rule_number_a_score_a_path_or_a_hash() {
        let cases = every_case();
        assert!(cases.len() > 1000);
        for case in &cases {
            let wording = simple(case);
            for text in wording.strings() {
                let forbidden = [
                    case.item_id.as_str(),
                    case.id.as_str(),
                    case.content_hash.as_str(),
                    case.receipt_id.as_str(),
                    case.facts.project_root.as_str(),
                    case.file.as_str(),
                    "0003",
                    "0010",
                    "0521",
                    "rule ",
                    "13",
                    "/",
                    "~",
                    "#",
                    "@",
                    "unreadable)",
                    "8e05d7c5d51f",
                ];
                for needle in forbidden.iter().filter(|needle| !needle.is_empty()) {
                    assert!(
                        !text.contains(needle),
                        "`{text}` holds `{needle}` ({} {})",
                        case.item_id.as_str(),
                        case.source
                    );
                }
                assert!(!text.contains('\u{2014}'), "{text}");
            }
        }
    }
}
