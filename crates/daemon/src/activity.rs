//! The Activity: the Event Log as a person reads it (spec section 8.1).
//!
//! Every record of the Event Log stands for one Activity line, or for several
//! when it is a change of the Rule Pack that withdrew Rules: the actions of
//! spec section 5.5, the chain restarts, the answers to an integrity state
//! and the `rule-pack` records. Beside them stand the lines a Scan leaves
//! that no record stands behind: a consistent plugin update (spec section
//! 4.6.5), content that changed back, and a Finding that went gone.
//!
//! A line names the Item, who did what to it and how it came out. It never
//! carries what the Item holds, and never a sensitive field, not even its
//! hash (spec section 5.5): the facts a record keeps under `sensitive` are
//! not read here at all, and of its other facts only the ones named below
//! (an Agent, an engine, a count) reach a line. The technical columns the
//! Developer Posture shows beside the line are the record's action, Item id,
//! content hash, Rule id and Receipt id. A record of an earlier key
//! generation, which no key in hand can verify, keeps its line and is marked
//! unverified.

use std::collections::BTreeSet;

use agentsweep_core::drift::Note;
use agentsweep_core::envelope::{ChainId, Timestamp};
use agentsweep_core::eventlog::{
    Action, Actor, Event, EventLogView, Outcome, RecordedEvent, RecordedIntegrity, RecordedRestart,
    RecordedRulePack,
};
use agentsweep_core::integrity::IntegrityRecord;
use agentsweep_core::item::{ItemId, Kind};
use agentsweep_core::state::RecordedFinding;
use agentsweep_ipc::protocol::ActivityLine;

/// Every line the Event Log stands for, in the order the records were
/// written.
pub fn of_the_event_log(view: &EventLogView) -> Vec<ActivityLine> {
    let mut lines: Vec<ActivityLine> = view.events.iter().map(of_event).collect();
    lines.extend(view.rule_packs.iter().flat_map(of_pack_change));
    lines.extend(view.chain_restarts.iter().map(of_restart));
    lines.extend(view.integrity.iter().map(of_integrity));
    lines.sort_by_key(|line| line.sequence);
    lines
}

/// The line one event stands for.
pub fn of_event(recorded: &RecordedEvent) -> ActivityLine {
    let event = &recorded.event;
    ActivityLine {
        sequence: Some(recorded.sequence),
        recorded_at: recorded.recorded_at,
        line: sentence(event),
        actor: event.actor.as_str().to_string(),
        action: event.action.as_str().to_string(),
        item_id: event
            .item_id
            .as_ref()
            .map(ItemId::to_string)
            .unwrap_or_default(),
        content_hash: event.content_hash.clone(),
        rule_id: event.rule_id,
        receipt_id: event.receipt_id.clone(),
        verified: recorded.verified,
    }
}

/// The lines one change of the Rule Pack stands for, all with the record's
/// sequence: which pack is in force and why, then what it withdrew and what
/// left Probation.
fn of_pack_change(recorded: &RecordedRulePack) -> Vec<ActivityLine> {
    recorded
        .record
        .activity()
        .into_iter()
        .map(|line| ActivityLine {
            sequence: Some(recorded.sequence),
            recorded_at: recorded.recorded_at,
            line,
            action: "rule-pack".to_string(),
            verified: recorded.verified,
            ..ActivityLine::default()
        })
        .collect()
}

/// The line a restart of the chain under a new key stands for.
fn of_restart(recorded: &RecordedRestart) -> ActivityLine {
    ActivityLine {
        sequence: Some(recorded.sequence),
        recorded_at: recorded.recorded_at,
        line: "AgentSweep's records started again under a new key. The records before \
               this cannot be checked."
            .to_string(),
        action: "chain-restart".to_string(),
        verified: recorded.verified,
        ..ActivityLine::default()
    }
}

/// The line the user's answer to an integrity state stands for.
fn of_integrity(recorded: &RecordedIntegrity) -> ActivityLine {
    let line = match &recorded.record {
        IntegrityRecord::KeyMissing => "You started a fresh record.".to_string(),
        IntegrityRecord::ChainBroken { chain, .. } => format!(
            "You chose to scan again, trusting nothing, after the {} was changed.",
            match chain {
                ChainId::Events => "Event Log",
                ChainId::Baseline => "Baseline",
            }
        ),
    };
    ActivityLine {
        sequence: Some(recorded.sequence),
        recorded_at: recorded.recorded_at,
        line,
        actor: Actor::User.as_str().to_string(),
        action: "integrity".to_string(),
        verified: recorded.verified,
        ..ActivityLine::default()
    }
}

/// The line a Scan leaves that no record stands behind: a consistent plugin
/// update, or content that changed back to what was accepted.
pub fn of_note(note: &Note, at: Timestamp) -> ActivityLine {
    ActivityLine {
        recorded_at: at,
        line: note.line.clone(),
        item_id: note.item_id.to_string(),
        ..ActivityLine::default()
    }
}

/// The line a Finding leaves when a Scan no longer derives it at all.
pub fn of_gone(finding: &RecordedFinding, at: Timestamp) -> ActivityLine {
    ActivityLine {
        recorded_at: at,
        line: format!(
            "The Finding on the {} is gone.",
            named(Some(finding.kind), finding.item_id.as_str())
        ),
        item_id: finding.item_id.to_string(),
        content_hash: finding.content_hash.clone(),
        rule_id: finding.rule_id,
        ..ActivityLine::default()
    }
}

/// The Activity a running daemon keeps: every line the Event Log stands for,
/// and the lines its own Scans left beside them.
#[derive(Clone, Debug, Default)]
pub struct Kept {
    lines: Vec<ActivityLine>,
    /// The sequences of the records whose lines are kept, so a record read
    /// again is never kept twice.
    followed: BTreeSet<u64>,
}

impl Kept {
    /// Keeps the lines of the records not kept yet, out of every line the
    /// Event Log stands for now, and answers with them in the order written.
    pub fn follow(&mut self, every: Vec<ActivityLine>) -> Vec<ActivityLine> {
        let new: Vec<ActivityLine> = every
            .into_iter()
            .filter(|line| line.sequence.is_some_and(|at| !self.followed.contains(&at)))
            .collect();
        self.followed
            .extend(new.iter().filter_map(|line| line.sequence));
        self.lines.extend(new.iter().cloned());
        new
    }

    /// Keeps one line no record stands behind.
    pub fn keep(&mut self, line: ActivityLine) {
        self.lines.push(line);
    }

    /// Every line kept, oldest first.
    pub fn lines(&self) -> Vec<ActivityLine> {
        let mut lines = self.lines.clone();
        lines.sort_by_key(|line| (line.recorded_at, line.sequence.unwrap_or(u64::MAX)));
        lines
    }
}

/// The name a person knows an Item by: the last part of its locator.
pub(crate) fn name_of(item_id: &str) -> &str {
    let locator = item_id.rsplit(['/', '#']).next().unwrap_or(item_id);
    if locator.is_empty() { item_id } else { locator }
}

/// An Item as a sentence names it: its kind in words, then its name.
pub(crate) fn named(kind: Option<Kind>, item_id: &str) -> String {
    match kind {
        Some(kind) => format!(
            "{} '{}'",
            kind.id_segment().replace('-', " "),
            name_of(item_id)
        ),
        None => format!("'{}'", name_of(item_id)),
    }
}

/// The Activity line one `purge` record stands for. It names the Item and the
/// Receipt, never what the Item held.
pub(crate) fn purge_line(kind: Option<Kind>, item_id: &str, receipt_id: &str) -> String {
    format!(
        "Deleted the {} from quarantine for good ({receipt_id}).",
        named(kind, item_id)
    )
}

/// The plain sentence one event stands for, with how it came out where it
/// did not go through.
fn sentence(event: &Event) -> String {
    let item = event
        .item_id
        .as_ref()
        .map(ItemId::as_str)
        .unwrap_or_default();
    let what = named(event.kind, item);
    let detail = |name: &str| event.detail.get(name).map(String::as_str).unwrap_or("");
    let line = match (event.action, event.actor) {
        (Action::Quarantine, Actor::Auto) => format!("AgentSweep stopped the {what}."),
        (Action::Quarantine, _) => format!("You quarantined the {what}."),
        (Action::Restore, _) => format!("You restored the {what}."),
        (Action::ReEnable, _) => format!("You switched the {what} back on (Re-enable)."),
        (Action::Trust, Actor::Restore) => {
            format!("This version of the {what} is trusted because you restored it.")
        }
        (Action::Trust, _) => format!("You trusted this version of the {what}."),
        (Action::Untrust, _) => format!("You withdrew Trust from a version of the {what}."),
        (Action::Purge, _) => purge_line(event.kind, item, &event.receipt_id),
        (Action::ReEnforce, _) => {
            format!("The {what} came back, and AgentSweep took it out again.")
        }
        (Action::Acknowledge, _) if event.item_id.is_none() => {
            "You said a change was your own.".to_string()
        }
        (Action::Acknowledge, _) => format!("You said the change to the {what} was your own."),
        (Action::EngineChanged, _) => {
            engine_line(detail("change"), detail("to_engine"), detail("from_engine"))
        }
        (Action::BaselineCompacted, _) => format!(
            "The Baseline was compacted: {} dropped.",
            records(detail("dropped"))
        ),
        (Action::VerdictsCompacted, _) => format!(
            "The Verdict cache was compacted: {} before, {} after.",
            records(detail("old_records")),
            detail("new_records").parse::<u64>().unwrap_or(0)
        ),
        (Action::GateRegistered, _) => {
            format!("The Gate was added to {}.", agent_name(detail("agent")))
        }
        (Action::GateRemoved, _) => {
            format!("The Gate was removed from {}.", agent_name(detail("agent")))
        }
    };
    match event.result {
        Outcome::Ok => line,
        Outcome::Skipped => format!("{line} Some steps were skipped."),
        Outcome::Failed => format!("{line} It did not go through."),
    }
}

/// A count of records, from the number a record carries as text.
fn records(count: &str) -> String {
    match count.parse::<u64>().unwrap_or(0) {
        1 => "1 record".to_string(),
        n => format!("{n} records"),
    }
}

/// The sentence one change of the Judgement Engine stands for. It names the
/// engines and nothing of a key.
fn engine_line(change: &str, to: &str, from: &str) -> String {
    match change {
        "enabled" => format!("The AI check was switched on, with {}.", engine_name(to)),
        "switched" => format!(
            "The AI check moved from {} to {}.",
            engine_name(from),
            engine_name(to)
        ),
        "disabled" => "The AI check was switched off.".to_string(),
        "key-added" => "A Claude API key was handed over for the AI check.".to_string(),
        "key-removed" => "The Claude API key was removed.".to_string(),
        _ => "The AI check was changed.".to_string(),
    }
}

/// A Judgement Engine as a sentence names it.
fn engine_name(engine: &str) -> &str {
    match engine {
        "apple" => "Apple on-device",
        "ollama" => "Ollama",
        "claude" => "the Claude API",
        other => other,
    }
}

/// An Agent as a sentence names it, from the adapter id a record carries.
fn agent_name(agent: &str) -> &str {
    match agent {
        "claude-code" => "Claude Code",
        "codex" => "Codex",
        "" => "an Agent",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::eventlog::{EventLog, EventLogWriter, ReceiptStep};
    use agentsweep_core::eventlog::{PackChange, Primitive, RulePackRecord};
    use agentsweep_core::finding::Tier;
    use agentsweep_core::item::Scope;
    use agentsweep_core::keychain::{KeySource, MemoryKeySource};
    use agentsweep_core::packs::PackOrigin;
    use tempfile::TempDir;

    /// A secret no line may ever carry, nor its hash.
    const SECRET: &str = "ghp-not-a-real-token-but-sensitive";
    /// Content no line may ever carry.
    const CONTENT: &str = "echo planted-content-of-the-item";

    fn item(locator: &str) -> ItemId {
        ItemId::new("claude-code", &Scope::User, Kind::McpServer, locator)
    }

    /// One event of every action of spec section 5.5, each about an MCP
    /// server whose environment holds a secret, with a step whose path and
    /// detail name the file but never its content.
    fn one_of_each() -> Vec<Event> {
        let about = |action: Action, actor: Actor| {
            let mut event = Event::new(action, actor)
                .about(
                    &item("~/.claude.json#tracker"),
                    Kind::McpServer,
                    "sha256:abc",
                )
                .because_of("finding-1", Tier::Rules, 3)
                .hiding("env.GITHUB_TOKEN", SECRET);
            event.receipt_id = "r-1".to_string();
            event
                .steps
                .push(ReceiptStep::new(Primitive::RemoveEntry, "~/.claude.json"));
            event
        };
        vec![
            about(Action::Quarantine, Actor::Auto),
            about(Action::Restore, Actor::User),
            about(Action::ReEnable, Actor::User),
            about(Action::Trust, Actor::Restore),
            about(Action::Untrust, Actor::User),
            about(Action::Purge, Actor::User),
            about(Action::ReEnforce, Actor::Auto),
            about(Action::Acknowledge, Actor::User),
            Event::new(Action::EngineChanged, Actor::User)
                .noting("change", "enabled")
                .noting("from_engine", "off")
                .noting("to_engine", "apple"),
            Event::new(Action::BaselineCompacted, Actor::Auto)
                .noting("old_head", "aa")
                .noting("new_head", "bb")
                .noting("dropped", "2"),
            Event::new(Action::VerdictsCompacted, Actor::Auto)
                .noting("old_records", "5")
                .noting("new_records", "3")
                .noting("hash", "cc"),
            Event::new(Action::GateRegistered, Actor::Auto)
                .about(
                    &item("~/.claude/settings.json#hooks"),
                    Kind::Hook,
                    "sha256:def",
                )
                .noting("agent", "claude-code"),
            Event::new(Action::GateRemoved, Actor::Auto)
                .about(&item("~/.codex/hooks.json#hooks"), Kind::Hook, "sha256:fed")
                .noting("agent", "codex"),
        ]
    }

    /// A fixture Event Log on a temporary data directory: one record of each
    /// action, a Rule Pack change, a restart under a new key and the answer
    /// to it.
    fn fixture_log() -> (TempDir, EventLogView) {
        let directory = TempDir::new().expect("a temporary directory");
        let log = EventLog::at(directory.path().join("events.jsonl"));
        let keys = MemoryKeySource::empty();
        {
            let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
            for event in one_of_each() {
                writer.append(&event).expect("an appended event");
            }
            let mut pack = RulePackRecord::new(
                PackChange::Accepted,
                3,
                "2026-10-01T00:00:00Z",
                PackOrigin::Fetched,
            );
            pack.withdrawn = vec![7];
            writer.record_rule_pack(&pack).expect("a pack change");
        }
        keys.forget().expect("the key goes away");
        {
            let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
            writer
                .record_integrity(&IntegrityRecord::KeyMissing)
                .expect("the answer");
        }
        let view = log.read(&keys).expect("a readable log");
        (directory, view)
    }

    #[test]
    fn every_record_of_the_event_log_yields_its_line_in_the_order_written() {
        let (_directory, view) = fixture_log();
        let lines = of_the_event_log(&view);
        let actions: Vec<&str> = lines.iter().map(|line| line.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "quarantine",
                "restore",
                "re-enable",
                "trust",
                "untrust",
                "purge",
                "re-enforce",
                "acknowledge",
                "engine-changed",
                "baseline-compacted",
                "verdicts-compacted",
                "gate-registered",
                "gate-removed",
                "rule-pack",
                "rule-pack",
                "chain-restart",
                "integrity",
            ]
        );
        let sequences: Vec<u64> = lines.iter().filter_map(|line| line.sequence).collect();
        assert_eq!(sequences.len(), lines.len(), "every line has its record");
        assert!(sequences.windows(2).all(|pair| pair[0] <= pair[1]));

        let said: Vec<&str> = lines.iter().map(|line| line.line.as_str()).collect();
        assert_eq!(said[0], "AgentSweep stopped the mcp server 'tracker'.");
        assert_eq!(said[1], "You restored the mcp server 'tracker'.");
        assert_eq!(
            said[3],
            "This version of the mcp server 'tracker' is trusted because you restored it."
        );
        assert_eq!(
            said[5],
            "Deleted the mcp server 'tracker' from quarantine for good (r-1)."
        );
        assert_eq!(
            said[8],
            "The AI check was switched on, with Apple on-device."
        );
        assert_eq!(said[9], "The Baseline was compacted: 2 records dropped.");
        assert_eq!(said[11], "The Gate was added to Claude Code.");
        assert_eq!(said[12], "The Gate was removed from Codex.");
        assert_eq!(
            said[13],
            "Rule Pack 3 (fetched) is in force, released 2026-10-01."
        );
        assert_eq!(said[14], "Rule 0007 was withdrawn by Rule Pack 3.");
        assert_eq!(said[16], "You started a fresh record.");

        let first = &lines[0];
        assert_eq!(first.actor, "auto");
        assert_eq!(
            first.item_id,
            "claude-code/user/mcp-server/~/.claude.json#tracker"
        );
        assert_eq!(first.content_hash, "sha256:abc");
        assert_eq!(first.rule_id, 3);
        assert_eq!(first.receipt_id, "r-1");
    }

    #[test]
    fn no_line_carries_a_sensitive_value_its_hash_or_any_content() {
        let (_directory, view) = fixture_log();
        let hash = agentsweep_core::eventlog::Redacted::of(SECRET);
        assert!(
            view.events.iter().any(|recorded| recorded
                .event
                .sensitive
                .values()
                .any(|held| *held == hash)),
            "the fixture records the secret's hash"
        );
        let digest = hash.as_str().trim_start_matches("sha256:").to_string();
        for line in of_the_event_log(&view) {
            let wire = line.to_value().to_string();
            assert!(!wire.contains(SECRET), "{wire}");
            assert!(!wire.contains(&digest), "no sensitive hash: {wire}");
            assert!(!wire.contains("GITHUB_TOKEN"), "no sensitive name: {wire}");
            assert!(!wire.contains(CONTENT), "{wire}");
        }
    }

    #[test]
    fn a_record_of_an_earlier_key_generation_is_marked_unverified() {
        let (_directory, view) = fixture_log();
        let lines = of_the_event_log(&view);
        let (before, after): (Vec<&ActivityLine>, Vec<&ActivityLine>) = lines
            .iter()
            .partition(|line| line.action != "chain-restart" && line.action != "integrity");
        assert!(before.iter().all(|line| !line.verified), "{before:?}");
        assert!(after.iter().all(|line| line.verified), "{after:?}");
    }

    #[test]
    fn a_record_read_again_is_kept_once() {
        let (_directory, view) = fixture_log();
        let mut kept = Kept::default();
        let all = of_the_event_log(&view);
        assert_eq!(kept.follow(all.clone()).len(), all.len());
        assert!(kept.follow(all.clone()).is_empty(), "nothing new");
        kept.keep(of_note(
            &Note {
                item_id: item("~/.claude/plugins/warp"),
                kind: Kind::Plugin,
                line: "Plugin warp updated".to_string(),
            },
            Timestamp::from_unix_ms(i64::MAX / 2),
        ));
        let lines = kept.lines();
        assert_eq!(lines.len(), all.len() + 1);
        assert_eq!(
            lines.last().map(|line| line.line.as_str()),
            Some("Plugin warp updated")
        );
    }

    #[test]
    fn a_failed_or_partial_action_says_so() {
        let mut event = Event::new(Action::Restore, Actor::User).about(
            &item("~/.claude.json#tracker"),
            Kind::McpServer,
            "sha256:abc",
        );
        event.result = Outcome::Skipped;
        assert_eq!(
            sentence(&event),
            "You restored the mcp server 'tracker'. Some steps were skipped."
        );
        event.result = Outcome::Failed;
        assert!(sentence(&event).ends_with("It did not go through."));
    }

    #[test]
    fn a_scan_line_has_no_record_behind_it() {
        let note = Note {
            item_id: item("~/.claude/plugins/warp"),
            kind: Kind::Plugin,
            line: "Plugin warp updated 1.2 to 1.3".to_string(),
        };
        let at = Timestamp::from_unix_ms(1_000);
        let line = of_note(&note, at);
        assert_eq!(line.sequence, None);
        assert_eq!(line.recorded_at, at);
        assert_eq!(line.line, "Plugin warp updated 1.2 to 1.3");
        assert!(line.verified);
    }
}
