//! The Activity pane (spec section 8.1): the Event Log as the window shows it.
//!
//! The lines are the daemon's: one per record of the Event Log, and the ones
//! its Scans left that no record stands behind, each already free of content
//! and of sensitive values. The app keeps them from the status and follows
//! the `activity` state event, so an open pane grows without being opened
//! again. The pane lists them newest first. In the Simple Posture a line is
//! its plain sentence and its moment; the Developer Posture adds the
//! record's action, Item id, content hash, Rule id and Receipt id beside it.
//! A line whose record an earlier key generation wrote carries the
//! unverified mark in both Postures (spec section 5.5).

use agentsweep_core::settings::Posture;
use agentsweep_ipc::protocol::{ActivityLine, StateEvent, Status};
use serde_json::{Value, json};

use crate::findings::Follow;

/// The mark a line carries when no key in hand can verify its record.
pub const UNVERIFIED: &str = "Unverified";

/// What the Developer Posture adds under the list: that a record of an
/// earlier key generation cannot rule out tampering (spec section 5.5).
pub const UNVERIFIED_NOTE: &str = "Records marked unverified were written before the protection \
     state was reset. No key in hand can check them, so they cannot rule out tampering.";

/// The Activity as the app keeps it, oldest first, as the daemon sends it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Activity {
    lines: Vec<ActivityLine>,
}

impl Activity {
    /// Takes every line from a status answer.
    pub fn load(&mut self, status: &Status) {
        self.lines = status.activity.clone();
    }

    /// No daemon answers: the pane shows nothing it cannot stand behind.
    pub fn clear(&mut self) {
        self.lines.clear();
    }

    /// Follows one `activity` event: a line not held yet is added and the
    /// pane is sent again; a line held already changes nothing. A daemon from
    /// before the columns sends the line alone, and the status is asked for
    /// what it carries.
    pub fn apply(&mut self, event: &StateEvent) -> Follow {
        let StateEvent::Activity { entry, .. } = event else {
            return Follow::Nothing;
        };
        let Some(entry) = entry else {
            return Follow::Refresh;
        };
        match self.lines.contains(entry) {
            true => Follow::Nothing,
            false => {
                self.lines.push((**entry).clone());
                Follow::Render
            }
        }
    }

    /// Every line held, oldest first.
    pub fn lines(&self) -> &[ActivityLine] {
        &self.lines
    }

    /// The pane in a Posture: newest first, each line with its moment and,
    /// in the Developer Posture only, its technical columns.
    pub fn view(&self, posture: Posture) -> Value {
        let developer = posture == Posture::Developer;
        let mut newest: Vec<&ActivityLine> = self.lines.iter().collect();
        newest.sort_by_key(|line| (line.recorded_at, line.sequence.unwrap_or(u64::MAX)));
        newest.reverse();
        let unverified = self.lines.iter().any(|line| !line.verified);
        json!({
            "lines": newest.into_iter().map(|line| row(line, developer)).collect::<Vec<_>>(),
            "empty": self.lines.is_empty(),
            "note": match developer && unverified {
                true => Value::from(UNVERIFIED_NOTE),
                false => Value::Null,
            },
        })
    }
}

/// One line as the pane renders it.
fn row(line: &ActivityLine, developer: bool) -> Value {
    json!({
        "line": line.line,
        "at": line.recorded_at.to_string(),
        "sequence": line.sequence,
        "mark": match line.verified {
            true => Value::Null,
            false => Value::from(UNVERIFIED),
        },
        "technical": match developer {
            true => technical(line),
            false => Value::Null,
        },
    })
}

/// The technical columns of one line, each absent where the record names
/// none.
fn technical(line: &ActivityLine) -> Value {
    let text = |value: &str| match value.is_empty() {
        true => Value::Null,
        false => Value::from(value),
    };
    json!({
        "action": text(&line.action),
        "actor": text(&line.actor),
        "itemId": text(&line.item_id),
        "contentHash": text(&line.content_hash),
        "ruleId": match line.rule_id {
            0 => Value::Null,
            id => Value::from(format!("{id:04}")),
        },
        "receiptId": text(&line.receipt_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::envelope::Timestamp;

    fn line(sequence: u64, at: &str, said: &str) -> ActivityLine {
        ActivityLine {
            sequence: Some(sequence),
            recorded_at: Timestamp::parse(at).expect("a moment"),
            line: said.to_string(),
            actor: "user".to_string(),
            action: "quarantine".to_string(),
            item_id: "claude-code/user/skill/~/.claude/skills/setup".to_string(),
            content_hash: "sha256:abc".to_string(),
            rule_id: 1,
            receipt_id: "r-1".to_string(),
            verified: true,
        }
    }

    fn status_with(lines: Vec<ActivityLine>) -> Status {
        let mut status = Status::unreachable("");
        status.activity = lines;
        status
    }

    fn said(view: &Value) -> Vec<&str> {
        view["lines"]
            .as_array()
            .expect("lines")
            .iter()
            .map(|row| row["line"].as_str().expect("a line"))
            .collect()
    }

    #[test]
    fn the_pane_lists_newest_first() {
        let mut activity = Activity::default();
        activity.load(&status_with(vec![
            line(1, "2026-10-01T08:00:00.000Z", "first"),
            line(2, "2026-10-02T08:00:00.000Z", "second"),
            ActivityLine {
                sequence: None,
                ..line(0, "2026-10-03T08:00:00.000Z", "a Scan's line")
            },
        ]));
        let view = activity.view(Posture::Simple);
        assert_eq!(said(&view), ["a Scan's line", "second", "first"]);
        assert_eq!(view["empty"], false);
        assert_eq!(view["lines"][1]["at"], "2026-10-02T08:00:00.000Z");
    }

    #[test]
    fn the_technical_columns_show_only_in_developer() {
        let mut activity = Activity::default();
        activity.load(&status_with(vec![line(4, "2026-10-01T08:00:00.000Z", "x")]));
        let simple = activity.view(Posture::Simple);
        assert!(simple["lines"][0]["technical"].is_null(), "{simple}");
        let developer = activity.view(Posture::Developer);
        let columns = &developer["lines"][0]["technical"];
        assert_eq!(columns["action"], "quarantine");
        assert_eq!(
            columns["itemId"],
            "claude-code/user/skill/~/.claude/skills/setup"
        );
        assert_eq!(columns["contentHash"], "sha256:abc");
        assert_eq!(columns["ruleId"], "0001");
        assert_eq!(columns["receiptId"], "r-1");
        assert_eq!(said(&simple), said(&developer), "the same sentence");
    }

    #[test]
    fn a_line_of_an_earlier_key_generation_is_marked_in_both_postures() {
        let mut activity = Activity::default();
        activity.load(&status_with(vec![
            ActivityLine {
                verified: false,
                ..line(1, "2026-10-01T08:00:00.000Z", "old")
            },
            line(2, "2026-10-02T08:00:00.000Z", "new"),
        ]));
        for posture in [Posture::Simple, Posture::Developer] {
            let view = activity.view(posture);
            assert!(view["lines"][0]["mark"].is_null(), "{view}");
            assert_eq!(view["lines"][1]["mark"], UNVERIFIED, "{view}");
        }
        assert!(activity.view(Posture::Simple)["note"].is_null());
        assert_eq!(activity.view(Posture::Developer)["note"], UNVERIFIED_NOTE);
    }

    #[test]
    fn the_pane_follows_the_stream_without_being_opened_again() {
        let mut activity = Activity::default();
        activity.load(&status_with(vec![line(
            1,
            "2026-10-01T08:00:00.000Z",
            "first",
        )]));
        let told = line(
            2,
            "2026-10-02T08:00:00.000Z",
            "You restored the skill 'setup'.",
        );
        let event = StateEvent::Activity {
            line: told.line.clone(),
            sequence: told.sequence,
            entry: Some(Box::new(told.clone())),
        };
        assert_eq!(activity.apply(&event), Follow::Render);
        assert_eq!(
            said(&activity.view(Posture::Simple))[0],
            "You restored the skill 'setup'."
        );
        assert_eq!(activity.apply(&event), Follow::Nothing, "held once");
        assert_eq!(activity.lines().len(), 2);

        let bare = StateEvent::Activity {
            line: "from a daemon before the columns".to_string(),
            sequence: Some(3),
            entry: None,
        };
        assert_eq!(activity.apply(&bare), Follow::Refresh);
    }
}
