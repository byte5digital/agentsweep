//! Uninstall on the wire (spec section 9.6): the one `uninstall` request,
//! which carries the user's choice about what is in Quarantine and nothing
//! else, and what the daemon answers it with.
//!
//! The Settings flow and the in-bundle `agentsweep uninstall` both send it,
//! with the same choice and the same default, [`UninstallChoice::Keep`], so
//! removing the app never silently loses a quarantined Item. The daemon takes
//! the Gate's entries and the Codex pin away from every Agent first, on every
//! choice, then applies the choice, since it is the only writer of the stores.
//! Unregistering the daemon and the login item and moving the app to the
//! Trash are the app's; the command line interface tells the user to move the
//! app to the Trash.

use serde_json::{Map, Value};

use crate::protocol::ActionReport;

/// What happens to what is in Quarantine when AgentSweep is removed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UninstallChoice {
    /// **Restore all N quarantined items**: every Receipt replayed as a
    /// single Restore would replay it, under its conflict rule (spec section
    /// 5.4), each outcome in the Event Log.
    RestoreAll,
    /// **Keep them in quarantine**, the default: the store, the Event Log and
    /// the data directory stay as they are, so a reinstall resumes them.
    #[default]
    Keep,
    /// **Delete everything**: everything AgentSweep made goes, the data
    /// directory with the quarantined payloads, the Keychain items, the log
    /// directory, the caches and the app's preferences.
    DeleteEverything,
}

impl UninstallChoice {
    /// Every choice, in the order they are offered.
    pub const ALL: [UninstallChoice; 3] = [
        UninstallChoice::RestoreAll,
        UninstallChoice::Keep,
        UninstallChoice::DeleteEverything,
    ];

    /// The spelling the wire carries.
    pub fn as_str(self) -> &'static str {
        match self {
            UninstallChoice::RestoreAll => "restore-all",
            UninstallChoice::Keep => "keep",
            UninstallChoice::DeleteEverything => "delete-everything",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<UninstallChoice> {
        UninstallChoice::ALL
            .into_iter()
            .find(|choice| choice.as_str() == text)
    }
}

/// What the daemon answers an `uninstall` request with.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UninstallReport {
    /// The choice it applied.
    pub choice: UninstallChoice,
    /// How many Gate entries it took away, across every Agent.
    pub gate_removed: usize,
    /// The Agents, by id, whose Gate entries could not be taken away.
    pub gate_failed: Vec<String>,
    /// For Restore all, one report per Receipt, as a single Restore answers.
    pub restored: Vec<ActionReport>,
    /// For Delete everything, what was deleted, in words: "the data
    /// directory", "the log directory" and so on. Never a value.
    pub deleted: Vec<String>,
    /// What could not be done, in words.
    pub failed: Vec<String>,
    /// The sentence a person reads first.
    pub message: String,
}

impl UninstallReport {
    /// The report as the wire carries it.
    pub fn to_value(&self) -> Value {
        let texts = |list: &[String]| {
            Value::Array(list.iter().map(|text| Value::from(text.as_str())).collect())
        };
        let mut map = Map::new();
        map.insert("choice".to_string(), Value::from(self.choice.as_str()));
        map.insert("deleted".to_string(), texts(&self.deleted));
        map.insert("failed".to_string(), texts(&self.failed));
        map.insert("gate_failed".to_string(), texts(&self.gate_failed));
        map.insert("gate_removed".to_string(), Value::from(self.gate_removed));
        map.insert("message".to_string(), Value::from(self.message.as_str()));
        map.insert(
            "restored".to_string(),
            Value::Array(self.restored.iter().map(ActionReport::to_value).collect()),
        );
        Value::Object(map)
    }

    /// Reads back what [`UninstallReport::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<UninstallReport> {
        let texts = |field: &str| -> Option<Vec<String>> {
            value
                .get(field)?
                .as_array()?
                .iter()
                .map(|text| text.as_str().map(str::to_string))
                .collect()
        };
        Some(UninstallReport {
            choice: UninstallChoice::parse(value.get("choice")?.as_str()?)?,
            gate_removed: usize::try_from(value.get("gate_removed")?.as_u64()?).ok()?,
            gate_failed: texts("gate_failed")?,
            restored: value
                .get("restored")?
                .as_array()?
                .iter()
                .map(ActionReport::from_value)
                .collect::<Option<Vec<_>>>()?,
            deleted: texts("deleted")?,
            failed: texts("failed")?,
            message: value.get("message")?.as_str()?.to_string(),
        })
    }

    /// True when everything the choice asked for was done.
    pub fn complete(&self) -> bool {
        self.gate_failed.is_empty()
            && self.failed.is_empty()
            && self
                .restored
                .iter()
                .all(|report| report.result == agentsweep_core::eventlog::Outcome::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_choice_is_spelled_and_read_back_and_keep_is_the_default() {
        for choice in UninstallChoice::ALL {
            assert_eq!(UninstallChoice::parse(choice.as_str()), Some(choice));
        }
        assert_eq!(UninstallChoice::parse("everything"), None);
        assert_eq!(UninstallChoice::default(), UninstallChoice::Keep);
    }

    #[test]
    fn the_report_survives_the_wire() {
        let report = UninstallReport {
            choice: UninstallChoice::DeleteEverything,
            gate_removed: 3,
            gate_failed: vec!["codex".to_string()],
            restored: Vec::new(),
            deleted: vec!["the data directory".to_string()],
            failed: vec!["the log directory".to_string()],
            message: "Deleted.".to_string(),
        };
        assert_eq!(
            UninstallReport::from_value(&report.to_value()),
            Some(report.clone())
        );
        assert!(!report.complete());
    }
}
