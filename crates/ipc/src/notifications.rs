//! What the daemon has to tell and the application raises (spec sections 6.7
//! and 8.7).
//!
//! Only the application can notify; the daemon decides when there is
//! something to tell. It answers the `unnotified` request with every change
//! not yet told, each in one of the four notification classes or the
//! permission class, and the application answers with `notified` once it has
//! raised them, after which the daemon writes `notified_at` in the state file
//! so nothing fires twice, also across a restart.
//!
//! When there is something to tell and no application holds a subscription,
//! the daemon launches the application of its own bundle with
//! [`WINDOWLESS`], which the application reads as "start into the menu bar
//! with no window".

use serde_json::{Map, Value};

use agentsweep_core::eventlog::SessionsRunning;
use agentsweep_core::item::{ItemId, Kind};

/// The launch argument the application reads as "start into the menu bar
/// with no window" (spec section 6.7).
pub const WINDOWLESS: &str = "--windowless";

/// One of the four notification classes of spec section 8.7, or the
/// permission class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NotificationClass {
    /// AgentSweep quarantined an Item by itself: the notification names the
    /// Item, says whether Agent sessions were open and asks for a restart.
    StoppedAutomatically,
    /// Nothing was changed; the user is asked to open AgentSweep and decide.
    NeedsYou,
    /// An Item AgentSweep took out came back a third time within the hour.
    KeepsComingBack,
    /// One of AgentSweep's own chains was changed by something else.
    RecordsChanged,
    /// "AgentSweep can't check N projects yet."
    Permission,
}

impl NotificationClass {
    /// Every class, in the order spec section 8.7 lists them.
    pub const ALL: [NotificationClass; 5] = [
        NotificationClass::StoppedAutomatically,
        NotificationClass::NeedsYou,
        NotificationClass::KeepsComingBack,
        NotificationClass::RecordsChanged,
        NotificationClass::Permission,
    ];

    /// The spelling the wire carries.
    pub fn as_str(self) -> &'static str {
        match self {
            NotificationClass::StoppedAutomatically => "stopped-automatically",
            NotificationClass::NeedsYou => "needs-you",
            NotificationClass::KeepsComingBack => "keeps-coming-back",
            NotificationClass::RecordsChanged => "records-changed",
            NotificationClass::Permission => "permission",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<NotificationClass> {
        NotificationClass::ALL
            .into_iter()
            .find(|class| class.as_str() == text)
    }
}

/// One change the user has not been told about yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unnotified {
    /// What the application confirms with `notified`: a Finding id for the
    /// three classes about a Finding, an opaque id otherwise.
    pub id: String,
    /// Which notification it is.
    pub class: NotificationClass,
    /// The Item the Finding is about, absent for the records and permission
    /// classes.
    pub item_id: Option<ItemId>,
    /// That Item's kind, absent beside an absent Item.
    pub kind: Option<Kind>,
    /// The name a person knows the Item by ([`item_name`]), empty beside an
    /// absent Item.
    pub name: String,
    /// Whether Agent sessions appeared to be running when AgentSweep stopped
    /// the Item, as its Event Log record says. Unknown for every class but
    /// stopped automatically.
    pub sessions: SessionsRunning,
    /// How many projects cannot be checked yet, for the permission class;
    /// zero for every other.
    pub count: usize,
}

impl Unnotified {
    /// The change as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("class".to_string(), Value::from(self.class.as_str()));
        map.insert("count".to_string(), Value::from(self.count as u64));
        map.insert("id".to_string(), Value::from(self.id.as_str()));
        map.insert(
            "item_id".to_string(),
            Value::from(
                self.item_id
                    .as_ref()
                    .map(ItemId::as_str)
                    .unwrap_or_default(),
            ),
        );
        map.insert(
            "kind".to_string(),
            Value::from(self.kind.map(Kind::as_str).unwrap_or_default()),
        );
        map.insert("name".to_string(), Value::from(self.name.as_str()));
        map.insert("sessions".to_string(), Value::from(self.sessions.as_str()));
        Value::Object(map)
    }

    /// Reads back what [`Unnotified::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<Unnotified> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        Some(Unnotified {
            id: text("id")?.to_string(),
            class: NotificationClass::parse(text("class")?)?,
            item_id: match text("item_id")? {
                "" => None,
                id => Some(ItemId::from_recorded(id)),
            },
            kind: match text("kind")? {
                "" => None,
                kind => Some(Kind::parse(kind)?),
            },
            name: text("name")?.to_string(),
            sessions: SessionsRunning::parse(text("sessions")?)?,
            count: value.get("count")?.as_u64()? as usize,
        })
    }
}

/// The answer to `unnotified`: every change not yet told, as a list under
/// `changes`.
pub fn changes_to_value(changes: &[Unnotified]) -> Value {
    let mut map = Map::new();
    map.insert(
        "changes".to_string(),
        Value::Array(changes.iter().map(Unnotified::to_value).collect()),
    );
    Value::Object(map)
}

/// Reads back what [`changes_to_value`] wrote.
pub fn changes_from_value(value: &Value) -> Option<Vec<Unnotified>> {
    value
        .get("changes")?
        .as_array()?
        .iter()
        .map(Unnotified::from_value)
        .collect()
}

/// The part of an Item id a person knows the Item by. A hook is named by the
/// event it runs on, because the rest of its locator is a hash; a settings
/// entry by its key without array positions; a plugin by its name without
/// marketplace or version; everything else by the last part of its locator.
/// No name holds a slash.
pub fn item_name(kind: Kind, id: &str) -> String {
    let locator = id.rsplit_once('#').map(|(_, after)| after);
    let named = match (kind, locator) {
        (Kind::Hook, Some(entry)) => entry.split('/').next().unwrap_or_default().to_string(),
        (Kind::SettingsEntry, Some(pointer)) => pointer
            .split('/')
            .filter(|segment| !segment.is_empty() && !segment.bytes().all(|b| b.is_ascii_digit()))
            .collect::<Vec<_>>()
            .join("."),
        (Kind::Plugin, _) => last_part(id)
            .split('@')
            .next()
            .unwrap_or_default()
            .to_string(),
        _ => last_part(id).to_string(),
    };
    match named.is_empty() {
        true => last_part(id).replace('/', " "),
        false => named.replace('/', " "),
    }
}

/// The last part of an Item id's locator.
fn last_part(item_id: &str) -> &str {
    let locator = item_id.rsplit(['/', '#']).next().unwrap_or(item_id);
    if locator.is_empty() { item_id } else { locator }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_reads_back_its_spelling() {
        for class in NotificationClass::ALL {
            assert_eq!(NotificationClass::parse(class.as_str()), Some(class));
        }
        assert_eq!(NotificationClass::parse("ambiguous"), None);
    }

    #[test]
    fn a_change_crosses_the_wire_and_back() {
        let changes = vec![
            Unnotified {
                id: "claude-code/user/skill/skills/setup|rule/0001|abc".to_string(),
                class: NotificationClass::StoppedAutomatically,
                item_id: Some(ItemId::from_recorded("claude-code/user/skill/skills/setup")),
                kind: Some(Kind::Skill),
                name: "setup".to_string(),
                sessions: SessionsRunning::Yes,
                count: 0,
            },
            Unnotified {
                id: "permission/2/0123456789ab".to_string(),
                class: NotificationClass::Permission,
                item_id: None,
                kind: None,
                name: String::new(),
                sessions: SessionsRunning::Unknown,
                count: 2,
            },
        ];
        let wire = changes_to_value(&changes);
        assert_eq!(changes_from_value(&wire), Some(changes));
        assert_eq!(changes_from_value(&serde_json::json!({})), None);
    }

    #[test]
    fn an_item_is_named_the_way_a_person_knows_it() {
        assert_eq!(
            item_name(Kind::Skill, "claude-code/user/skill/skills/setup"),
            "setup"
        );
        assert_eq!(
            item_name(
                Kind::Plugin,
                "claude-code/user/plugin/plugin/warp@claude-code-warp"
            ),
            "warp"
        );
        assert_eq!(
            item_name(
                Kind::SettingsEntry,
                "claude-code/user/settings/settings.json#/permissions/allow/0"
            ),
            "permissions.allow"
        );
        assert_eq!(
            item_name(
                Kind::Hook,
                "claude-code/user/hook/settings.json#PreToolUse/0/1"
            ),
            "PreToolUse"
        );
    }
}
