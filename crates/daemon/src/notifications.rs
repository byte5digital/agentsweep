//! The daemon's half of the notifications (spec sections 6.7 and 8.7).
//!
//! Only the application can notify; the daemon decides when there is
//! something to tell. Every Finding change not yet told falls in one of the
//! four classes or in none, by the Finding's state and never by its Tier:
//!
//! - **stopped automatically**: a Finding AgentSweep stopped by itself, with
//!   whether Agent sessions appeared to be running when it did, as the
//!   Quarantine's Event Log record says;
//! - **keeps coming back**: the open Finding of an Item AgentSweep took out
//!   that came back a third time within the hour;
//! - **needs you**: every other open Threat Finding, whatever raised it: a
//!   Rule on Probation, a Score in the Suspicious Band, a Drift question, a
//!   late malicious Verdict;
//! - nothing for an Exposure, a Finding the user decided, a gone one, and for
//!   what raises no Finding at all: the Ambiguous Band, a benign or unsure
//!   Verdict, a daily Scan that found nothing new.
//!
//! Beside the Findings stand two notifications about something else: records
//! changed, for a chain that broke, and the permission class, for a project
//! that Needs Permission and was not covered by the last such notification.
//!
//! The application asks for what is un-notified and confirms what it raised;
//! the daemon then writes `notified_at` (or, for the two others, what it told)
//! into the state file, so nothing fires twice, also across a restart. A
//! Finding whose state moves is a change of its own: a Finding that was told
//! as "needs you" and is then stopped by a Rule leaving Probation is told
//! again, as stopped automatically.
//!
//! When there is something to tell and no application holds a subscription,
//! the daemon launches the application of its own bundle, windowless, through
//! the [`Launcher`] seam, at most once per change set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentsweep_core::chain::ChainState;
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::eventlog::{Action, Actor, EventLog, SessionsRunning};
use agentsweep_core::finding::{Category, FindingState, Source};
use agentsweep_core::health::Health;
use agentsweep_core::item::sha256_hex;
use agentsweep_core::overview::{Overview, ProjectCheck};
use agentsweep_core::state::{RecordedFinding, State};
use agentsweep_ipc::notifications::{NotificationClass, Unnotified, WINDOWLESS, item_name};

use crate::service::Daemon;

/// Starts an application. The seam the suite hands a fake through, so no
/// test ever launches anything.
pub trait Launcher: Send + Sync {
    /// Starts the application at `app` with these launch arguments, without
    /// bringing it to the front.
    fn launch(&self, app: &Path, arguments: &[&str]);
}

/// The application the daemon launches and what launches it: the daemon's
/// own bundle and never anything else.
#[derive(Clone)]
pub struct Launch {
    /// What starts it.
    pub launcher: Arc<dyn Launcher>,
    /// The `.app` directory the daemon sits in.
    pub app: PathBuf,
}

impl std::fmt::Debug for Launch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Launch")
            .field("app", &self.app)
            .finish_non_exhaustive()
    }
}

impl Launch {
    /// The installed daemon's: its own bundle, launched through
    /// LaunchServices. Nothing when the daemon does not run out of a bundle.
    pub fn of_this_bundle() -> Option<Launch> {
        crate::bundle_watch::Own::this_process().map(|own| Launch {
            launcher: Arc::new(LaunchServices),
            app: own.bundle,
        })
    }
}

/// LaunchServices, through `NSWorkspace`, with activation off: the
/// application starts into the menu bar and takes no focus.
#[derive(Clone, Copy, Debug, Default)]
pub struct LaunchServices;

impl Launcher for LaunchServices {
    #[cfg(target_os = "macos")]
    fn launch(&self, app: &Path, arguments: &[&str]) {
        use objc2_app_kit::{NSWorkspace, NSWorkspaceOpenConfiguration};
        use objc2_foundation::{NSArray, NSString, NSURL};

        let Some(path) = app.to_str() else {
            return;
        };
        let url = NSURL::fileURLWithPath(&NSString::from_str(path));
        let configuration = NSWorkspaceOpenConfiguration::configuration();
        configuration.setActivates(false);
        configuration.setAddsToRecentItems(false);
        configuration.setPromptsUserIfNeeded(false);
        let arguments: Vec<_> = arguments
            .iter()
            .map(|argument| NSString::from_str(argument))
            .collect();
        configuration.setArguments(&NSArray::from_retained_slice(&arguments));
        NSWorkspace::sharedWorkspace().openApplicationAtURL_configuration_completionHandler(
            &url,
            &configuration,
            None,
        );
    }

    #[cfg(not(target_os = "macos"))]
    fn launch(&self, _app: &Path, _arguments: &[&str]) {}
}

/// The notification class one Finding falls in as it stands, or none.
pub fn class_of(finding: &RecordedFinding) -> Option<NotificationClass> {
    match finding.state {
        FindingState::Stopped => (finding.facts.actor == Some(Actor::Auto))
            .then_some(NotificationClass::StoppedAutomatically),
        FindingState::Open if finding.category == Category::Threat => {
            match finding.source == Source::KeepsComingBack.to_string() {
                true => Some(NotificationClass::KeepsComingBack),
                false => Some(NotificationClass::NeedsYou),
            }
        }
        _ => None,
    }
}

/// The id of the "records changed" notification for the chains as Health
/// shows them: every broken chain and where it broke. None while no chain is
/// broken.
fn records_id(health: &Health) -> Option<String> {
    let broken: Vec<String> = [("events", &health.events), ("baseline", &health.baseline)]
        .into_iter()
        .filter_map(|(chain, state)| match state {
            ChainState::Broken { sequence, .. } => Some(format!("{chain}@{sequence}")),
            _ => None,
        })
        .collect();
    (!broken.is_empty()).then(|| format!("records/{}", broken.join(",")))
}

/// The project roots that Need Permission.
fn needing_permission(overview: &Overview) -> BTreeSet<String> {
    overview
        .projects
        .iter()
        .filter(|project| project.check == ProjectCheck::NeedsPermission)
        .map(|project| project.root.clone())
        .collect()
}

/// The id of the permission notification for these roots. It names how many
/// and a digest of which, never a path: the closed vocabulary carries no path
/// on this request (ADR 0008).
fn permission_id(roots: &BTreeSet<String>) -> String {
    let joined: Vec<&str> = roots.iter().map(String::as_str).collect();
    let digest = sha256_hex(joined.join("\n").as_bytes());
    format!("permission/{}/{}", roots.len(), &digest[..12])
}

/// Every change not yet told, Findings first in the order the state holds
/// them, then records changed, then the permission class. `sessions` answers
/// for a Receipt whether Agent sessions appeared to be running when it was
/// written.
pub fn unnotified(
    state: &State,
    health: &Health,
    sessions: &dyn Fn(&str) -> SessionsRunning,
) -> Vec<Unnotified> {
    let mut changes: Vec<Unnotified> = state
        .findings
        .iter()
        .filter(|finding| finding.notified_at.is_none())
        .filter_map(|finding| {
            let class = class_of(finding)?;
            Some(Unnotified {
                id: finding.id.as_str().to_string(),
                class,
                item_id: Some(finding.item_id.clone()),
                kind: Some(finding.kind),
                name: item_name(finding.kind, finding.item_id.as_str()),
                sessions: match class {
                    NotificationClass::StoppedAutomatically => sessions(&finding.receipt_id),
                    _ => SessionsRunning::Unknown,
                },
                count: 0,
            })
        })
        .collect();
    if let Some(id) = records_id(health).filter(|id| !state.told.records.contains(id)) {
        changes.push(told_about(id, NotificationClass::RecordsChanged, 0));
    }
    let roots = needing_permission(&state.overview);
    if !roots.is_subset(&state.told.permission) {
        changes.push(told_about(
            permission_id(&roots),
            NotificationClass::Permission,
            roots.len(),
        ));
    }
    changes
}

/// A change about something other than a Finding.
fn told_about(id: String, class: NotificationClass, count: usize) -> Unnotified {
    Unnotified {
        id,
        class,
        item_id: None,
        kind: None,
        name: String::new(),
        sessions: SessionsRunning::Unknown,
        count,
    }
}

impl Daemon {
    /// Every change the user has not been told about yet, with whether Agent
    /// sessions appeared to be running for each Item AgentSweep stopped by
    /// itself. Writes nothing.
    pub fn unnotified(&self) -> Vec<Unnotified> {
        // What the Quarantine records say about sessions, by Receipt. A log
        // that cannot be read says nothing, which reads as unknown.
        let sessions: BTreeMap<String, SessionsRunning> =
            match EventLog::in_data_directory(&self.directory).read(&*self.keys) {
                Ok(view) => view
                    .events
                    .iter()
                    .filter(|recorded| recorded.event.action == Action::Quarantine)
                    .map(|recorded| {
                        (
                            recorded.event.receipt_id.clone(),
                            recorded.event.sessions_running,
                        )
                    })
                    .collect(),
                Err(error) => {
                    say!("the Event Log could not be read for the sessions: {error}");
                    BTreeMap::new()
                }
            };
        let state = self.state.lock().expect("the state is not poisoned");
        let health = self.health();
        unnotified(&state, &health, &|receipt| {
            sessions.get(receipt).copied().unwrap_or_default()
        })
    }

    /// The application raised these changes. Each Finding among them gets
    /// its `notified_at`, records changed and the permission class are
    /// remembered as told, and the state file is written. An id that names
    /// nothing un-notified any more is passed over. Answers with how many
    /// were taken.
    pub fn notified(&self, ids: &[String]) -> usize {
        let ids: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
        let at = Timestamp::now();
        let mut state = self.state.lock().expect("the state is not poisoned");
        let health = self.health();
        let mut taken = 0;
        for finding in state.findings.iter_mut() {
            if finding.notified_at.is_none() && ids.contains(finding.id.as_str()) {
                finding.notified_at = Some(at);
                taken += 1;
            }
        }
        if let Some(id) = records_id(&health).filter(|id| ids.contains(id.as_str())) {
            state.told.records = BTreeSet::from([id]);
            taken += 1;
        }
        let roots = needing_permission(&state.overview);
        if !roots.is_empty() && ids.contains(permission_id(&roots).as_str()) {
            state.told.permission = roots;
            taken += 1;
        }
        if taken > 0 {
            self.write_state(&state);
        }
        taken
    }

    /// Launches the application windowless when there is something to tell
    /// and no application holds a subscription: once per change set, and
    /// only the application of the daemon's own bundle.
    pub(crate) fn launch_when_unnotified(&self) {
        let Some(launch) = self.launch.as_ref() else {
            return;
        };
        let ids: BTreeSet<String> = {
            let state = self.state.lock().expect("the state is not poisoned");
            let health = self.health();
            unnotified(&state, &health, &|_| SessionsRunning::Unknown)
                .into_iter()
                .map(|change| change.id)
                .collect()
        };
        if ids.is_empty() || self.app_subscribed() {
            return;
        }
        {
            let mut launched = self
                .launched
                .lock()
                .expect("the launched set is not poisoned");
            if ids.is_subset(&launched) {
                return;
            }
            *launched = ids.clone();
        }
        say!(
            "launching the app windowless for {} un-notified changes",
            ids.len()
        );
        launch.launcher.launch(&launch.app, &[WINDOWLESS]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::finding::{Finding, FindingId, RuleStatus, Severity, Standing, Tier};
    use agentsweep_core::item::{ItemId, Kind, Scope};
    use agentsweep_core::overview::ProjectRecord;

    fn moment() -> Timestamp {
        Timestamp::parse("2026-10-16T08:00:00.000Z").expect("a moment")
    }

    fn finding(source: Source, category: Category, state: FindingState) -> RecordedFinding {
        let item_id = ItemId::new("claude-code", &Scope::User, Kind::Skill, "skills/setup");
        let finding = Finding {
            item_id,
            source,
            content_hash: "abc".to_string(),
            category,
            severity: Severity::Critical,
            tier: Tier::Rules,
            status: RuleStatus::Probation,
            title: String::new(),
            plain: String::new(),
            sensitive: false,
            file: String::new(),
            matches: Vec::new(),
            heuristics: Vec::new(),
            drift: None,
        };
        let standing = Standing {
            id: FindingId::of(&finding),
            finding,
            state,
            receipt_id: match state {
                FindingState::Stopped => "q-1".to_string(),
                _ => String::new(),
            },
        };
        RecordedFinding::of(&standing, moment())
    }

    fn healthy() -> Health {
        Health::default()
    }

    #[test]
    fn each_finding_falls_in_its_class_by_its_state() {
        let mut stopped = finding(Source::Rule(1), Category::Threat, FindingState::Stopped);
        stopped.facts.actor = Some(Actor::Auto);
        assert_eq!(
            class_of(&stopped),
            Some(NotificationClass::StoppedAutomatically)
        );
        stopped.facts.actor = Some(Actor::User);
        assert_eq!(class_of(&stopped), None, "the user stopped it");

        for source in [Source::Rule(1), Source::Score(7), Source::Drift] {
            assert_eq!(
                class_of(&finding(source, Category::Threat, FindingState::Open)),
                Some(NotificationClass::NeedsYou),
                "{source}"
            );
        }
        assert_eq!(
            class_of(&finding(
                Source::KeepsComingBack,
                Category::Threat,
                FindingState::Open
            )),
            Some(NotificationClass::KeepsComingBack)
        );
        assert_eq!(
            class_of(&finding(
                Source::Rule(18),
                Category::Exposure,
                FindingState::Open
            )),
            None,
            "an Exposure"
        );
        for state in [
            FindingState::Trusted,
            FindingState::Acknowledged,
            FindingState::Gone,
        ] {
            assert_eq!(
                class_of(&finding(Source::Rule(1), Category::Threat, state)),
                None
            );
        }
    }

    #[test]
    fn a_told_finding_is_not_un_notified_and_a_stopped_one_carries_its_sessions() {
        let mut stopped = finding(Source::Rule(1), Category::Threat, FindingState::Stopped);
        stopped.facts.actor = Some(Actor::Auto);
        let told =
            finding(Source::Drift, Category::Threat, FindingState::Open).notified(Some(moment()));
        let state = State {
            findings: vec![stopped.clone(), told],
            ..State::empty()
        };
        let changes = unnotified(&state, &healthy(), &|receipt| match receipt {
            "q-1" => SessionsRunning::Yes,
            _ => SessionsRunning::No,
        });
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0].id, stopped.id.as_str());
        assert_eq!(changes[0].class, NotificationClass::StoppedAutomatically);
        assert_eq!(changes[0].name, "setup");
        assert_eq!(changes[0].kind, Some(Kind::Skill));
        assert_eq!(changes[0].sessions, SessionsRunning::Yes);
    }

    #[test]
    fn a_broken_chain_is_told_once_per_break() {
        let mut health = healthy();
        health.events = ChainState::Broken {
            sequence: 3,
            reason: agentsweep_core::chain::BreakReason::MacFailed,
        };
        let mut state = State::empty();
        let changes = unnotified(&state, &health, &|_| SessionsRunning::Unknown);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].class, NotificationClass::RecordsChanged);
        assert_eq!(changes[0].id, "records/events@3");

        state.told.records.insert(changes[0].id.clone());
        assert!(unnotified(&state, &health, &|_| SessionsRunning::Unknown).is_empty());

        health.baseline = ChainState::Broken {
            sequence: 9,
            reason: agentsweep_core::chain::BreakReason::MacFailed,
        };
        let again = unnotified(&state, &health, &|_| SessionsRunning::Unknown);
        assert_eq!(again[0].id, "records/events@3,baseline@9", "a new break");
    }

    #[test]
    fn a_new_project_that_needs_permission_is_told_with_the_count() {
        let project = |root: &str, check| ProjectRecord {
            root: root.to_string(),
            agents: Vec::new(),
            check,
        };
        let mut state = State::empty();
        state.overview.projects = vec![
            project("/home/Documents/app", ProjectCheck::NeedsPermission),
            project("/home/Developer/tool", ProjectCheck::Checked),
        ];
        let changes = unnotified(&state, &healthy(), &|_| SessionsRunning::Unknown);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].class, NotificationClass::Permission);
        assert_eq!(changes[0].count, 1);
        assert!(!changes[0].id.contains("Documents"), "no path in the id");

        state.told.permission = BTreeSet::from(["/home/Documents/app".to_string()]);
        assert!(unnotified(&state, &healthy(), &|_| SessionsRunning::Unknown).is_empty());

        state
            .overview
            .projects
            .push(project("/home/Desktop/site", ProjectCheck::NeedsPermission));
        let again = unnotified(&state, &healthy(), &|_| SessionsRunning::Unknown);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].count, 2, "the count is every project not checked");
    }
}
