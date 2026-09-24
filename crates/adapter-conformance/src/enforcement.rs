//! The enforcement half of the contract: every capability an adapter declares,
//! carried out and taken back on a temporary copy.
//!
//! A declared capability that does not work is worse than none, so the suite
//! does the real thing to every Item of every kind an adapter declares a
//! primitive for: it quarantines the Item with the primitives the eligibility
//! table of spec section 5.2 names, checks that the Agent would no longer load
//! what the Finding was about, and then restores it and compares the whole
//! Surface with what it held before, byte for byte and mode for mode.
//!
//! The comparison is over the whole fixture copy rather than the Item's own
//! path, because a composite touches more than one file: a plugin is switched
//! off in the Agent's settings before its directory moves, and a hook entry
//! takes the script it points at with it. Anything either of them left behind
//! is a difference somewhere in the copy.
//!
//! What "the Agent would no longer load it" means is asked of the adapter
//! rather than of the file system: the case is enumerated again, and the Item
//! must be gone from it or carry another content hash. That is the one
//! question every primitive answers the same way, whether the Item was moved
//! out, dropped from a shared file or commented out where it lay.
//!
//! Nothing here touches the real machine. The Surface is the fixture copy and
//! the quarantine store is a scratch directory beside it, both removed when
//! the case is done.
//!
//! The quarantine store is written by the daemon alone (spec section 6.2), so
//! this module exists only in a test build of this crate, which is the one
//! place that turns the core's `daemon` feature on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agentsweep_core::adapter::{Primitive, SurfaceAdapter, eligibility};
use agentsweep_core::eventlog::Outcome;
use agentsweep_core::host::Host;
use agentsweep_core::item::{Item, ItemId, Kind, Scope};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::quarantine::{Conflict, QuarantineStore, Store};

use crate::{Report, fixtures};

/// Every case of one adapter, quarantined and restored, and then the question
/// the cases together answer: is every capability the adapter declares
/// exercised by a case?
///
/// A capability that is declared and never exercised is the one thing a static
/// table cannot catch, and it is worse than no capability at all: the core
/// would ask for a Quarantine that quietly does nothing.
pub fn check(adapter: &dyn SurfaceAdapter, report: &mut Report) {
    let agent = adapter.descriptor().agent;
    let mut exercised = Vec::new();
    for case in fixtures::cases(agent) {
        exercised.extend(check_case(adapter, &case, report));
    }
    for (kind, primitive) in declared(adapter) {
        if !exercised.contains(&(kind, primitive)) {
            report.note(
                agent,
                "-",
                "quarantine",
                format!(
                    "{kind} declares {} and no case carries it out",
                    primitive.as_str()
                ),
            );
        }
    }
}

/// Every capability one adapter declares, as the pairs a case has to carry
/// out.
pub fn declared(adapter: &dyn SurfaceAdapter) -> Vec<(Kind, Primitive)> {
    let descriptor = adapter.descriptor();
    let mut pairs = Vec::new();
    for kind in descriptor.kinds {
        for primitive in descriptor.capabilities_for(*kind) {
            pairs.push((*kind, *primitive));
        }
    }
    pairs
}

/// The kinds one adapter says it can take out of its Surface at all.
pub fn enforces(adapter: &dyn SurfaceAdapter) -> Vec<Kind> {
    let mut kinds: Vec<Kind> = declared(adapter)
        .into_iter()
        .map(|(kind, _)| kind)
        .collect();
    kinds.dedup();
    kinds
}

/// Quarantines and restores every Item of one case whose kind the adapter
/// declares a primitive for, and answers with the capabilities it got to.
pub fn check_case(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    report: &mut Report,
) -> Vec<(Kind, Primitive)> {
    let agent = adapter.descriptor().agent;
    let copy = fixtures::Copy::of(agent, case);
    let scratch = fixtures::Scratch::new("store");
    let host = copy.host();
    let directory = DataDirectory::at(scratch.path());
    let store = match QuarantineStore::open(&directory) {
        Ok(store) => store,
        Err(error) => {
            report.note(agent, case, "quarantine", format!("no store: {error}"));
            return Vec::new();
        }
    };

    let enumeration = adapter.enumerate(&host, host.project_roots());
    let mut exercised = Vec::new();
    let kinds = enforces(adapter);
    for item in &enumeration.items {
        // A Managed Item is read-only for AgentSweep whatever its kind, so the
        // suite never asks an adapter to touch one.
        if item.scope == Scope::Managed || !kinds.contains(&item.kind) {
            continue;
        }
        exercised.extend(round_trip(
            adapter, case, &copy, &host, &store, item, report,
        ));
    }
    exercised.sort_by_key(|(kind, primitive)| (kind.as_str(), primitive.as_str()));
    exercised.dedup();
    exercised
}

/// One Item out of its Surface and back again, with the whole copy compared
/// before and after.
fn round_trip(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    copy: &fixtures::Copy,
    host: &Host,
    store: &QuarantineStore,
    item: &Item,
    report: &mut Report,
) -> Vec<(Kind, Primitive)> {
    let agent = adapter.descriptor().agent;
    let wrong = |report: &mut Report, check: &str, detail: String| {
        report.note(agent, case, check, detail);
    };
    let before = Snapshot::of(copy.root());
    if Snapshot::of(&item.path).is_empty() {
        wrong(
            report,
            "quarantine",
            format!("{} is not on the Surface to begin with", item.id),
        );
        return Vec::new();
    }

    let primitives = eligibility(item.kind).primitives;
    let receipt = match adapter.enforce(host, store, item, primitives) {
        Ok(receipt) => receipt,
        Err(error) => {
            wrong(
                report,
                "quarantine",
                format!(
                    "{} declares {} and refused it: {error}",
                    item.id,
                    primitives
                        .iter()
                        .map(|primitive| primitive.as_str())
                        .collect::<Vec<_>>()
                        .join(" then ")
                ),
            );
            return Vec::new();
        }
    };

    let mut whole = true;
    // What the Agent would load is the adapter's own answer, so the case is
    // read again and the Item has to be gone from it or to have changed.
    if let Some(found) = enumerated(adapter, host, &item.id)
        && found == item.content_hash
    {
        wrong(
            report,
            "quarantine",
            format!("{} is still on the Surface after the Quarantine", item.id),
        );
        whole = false;
    }
    for primitive in primitives {
        if !receipt
            .steps
            .iter()
            .any(|step| Primitive::of_recorded(step.primitive) == *primitive)
        {
            wrong(
                report,
                "quarantine",
                format!(
                    "the Receipt of {} has no {} step",
                    item.id,
                    primitive.as_str()
                ),
            );
            whole = false;
        }
    }
    whole &= moved_out_cleanly(agent, case, store, item, &receipt, report);

    let restored = adapter.restore(host, store, &receipt, Conflict::Refuse);
    if !restored.is_complete() {
        wrong(
            report,
            "restore",
            format!("{} did not come back whole: {:?}", item.id, restored.steps),
        );
        return Vec::new();
    }
    let after = Snapshot::of(copy.root());
    if after != before {
        wrong(
            report,
            "restore",
            format!(
                "the Surface came back different after {}: {}",
                item.id,
                after.against(&before)
            ),
        );
        return Vec::new();
    }
    match enumerated(adapter, host, &item.id) {
        Some(hash) if hash == item.content_hash => {}
        _ => {
            wrong(
                report,
                "restore",
                format!("{} is not enumerated again after the Restore", item.id),
            );
            return Vec::new();
        }
    }
    if !whole {
        return Vec::new();
    }
    receipt
        .steps
        .iter()
        .filter(|step| step.outcome == Outcome::Ok)
        .map(|step| (item.kind, Primitive::of_recorded(step.primitive)))
        .collect()
}

/// What the store holds for every MoveOut step of one Receipt: a payload, with
/// no executable bit left on it and nothing of the Item's name in its path.
fn moved_out_cleanly(
    agent: &str,
    case: &str,
    store: &QuarantineStore,
    item: &Item,
    receipt: &agentsweep_core::quarantine::Receipt,
    report: &mut Report,
) -> bool {
    if !receipt.steps.iter().any(|step| {
        Primitive::of_recorded(step.primitive) == Primitive::MoveOut && step.outcome == Outcome::Ok
    }) {
        return true;
    }
    let mut whole = true;
    let payload = store.payload_of(&receipt.id);
    if std::fs::symlink_metadata(&payload).is_err() {
        report.note(
            agent,
            case,
            "quarantine",
            format!("{} left no payload in the store", item.id),
        );
        return false;
    }
    for (name, entry) in &Snapshot::of(&payload).entries {
        if entry.mode & 0o111 != 0 && !entry.is_dir && !entry.is_link {
            report.note(
                agent,
                case,
                "quarantine",
                format!("the payload of {} keeps {name:?} executable", item.id),
            );
            whole = false;
        }
    }
    // The original name is in the Receipt the Event Log holds and nowhere in
    // the store, so the store is never a second, weaker record of what was
    // taken out (spec section 5.1).
    let name = item.path.file_name().unwrap_or_default().to_string_lossy();
    if payload.display().to_string().contains(name.as_ref()) {
        report.note(
            agent,
            case,
            "quarantine",
            format!("the store names the payload of {} after the Item", item.id),
        );
        whole = false;
    }
    whole
}

/// The content hash one Item has in the case as it stands now, absent when the
/// adapter no longer enumerates it.
fn enumerated(adapter: &dyn SurfaceAdapter, host: &Host, id: &ItemId) -> Option<String> {
    adapter
        .enumerate(host, host.project_roots())
        .items
        .into_iter()
        .find(|item| item.id == *id)
        .map(|item| item.content_hash)
}

/// What one path holds: the bytes and the permission bits of everything below
/// it, which is what "identical bytes and modes" is compared with.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Snapshot {
    entries: BTreeMap<String, Entry>,
}

/// One file, directory or link of a Snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    mode: u32,
    is_dir: bool,
    is_link: bool,
    /// The bytes of a file, the target of a link, empty for a directory.
    content: Vec<u8>,
}

impl Snapshot {
    fn of(root: &Path) -> Snapshot {
        let mut snapshot = Snapshot::default();
        let mut stack = vec![(root.to_path_buf(), String::new())];
        while let Some((path, name)) = stack.pop() {
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let is_link = metadata.file_type().is_symlink();
            let is_dir = metadata.is_dir() && !is_link;
            let content = if is_link {
                std::fs::read_link(&path)
                    .map(|target| target.display().to_string().into_bytes())
                    .unwrap_or_default()
            } else if is_dir {
                Vec::new()
            } else {
                std::fs::read(&path).unwrap_or_default()
            };
            snapshot.entries.insert(
                name.clone(),
                Entry {
                    mode: mode_of(&metadata),
                    is_dir,
                    is_link,
                    content,
                },
            );
            if !is_dir {
                continue;
            }
            let Ok(listing) = std::fs::read_dir(&path) else {
                continue;
            };
            let mut below: Vec<PathBuf> = listing
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect();
            below.sort();
            for entry in below {
                let child = entry
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let relative = match name.is_empty() {
                    true => child,
                    false => format!("{name}/{child}"),
                };
                stack.push((entry, relative));
            }
        }
        snapshot
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first difference, in words, so a violation says what moved.
    fn against(&self, other: &Snapshot) -> String {
        for (name, entry) in &other.entries {
            match self.entries.get(name) {
                None => return format!("{name:?} is gone"),
                Some(found) if found.content != entry.content => {
                    return format!("{name:?} holds other bytes");
                }
                Some(found) if found.mode != entry.mode => {
                    return format!("{name:?} is {:o} and was {:o}", found.mode, entry.mode);
                }
                Some(_) => {}
            }
        }
        for name in self.entries.keys() {
            if !other.entries.contains_key(name) {
                return format!("{name:?} is new");
            }
        }
        "nothing".to_string()
    }
}

#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters;

    use agentsweep_core::adapter::{Descriptor, Detection, Enumeration, ProjectRegistration};
    use agentsweep_core::quarantine::{EnforcementError, Receipt};

    use std::path::PathBuf;

    /// The Claude Code adapter's enumeration under another adapter's
    /// enforcement, which is how the two halves are told apart. It answers with
    /// the real descriptor so that the suite finds the real fixture cases.
    struct Wrapping;

    impl Wrapping {
        fn inner() -> agentsweep_adapter_claude_code::ClaudeCode {
            agentsweep_adapter_claude_code::ClaudeCode::new()
        }
    }

    /// An adapter that declares MoveOut and does not carry it out.
    struct Refuses;

    impl SurfaceAdapter for Refuses {
        fn descriptor(&self) -> &'static Descriptor {
            Wrapping::inner().descriptor()
        }
        fn detect(&self, _host: &Host) -> Detection {
            Detection::default()
        }
        fn projects(&self, _host: &Host) -> Vec<ProjectRegistration> {
            Vec::new()
        }
        fn enumerate(&self, host: &Host, roots: &[PathBuf]) -> Enumeration {
            Wrapping::inner().enumerate(host, roots)
        }
    }

    /// An adapter that takes an Item out and cannot put it back.
    struct Forgets;

    impl SurfaceAdapter for Forgets {
        fn descriptor(&self) -> &'static Descriptor {
            Wrapping::inner().descriptor()
        }
        fn detect(&self, _host: &Host) -> Detection {
            Detection::default()
        }
        fn projects(&self, _host: &Host) -> Vec<ProjectRegistration> {
            Vec::new()
        }
        fn enumerate(&self, host: &Host, roots: &[PathBuf]) -> Enumeration {
            Wrapping::inner().enumerate(host, roots)
        }
        fn enforce(
            &self,
            host: &Host,
            store: &dyn Store,
            item: &Item,
            primitives: &[Primitive],
        ) -> Result<Receipt, EnforcementError> {
            Wrapping::inner().enforce(host, store, item, primitives)
        }
    }

    /// The case every MoveOut kind of the Claude Code adapter appears in.
    const CASE: &str = "user-skills-and-commands";

    /// Acceptance of ticket 16: every capability every adapter declares is
    /// carried out on a temporary copy and taken back, and the Surface is
    /// byte for byte what it was.
    #[test]
    fn every_capability_the_adapters_declare_has_a_case_that_carries_it_out() {
        for adapter in adapters() {
            let mut report = Report::default();
            check(adapter.as_ref(), &mut report);
            assert!(
                report.is_clean(),
                "{}: {}",
                adapter.descriptor().agent,
                report.violations.join("\n")
            );
        }

        // The check is worth something only if there is anything to exercise,
        // so the three adapters name what it got to.
        assert_eq!(
            declared(&Wrapping::inner()),
            vec![
                (Kind::InstructionFile, Primitive::MoveOut),
                (Kind::Skill, Primitive::MoveOut),
                (Kind::Plugin, Primitive::NativeDisable),
                (Kind::Plugin, Primitive::MoveOut),
                (Kind::Marketplace, Primitive::RemoveEntry),
                (Kind::Marketplace, Primitive::MoveOut),
                (Kind::McpServer, Primitive::RemoveEntry),
                (Kind::Hook, Primitive::RemoveEntry),
                (Kind::SettingsEntry, Primitive::RemoveEntry),
                (Kind::Subagent, Primitive::MoveOut),
                (Kind::Workflow, Primitive::MoveOut),
            ]
        );
        assert_eq!(
            declared(&agentsweep_adapter_codex::Codex::new()),
            vec![
                (Kind::InstructionFile, Primitive::MoveOut),
                (Kind::Skill, Primitive::MoveOut),
                (Kind::McpServer, Primitive::RemoveEntry),
                (Kind::Hook, Primitive::RemoveEntry),
                (Kind::SettingsEntry, Primitive::RemoveEntry),
                (Kind::ExecPolicy, Primitive::MoveOut),
            ]
        );
        assert_eq!(
            declared(&agentsweep_adapter_workspace::Workspace::new()),
            vec![
                (Kind::RepositoryMetadata, Primitive::NeutraliseInPlace),
                (Kind::EnvFile, Primitive::NeutraliseInPlace),
            ]
        );
    }

    #[test]
    fn an_adapter_that_declares_move_out_and_refuses_it_is_told_so() {
        let mut report = Report::default();

        let exercised = check_case(&Refuses, CASE, &mut report);

        assert!(exercised.is_empty());
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.contains("and refused it")),
            "{:?}",
            report.violations
        );
    }

    #[test]
    fn an_adapter_that_cannot_put_an_item_back_is_told_so() {
        let mut report = Report::default();

        let exercised = check_case(&Forgets, CASE, &mut report);

        assert!(exercised.is_empty());
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.contains("did not come back whole")),
            "{:?}",
            report.violations
        );
    }

    #[test]
    fn a_declared_kind_no_case_has_is_a_violation() {
        /// An adapter that declares a MoveOut kind and has no fixture tree at
        /// all, so nothing ever proves the capability.
        struct Unproven;

        static KINDS: &[Kind] = &[Kind::InstructionFile];
        static CAPABILITIES: &[(Kind, &[Primitive])] =
            &[(Kind::InstructionFile, &[Primitive::MoveOut])];
        static DESCRIPTOR: Descriptor = Descriptor {
            agent: "unproven",
            display_name: "Unproven",
            kinds: KINDS,
            default_config_dir: "",
            surfaces: &[],
            capabilities: CAPABILITIES,
        };

        impl SurfaceAdapter for Unproven {
            fn descriptor(&self) -> &'static Descriptor {
                &DESCRIPTOR
            }
            fn detect(&self, _host: &Host) -> Detection {
                Detection::default()
            }
            fn projects(&self, _host: &Host) -> Vec<ProjectRegistration> {
                Vec::new()
            }
            fn enumerate(&self, _host: &Host, _roots: &[PathBuf]) -> Enumeration {
                Enumeration::default()
            }
        }

        let mut report = Report::default();

        check(&Unproven, &mut report);

        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.contains("no case carries it out")),
            "{:?}",
            report.violations
        );
    }
}
