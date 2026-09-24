//! The enforcement half of the contract: MoveOut and Restore on a temporary
//! copy, for every kind an adapter declares it can move out.
//!
//! A declared capability that does not work is worse than none, so the suite
//! carries out the real thing: it quarantines each Item of a MoveOut kind into
//! a store of its own, checks that the Surface no longer holds it and that the
//! payload carries no executable bit, and then restores it and compares the
//! Surface with what it held before, byte for byte and mode for mode.
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
use agentsweep_core::host::Host;
use agentsweep_core::item::{Item, Kind, Scope};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::quarantine::{Conflict, QuarantineStore, Store};

use crate::{Report, fixtures};

/// Every case of one adapter, quarantined and restored, and then the question
/// the cases together answer: does every kind the adapter declares MoveOut for
/// have a case that proves it?
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
    for kind in moves_out(adapter) {
        if !exercised.contains(&kind) {
            report.note(
                agent,
                "-",
                "quarantine",
                format!("{kind} declares MoveOut and no case has one to move out"),
            );
        }
    }
}

/// The kinds one adapter has to be able to move out: the ones it declares
/// MoveOut for whose whole Quarantine is that one primitive. A composite kind
/// waits for the primitives its other steps need.
pub fn moves_out(adapter: &dyn SurfaceAdapter) -> Vec<Kind> {
    adapter
        .descriptor()
        .kinds
        .iter()
        .copied()
        .filter(|kind| eligibility(*kind).primitives == [Primitive::MoveOut])
        .filter(|kind| {
            adapter
                .descriptor()
                .capabilities_for(*kind)
                .contains(&Primitive::MoveOut)
        })
        .collect()
}

/// Quarantines and restores every Item of one case that declares MoveOut, and
/// answers with the kinds it got to.
pub fn check_case(adapter: &dyn SurfaceAdapter, case: &str, report: &mut Report) -> Vec<Kind> {
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
    let movable = moves_out(adapter);
    for item in &enumeration.items {
        // A Managed Item is read-only for AgentSweep whatever its kind, so the
        // suite never asks an adapter to touch one.
        if item.scope == Scope::Managed || !movable.contains(&item.kind) {
            continue;
        }
        if round_trip(adapter, case, &host, &store, item, report) {
            exercised.push(item.kind);
        }
    }
    exercised.sort_by_key(|kind| kind.as_str());
    exercised.dedup();
    exercised
}

/// One Item out of its Surface and back again.
fn round_trip(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    host: &Host,
    store: &QuarantineStore,
    item: &Item,
    report: &mut Report,
) -> bool {
    let agent = adapter.descriptor().agent;
    let before = Snapshot::of(&item.path);
    if before.is_empty() {
        report.note(
            agent,
            case,
            "quarantine",
            format!("{} is not on the Surface to begin with", item.id),
        );
        return false;
    }

    let primitives = eligibility(item.kind).primitives;
    let receipt = match adapter.enforce(host, store, item, primitives) {
        Ok(receipt) => receipt,
        Err(error) => {
            report.note(
                agent,
                case,
                "quarantine",
                format!("{} declares MoveOut and refused it: {error}", item.id),
            );
            return false;
        }
    };

    let mut whole = true;
    let wrong = |report: &mut Report, check: &str, detail: String| {
        report.note(agent, case, check, detail);
    };
    if std::fs::symlink_metadata(&item.path).is_ok() {
        wrong(
            report,
            "quarantine",
            format!("{} is still on the Surface after MoveOut", item.id),
        );
        whole = false;
    }
    let payload = store.payload_of(&receipt.id);
    if std::fs::symlink_metadata(&payload).is_err() {
        wrong(
            report,
            "quarantine",
            format!("{} left no payload in the store", item.id),
        );
        whole = false;
    }
    for (name, entry) in &Snapshot::of(&payload).entries {
        if entry.mode & 0o111 != 0 && !entry.is_dir && !entry.is_link {
            wrong(
                report,
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
        wrong(
            report,
            "quarantine",
            format!("the store names the payload of {} after the Item", item.id),
        );
        whole = false;
    }
    let path = item.path.display().to_string();
    if !receipt.steps.iter().any(|step| step.path == path) {
        wrong(
            report,
            "quarantine",
            format!("no step of the Receipt of {} names its path", item.id),
        );
        whole = false;
    }

    let restored = adapter.restore(host, store, &receipt, Conflict::Refuse);
    if !restored.is_complete() {
        wrong(
            report,
            "restore",
            format!("{} did not come back whole: {:?}", item.id, restored.steps),
        );
        return false;
    }
    let after = Snapshot::of(&item.path);
    if after != before {
        wrong(
            report,
            "restore",
            format!(
                "{} came back different: {}",
                item.id,
                after.against(&before)
            ),
        );
        return false;
    }
    whole
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

    #[test]
    fn every_kind_the_agent_adapters_declare_move_out_for_has_a_case_that_proves_it() {
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
        // so the two Agent adapters name what it got to.
        assert_eq!(
            moves_out(&Wrapping::inner()),
            vec![
                Kind::InstructionFile,
                Kind::Skill,
                Kind::Subagent,
                Kind::Workflow
            ]
        );
        assert_eq!(
            moves_out(&agentsweep_adapter_codex::Codex::new()),
            vec![Kind::InstructionFile, Kind::Skill, Kind::ExecPolicy]
        );
        // The reference adapter neutralises in place and moves nothing out, so
        // it is exempt rather than silently passing.
        assert!(moves_out(&agentsweep_adapter_workspace::Workspace::new()).is_empty());
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
                .any(|violation| violation.contains("declares MoveOut and refused it")),
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
                .any(|violation| violation.contains("no case has one to move out")),
            "{:?}",
            report.violations
        );
    }
}
