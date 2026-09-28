//! The Surface Adapter conformance suite.
//!
//! It runs every adapter against sanitised fixture trees on temporary copies
//! and checks what the contract of spec section 3 promises: the enumeration is
//! the one the snapshot records, two enumerations of the same tree yield the
//! same Item ids, a second copy of the tree in a directory of its own yields
//! the same content hashes, every watch root maps back to at least one Item,
//! every parsed view validates against the schema a Rule compiles against, and
//! the descriptor declares an enforcement capability for every kind it yields
//! that agrees with the core's eligibility table.
//!
//! The workspace adapter is the reference: it is written against the trait and
//! nothing else, and it is run first.
//!
//! **Adding an adapter.** Implement [`SurfaceAdapter`] in a crate of its own,
//! add it to [`adapters`], put one fixture tree per case at
//! `fixtures/<agent id>/<case>/` and record the first snapshot by running the
//! suite once with `AGENTSWEEP_UPDATE_SNAPSHOTS=1`. Nothing in the core has to
//! change for that; if it does, the adapter contract is what is wrong.
//!
//! The other half of the contract is what an adapter does rather than what it
//! reads: [`enforcement`] carries out every capability the adapter declares on
//! the copy, whichever primitive it is, and then takes it back and compares
//! the whole copy with what it held before. It writes a quarantine store,
//! which only the daemon may do (spec section 6.2), so it is behind this
//! crate's `daemon` feature, and a test build is the only build that turns
//! that on.

#![warn(missing_docs)]

#[cfg(feature = "daemon")]
pub mod enforcement;
pub mod fixtures;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use agentsweep_adapter_workspace::Workspace;
use agentsweep_core::adapter::{Enumeration, SurfaceAdapter, eligibility};
use agentsweep_core::item::{Item, Kind};
use agentsweep_core::views::{ParsedView, Views};
use serde_json::Value;

/// The environment variable that rewrites the snapshots instead of comparing
/// against them.
pub const UPDATE: &str = "AGENTSWEEP_UPDATE_SNAPSHOTS";

/// The Agent ids of the adapters v1 ships, in the order the suite runs them:
/// the workspace adapter first, because it is the reference adapter.
pub fn agent_ids() -> [&'static str; 3] {
    [
        agentsweep_adapter_workspace::AGENT_ID,
        agentsweep_adapter_claude_code::AGENT_ID,
        agentsweep_adapter_codex::AGENT_ID,
    ]
}

/// Every adapter the suite runs, the reference adapter first.
pub fn adapters() -> Vec<Box<dyn SurfaceAdapter>> {
    vec![
        Box::new(Workspace::new()),
        Box::new(agentsweep_adapter_claude_code::ClaudeCode::new()),
        Box::new(agentsweep_adapter_codex::Codex::new()),
    ]
}

/// What the suite found wrong. An adapter conforms when this is empty.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// One line per thing that is wrong, naming the adapter, the case and the
    /// check.
    pub violations: Vec<String>,
    /// The cases that were run, in order.
    pub cases: Vec<String>,
}

impl Report {
    /// True when nothing is wrong.
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    fn note(&mut self, agent: &str, case: &str, check: &str, detail: impl AsRef<str>) {
        self.violations.push(format!(
            "{agent}/{case}: {check}: {}",
            detail.as_ref().trim()
        ));
    }
}

/// Runs every check of every fixture case of one adapter.
pub fn check(adapter: &dyn SurfaceAdapter) -> Report {
    let agent = adapter.descriptor().agent;
    let mut report = Report::default();
    check_descriptor(adapter, &mut report);
    for case in fixtures::cases(agent) {
        report.cases.push(format!("{agent}/{case}"));
        check_case(adapter, &case, &mut report);
    }
    if report.cases.is_empty() {
        report.note(agent, "-", "fixtures", "the adapter has no fixture case");
    }
    #[cfg(feature = "daemon")]
    enforcement::check(adapter, &mut report);
    report
}

/// Runs every adapter of [`adapters`].
pub fn check_all() -> Report {
    let mut report = Report::default();
    for adapter in adapters() {
        let one = check(adapter.as_ref());
        report.cases.extend(one.cases);
        report.violations.extend(one.violations);
    }
    report
}

/// The static half of the contract: what the descriptor promises.
fn check_descriptor(adapter: &dyn SurfaceAdapter, report: &mut Report) {
    let descriptor = adapter.descriptor();
    let agent = descriptor.agent;
    if agent.is_empty() || !agent.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
        report.note(
            agent,
            "-",
            "descriptor",
            "the Agent id is not machine readable",
        );
    }
    if descriptor.display_name.is_empty() {
        report.note(agent, "-", "descriptor", "the adapter has no display name");
    }
    for kind in descriptor.kinds {
        let declared = descriptor.capabilities_for(*kind);
        if declared.is_empty() {
            report.note(
                agent,
                "-",
                "capabilities",
                format!("{kind} is yielded but declares no enforcement primitive"),
            );
            continue;
        }
        // The core's table decides what one Quarantine does to a kind; an
        // adapter may only declare what it can carry out of that, the switch
        // a row puts first included.
        let row = eligibility(*kind);
        for primitive in declared {
            if !row.allows(*primitive) {
                report.note(
                    agent,
                    "-",
                    "capabilities",
                    format!("{kind} declares {primitive:?}, which is not its primitive"),
                );
            }
        }
    }
    for surface in descriptor.surfaces {
        if !descriptor.kinds.contains(&surface.kind) {
            report.note(
                agent,
                "-",
                "surfaces",
                format!(
                    "{} yields {}, which is not declared",
                    surface.locator, surface.kind
                ),
            );
        }
    }
}

/// Every check of one case.
fn check_case(adapter: &dyn SurfaceAdapter, case: &str, report: &mut Report) {
    let agent = adapter.descriptor().agent;
    let copy = fixtures::Copy::of(agent, case);
    let host = copy.host();
    let roots = host.project_roots().to_vec();

    let first = adapter.enumerate(&host, &roots);
    let second = adapter.enumerate(&host, &roots);

    // The second enumeration is of an independent copy in a directory of its
    // own. Anything an Item carries that depends on where the copy happened to
    // land, a path in the content an entry hash is taken over above all, shows
    // up here and nowhere else.
    let elsewhere = fixtures::Copy::of(agent, case);
    let other_host = elsewhere.host();
    let other = adapter.enumerate(&other_host, other_host.project_roots());

    check_ids(adapter, case, &first, &second, report);
    check_placement(
        adapter,
        case,
        &first,
        copy.root(),
        &other,
        elsewhere.root(),
        report,
    );
    report
        .violations
        .extend(check_enumeration(adapter, case, &first).violations);
    check_snapshot(adapter, case, &first, copy.root(), report);
}

/// Every check that one enumeration can answer on its own: the kinds, the
/// shape of the ids, the parsed views and the watch roots.
///
/// An adapter being written against the contract can call this with an
/// enumeration of its own before it has a fixture tree.
pub fn check_enumeration(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    enumeration: &Enumeration,
) -> Report {
    let mut report = Report::default();
    check_kinds(adapter, case, enumeration, &mut report);
    check_views(adapter, case, enumeration, &mut report);
    check_watch_roots(adapter, case, enumeration, &mut report);
    report
}

/// Two enumerations of the same tree yield the same Items, with the same ids
/// and the same content hashes. Identity that moves would make every Baseline
/// and every Trust record meaningless.
fn check_ids(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    first: &Enumeration,
    second: &Enumeration,
    report: &mut Report,
) {
    let agent = adapter.descriptor().agent;
    let ids = |enumeration: &Enumeration| -> Vec<String> {
        enumeration
            .items
            .iter()
            .map(|item| format!("{} {}", item.id, item.content_hash))
            .collect()
    };
    if ids(first) != ids(second) {
        report.note(
            agent,
            case,
            "id stability",
            format!("{:?} then {:?}", ids(first), ids(second)),
        );
    }
}

/// The same fixture tree in two different directories yields the same Items.
///
/// An Item id names where a project root is, so ids differ by construction and
/// are compared with the root written out as `<root>`. A content hash may not
/// differ at all: an entry hash is what Trust and the Baseline key on, and one
/// that moves with the directory the tree happens to sit in would mean a
/// machine could never carry either over.
fn check_placement(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    here: &Enumeration,
    here_root: &Path,
    elsewhere: &Enumeration,
    elsewhere_root: &Path,
    report: &mut Report,
) {
    let agent = adapter.descriptor().agent;
    let rendered = |enumeration: &Enumeration, root: &Path| -> Vec<String> {
        enumeration
            .items
            .iter()
            .map(|item| {
                format!("{} {}", item.id, item.content_hash)
                    .replace(&root.display().to_string(), "<root>")
            })
            .collect()
    };
    let one = rendered(here, here_root);
    let other = rendered(elsewhere, elsewhere_root);
    if one != other {
        report.note(
            agent,
            case,
            "placement",
            format!("a second copy of the tree yields {other:?} instead of {one:?}"),
        );
    }
}

/// An adapter yields only the kinds its descriptor declares, each Item once,
/// with an id of the documented shape and a content hash.
fn check_kinds(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    enumeration: &Enumeration,
    report: &mut Report,
) {
    let descriptor = adapter.descriptor();
    let agent = descriptor.agent;
    let mut seen = BTreeMap::new();
    for item in &enumeration.items {
        if seen.insert(item.id.clone(), ()).is_some() {
            report.note(agent, case, "id stability", format!("{} twice", item.id));
        }
        let expected = format!(
            "{}/{}/{}/",
            agent,
            item.scope.id_segment(),
            item.kind.id_segment()
        );
        if !item.id.as_str().starts_with(&expected) {
            report.note(
                agent,
                case,
                "id shape",
                format!("{} is not {expected}<locator>", item.id),
            );
        }
        if !descriptor.kinds.contains(&item.kind) {
            report.note(
                agent,
                case,
                "kinds",
                format!("{} is a {}, which is not declared", item.id, item.kind),
            );
        }
        if item.agent != agent {
            report.note(
                agent,
                case,
                "kinds",
                format!("{} says it comes from {}", item.id, item.agent),
            );
        }
        if item.content_hash.len() != 64 {
            report.note(
                agent,
                case,
                "kinds",
                format!("{} carries no content hash", item.id),
            );
        }
    }
}

/// Every parsed view an adapter attached validates against the schema the pack
/// was compiled with, and belongs to the Item's kind.
fn check_views(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    enumeration: &Enumeration,
    report: &mut Report,
) {
    let agent = adapter.descriptor().agent;
    for item in &enumeration.items {
        for unit in item.scan_units() {
            for violation in Views::of(item, &unit).validate() {
                report.note(agent, case, "views", format!("{}: {violation}", item.id));
            }
        }
        if let Some(expected) = view_of(item.kind) {
            let attached = item.view.name();
            if attached != expected {
                report.note(
                    agent,
                    case,
                    "views",
                    format!(
                        "{} is a {} and carries the {attached:?} view",
                        item.id, item.kind
                    ),
                );
            }
        } else if !matches!(item.view, ParsedView::None) {
            report.note(
                agent,
                case,
                "views",
                format!("{} is a {} and has no view to carry", item.id, item.kind),
            );
        }
    }
}

/// The view a kind carries, or nothing when Rules on it are byte Rules.
fn view_of(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::McpServer => Some("mcp"),
        Kind::Hook => Some("hook"),
        Kind::SettingsEntry => Some("settings"),
        Kind::Skill => Some("skill"),
        Kind::Plugin => Some("plugin"),
        Kind::Marketplace => Some("marketplace"),
        Kind::Subagent => Some("subagent"),
        Kind::EnvFile => Some("env"),
        Kind::RepositoryMetadata => Some("repo"),
        Kind::InstructionFile | Kind::ExecPolicy | Kind::Workflow | Kind::Generic => None,
    }
}

/// Every watch root maps back to at least one Item, and every Item is inside
/// one of the watch roots. A root with nothing behind it is a watcher that
/// wakes for nothing; an Item outside every root is a change nobody sees.
fn check_watch_roots(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    enumeration: &Enumeration,
    report: &mut Report,
) {
    let agent = adapter.descriptor().agent;
    let roots = adapter.watch_roots(enumeration);

    for root in roots.all() {
        // A root maps back to an Item by holding it, or by being the place a
        // tree's files really are: a skill reached through a link is watched
        // at its target and says so through `items_for_path`.
        let covered = enumeration
            .items
            .iter()
            .any(|item| item.path.starts_with(root))
            || !adapter.items_for_path(enumeration, root).is_empty();
        if !covered {
            report.note(
                agent,
                case,
                "watch roots",
                format!("no Item behind {}", root.display()),
            );
        }
    }

    for item in &enumeration.items {
        if !roots.covers(&item.path) {
            report.note(
                agent,
                case,
                "watch roots",
                format!("{} is watched by no root", item.id),
            );
        }
        let mapped = adapter.items_for_path(enumeration, &item.path);
        if !mapped.contains(&item.id) {
            report.note(
                agent,
                case,
                "items for path",
                format!("{} does not map back from its own path", item.id),
            );
        }
    }
}

/// The enumeration is the one the case recorded.
fn check_snapshot(
    adapter: &dyn SurfaceAdapter,
    case: &str,
    enumeration: &Enumeration,
    root: &Path,
    report: &mut Report,
) {
    let agent = adapter.descriptor().agent;
    let rendered = snapshot(adapter, enumeration, root);
    let path = fixtures::snapshot_path(agent, case);

    if std::env::var(UPDATE).is_ok() {
        std::fs::write(&path, &rendered).expect("a rewritten snapshot");
        return;
    }
    let recorded = std::fs::read_to_string(&path).unwrap_or_default();
    if recorded != rendered {
        report.note(
            agent,
            case,
            "snapshot",
            format!(
                "the enumeration is not the one recorded in {}. Recorded:\n{recorded}\nFound:\n{rendered}",
                path.display()
            ),
        );
    }
}

/// One enumeration, rendered so that it can be read and compared. The
/// temporary root is written as `<root>`, so the same tree renders the same way
/// wherever it was copied to.
pub fn snapshot(adapter: &dyn SurfaceAdapter, enumeration: &Enumeration, root: &Path) -> String {
    let mut out = String::new();
    for item in &enumeration.items {
        let _ = writeln!(out, "item {}", item.id);
        // The reason is written only when there is one, so a case whose Items
        // are all active reads exactly as it did before adapters learned to
        // say why something would not be loaded.
        let reason = match item.activation.reason() {
            "" => String::new(),
            reason => format!("({reason})"),
        };
        let _ = writeln!(
            out,
            "  shape={} scope={} provenance={} activation={}{reason} registered={} symlink={} size={}",
            item.shape.as_str(),
            item.scope.as_str(),
            item.provenance.as_str(),
            item.activation.as_str(),
            item.registered,
            item.is_symlink,
            item.size
        );
        let _ = writeln!(out, "  sha256={}", item.content_hash);
        // A tree's files are the case's own documentation: which ones a Rule
        // is run over, which ones are only in the manifest, and which ones are
        // not part of the tree at all.
        for file in &item.tree.files {
            let _ = writeln!(
                out,
                "  file {} {} {} {}",
                file.path,
                file.size,
                if file.scanned { "scanned" } else { "hashed" },
                file.facts.file_type.as_str()
            );
        }
        if let Some(view) = view_line(item) {
            let _ = writeln!(out, "  {view}");
        }
    }
    for problem in &enumeration.problems {
        let _ = writeln!(
            out,
            "problem {} {} {:?}",
            problem.surface,
            problem.path.display(),
            problem.reason
        );
    }
    let roots = adapter.watch_roots(enumeration);
    for path in &roots.recursive {
        let _ = writeln!(out, "watch recursive {}", path.display());
    }
    for path in &roots.non_recursive {
        let _ = writeln!(out, "watch {}", path.display());
    }
    out.replace(&root.display().to_string(), "<root>")
}

fn view_line(item: &Item) -> Option<String> {
    let name = item.view.name();
    if name.is_empty() {
        return None;
    }
    let views = Views::of(item, &item.scan_units()[0]);
    let value = views
        .globals()
        .into_iter()
        .find(|(global, _)| *global == name)
        .map(|(_, value)| value)?;
    Some(format!("view {name} {}", sorted(&value)))
}

/// A value rendered with its keys in a stable order.
fn sorted(value: &Value) -> String {
    match value {
        Value::Object(fields) => {
            let ordered: BTreeMap<&String, String> = fields
                .iter()
                .map(|(name, value)| (name, sorted(value)))
                .collect();
            let parts: Vec<String> = ordered
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            format!("{{{}}}", parts.join(" "))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(sorted).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::String(text) => format!("{text:?}"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_adapter_declares_its_own_agent_id() {
        let ids = agent_ids();
        for (index, id) in ids.iter().enumerate() {
            assert!(!ids[index + 1..].contains(id), "duplicate agent id {id}");
        }
    }

    #[test]
    fn the_reference_adapter_is_run_first() {
        let adapters = adapters();
        assert_eq!(
            adapters[0].descriptor().agent,
            agentsweep_adapter_workspace::AGENT_ID
        );
    }

    /// Every kind that carries a view in `rules/README.md` is named here, and
    /// the four that have none are named as having none.
    #[test]
    fn every_kind_says_which_view_it_carries() {
        for kind in Kind::ALL {
            let view = view_of(kind);
            match kind {
                Kind::InstructionFile | Kind::ExecPolicy | Kind::Workflow | Kind::Generic => {
                    assert_eq!(view, None, "{kind}")
                }
                _ => assert!(view.is_some(), "{kind}"),
            }
        }
    }

    /// An adapter that gets the contract wrong in every way the suite can see
    /// on one enumeration.
    struct Wrong;

    static WRONG_KINDS: &[Kind] = &[Kind::InstructionFile];
    static WRONG_CAPABILITIES: &[(Kind, &[agentsweep_core::adapter::Primitive])] = &[(
        Kind::InstructionFile,
        &[agentsweep_core::adapter::Primitive::NeutraliseInPlace],
    )];
    static WRONG_DESCRIPTOR: agentsweep_core::adapter::Descriptor =
        agentsweep_core::adapter::Descriptor {
            agent: "wrong",
            display_name: "Wrong",
            kinds: WRONG_KINDS,
            default_config_dir: "",
            surfaces: &[],
            capabilities: WRONG_CAPABILITIES,
            agent_written_keys: &[],
        };

    impl SurfaceAdapter for Wrong {
        fn descriptor(&self) -> &'static agentsweep_core::adapter::Descriptor {
            &WRONG_DESCRIPTOR
        }
        fn detect(
            &self,
            _host: &agentsweep_core::host::Host,
        ) -> agentsweep_core::adapter::Detection {
            agentsweep_core::adapter::Detection::default()
        }
        fn projects(
            &self,
            _host: &agentsweep_core::host::Host,
        ) -> Vec<agentsweep_core::adapter::ProjectRegistration> {
            Vec::new()
        }
        fn enumerate(
            &self,
            _host: &agentsweep_core::host::Host,
            _roots: &[std::path::PathBuf],
        ) -> Enumeration {
            Enumeration::default()
        }
        fn watch_roots(&self, _enumeration: &Enumeration) -> agentsweep_core::adapter::WatchRoots {
            let mut roots = agentsweep_core::adapter::WatchRoots::default();
            roots.watch(std::path::PathBuf::from("/nowhere"));
            roots
        }
    }

    /// The suite is worth something only when it says no. This one says no
    /// four times: a kind that is not declared, a view that does not belong to
    /// the Item's kind, a watch root with no Item behind it and an Item under
    /// no watch root.
    #[test]
    fn an_adapter_that_breaks_the_contract_is_told_so() {
        let mut item = Item::file(
            "wrong",
            agentsweep_core::item::Scope::User,
            Kind::EnvFile,
            ".env",
            std::path::PathBuf::from("/elsewhere/.env"),
            agentsweep_core::item::Provenance::Unknown,
            agentsweep_core::item::Activation::Unknown,
            b"CODEX_HOME=./.codex\n".to_vec(),
        );
        item.view = ParsedView::Skill(agentsweep_core::views::SkillView::default());
        let enumeration = Enumeration {
            items: vec![item],
            problems: Vec::new(),
        };

        let report = check_enumeration(&Wrong, "made-up", &enumeration);
        let said = report.violations.join("\n");

        assert!(said.contains("which is not declared"), "{said}");
        assert!(said.contains("carries the \"skill\" view"), "{said}");
        assert!(said.contains("no Item behind /nowhere"), "{said}");
        assert!(said.contains("is watched by no root"), "{said}");
        assert!(!report.is_clean());

        let mut descriptor = Report::default();
        check_descriptor(&Wrong, &mut descriptor);
        assert!(
            descriptor
                .violations
                .join("\n")
                .contains("NeutraliseInPlace"),
            "{:?}",
            descriptor.violations
        );
    }

    #[test]
    fn a_snapshot_hides_where_the_copy_happened_to_land() {
        let copy = fixtures::Copy::of("workspace", "planted-git-metadata");
        let adapter = Workspace::new();
        let host = copy.host();
        let enumeration = adapter.enumerate(&host, host.project_roots());
        let rendered = snapshot(&adapter, &enumeration, copy.root());
        assert!(!rendered.contains("/var/folders"), "{rendered}");
        assert!(!rendered.contains(&copy.root().display().to_string()));
        assert!(rendered.contains("<root>"), "{rendered}");
    }
}
