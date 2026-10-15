//! Every Surface Adapter against every fixture tree.
//!
//! This is the executable form of the adapter contract. An adapter that passes
//! it is one the core can carry without knowing anything about the Agent it
//! belongs to, which is what makes "a third adapter without touching the core"
//! an acceptance test rather than a hope.

use agentsweep_adapter_conformance::{adapters, check, check_all};

#[test]
fn every_adapter_conforms() {
    let report = check_all();
    assert!(
        report.is_clean(),
        "{} case(s) run, {} violation(s):\n{}",
        report.cases.len(),
        report.violations.len(),
        report.violations.join("\n")
    );
    assert!(!report.cases.is_empty());
}

#[test]
fn the_reference_adapter_conforms_on_every_case_it_has() {
    let adapters = adapters();
    let workspace = adapters
        .iter()
        .find(|adapter| adapter.descriptor().agent == "workspace")
        .expect("the workspace adapter is in the suite");

    let report = check(workspace.as_ref());

    assert!(report.is_clean(), "{}", report.violations.join("\n"));
    assert!(
        report.cases.len() >= 4,
        "the reference adapter covers a clean repository, planted git metadata, \
         a gitdir pointer that left the layout and a spoofed commondir: {:?}",
        report.cases
    );
}

/// The suite is worth something only if it fails when an adapter is wrong.
#[test]
fn a_snapshot_that_does_not_match_is_a_violation() {
    use agentsweep_adapter_conformance::fixtures;
    use agentsweep_adapter_workspace::Workspace;
    use agentsweep_core::adapter::SurfaceAdapter;

    let copy = fixtures::Copy::of("workspace", "planted-git-metadata");
    let host = copy.host();
    let adapter = Workspace::new();
    let enumeration = adapter.enumerate(&host, host.project_roots());

    let recorded =
        std::fs::read_to_string(fixtures::snapshot_path("workspace", "planted-git-metadata"))
            .expect("the case has a snapshot");
    let rendered = agentsweep_adapter_conformance::snapshot(&adapter, &enumeration, copy.root());

    assert_eq!(recorded, rendered);
    assert_ne!(recorded, format!("{rendered}item one more\n"));
}

/// Spec section 7.6: every Agent adapter states, for every pooled root of
/// every case, whether the project's own settings switch its hooks off; the
/// workspace adapter reads no Agent settings and states none.
#[test]
fn every_agent_adapter_states_the_hook_switch_of_every_root_and_the_workspace_none() {
    use agentsweep_adapter_conformance::fixtures;

    for adapter in adapters() {
        let agent = adapter.descriptor().agent;
        for case in fixtures::cases(agent) {
            let copy = fixtures::Copy::of(agent, &case);
            let host = copy.host();
            let roots = host.project_roots().to_vec();
            let enumeration = adapter.enumerate(&host, &roots);
            let stated: Vec<_> = enumeration
                .project_hooks
                .iter()
                .map(|hooks| (hooks.agent.as_str(), hooks.root.clone()))
                .collect();
            let expected: Vec<_> = match agent {
                "workspace" => Vec::new(),
                _ => roots.iter().map(|root| (agent, root.clone())).collect(),
            };
            assert_eq!(stated, expected, "{agent}/{case}");
        }
    }
}
