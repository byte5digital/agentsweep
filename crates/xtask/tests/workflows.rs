//! Every workflow held to the pipeline hardening rules (spec section 9.2).
//!
//! One test per rule over the repository's own workflows, so a failure says
//! which rule broke and where. Each rule is also shown to fail on temporary
//! copies of bad Fixtures, each breaking exactly that rule, beside good
//! Fixtures that break none: the release, Rule Pack and cask workflow shapes
//! the pipeline will hold. A bad Fixture's first line names the job and line
//! the violation must carry.

use std::fs;
use std::path::{Path, PathBuf};

use agentsweep_xtask::repo_root;
use agentsweep_xtask::workflows::{self, HardeningRule, Violation};
use tempfile::TempDir;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/workflow-fixtures")
}

fn bad_directory(rule: HardeningRule) -> &'static str {
    match rule {
        HardeningRule::PinnedActions => "pinned-actions",
        HardeningRule::LockedCargo => "locked-cargo",
        HardeningRule::ReleaseReach => "release-reach",
        HardeningRule::RulePackNotLatest => "rule-pack-not-latest",
    }
}

fn yaml_files(directory: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "yml"))
        .collect();
    files.sort();
    files
}

/// A temporary workflows directory holding a copy of `file` and nothing else.
fn copy_alone(file: &Path) -> TempDir {
    let directory = TempDir::new().expect("a temporary directory");
    fs::copy(file, directory.path().join(file.file_name().unwrap())).expect("a copy");
    directory
}

fn check(directory: &Path, rule: HardeningRule) -> Vec<Violation> {
    workflows::check_directory(directory, rule).unwrap_or_else(|error| panic!("{error}"))
}

fn assert_holds(rule: HardeningRule) {
    let violations = check(&workflows::directory(&repo_root()), rule);
    let listed: Vec<String> = violations.iter().map(ToString::to_string).collect();
    assert!(
        violations.is_empty(),
        "the workflows break `{rule}`:\n{}",
        listed.join("\n")
    );
}

/// Every bad Fixture of `rule`, alone in a temporary directory, breaks that
/// rule at the job and line its first line names, and no other rule.
fn assert_each_bad_fixture_breaks_only(rule: HardeningRule) {
    let files = yaml_files(&fixtures().join("bad").join(bad_directory(rule)));
    assert!(files.len() >= 3, "{rule}: at least three bad Fixtures");
    for file in files {
        let text = fs::read_to_string(&file).expect("the Fixture");
        let expect = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("# expect: "))
            .unwrap_or_else(|| panic!("{}: no `# expect:` line", file.display()));
        let (job, line) = expect.split_once(' ').expect("`job line`");
        let line: usize = line.parse().expect("a line number");
        let name = file.file_name().unwrap().to_string_lossy().into_owned();

        let copy = copy_alone(&file);
        let violations = check(copy.path(), rule);
        assert!(
            violations
                .iter()
                .any(|v| v.file == name && v.job == job && v.line == line && v.rule == rule),
            "{name}: expected `{rule}` broken in job `{job}` at line {line}, found {violations:#?}"
        );
        for other in HardeningRule::ALL
            .into_iter()
            .filter(|other| *other != rule)
        {
            let stray = check(copy.path(), other);
            assert!(
                stray.is_empty(),
                "{name} breaks more than `{rule}`: {stray:#?}"
            );
        }
    }
}

#[test]
fn every_action_is_pinned_by_a_full_commit_sha_with_its_version() {
    assert_holds(HardeningRule::PinnedActions);
}

#[test]
fn every_cargo_build_test_clippy_install_and_auditable_carries_locked() {
    assert_holds(HardeningRule::LockedCargo);
}

#[test]
fn release_secrets_are_reached_only_from_a_release_tag_or_a_published_release() {
    assert_holds(HardeningRule::ReleaseReach);
}

#[test]
fn every_rule_pack_release_is_created_with_make_latest_false() {
    assert_holds(HardeningRule::RulePackNotLatest);
}

#[test]
fn the_ci_workflow_passes_every_rule_as_it_stands() {
    let ci = workflows::directory(&repo_root()).join("ci.yml");
    assert!(ci.is_file(), "{}", ci.display());
    let copy = copy_alone(&ci);
    for rule in HardeningRule::ALL {
        assert_eq!(
            check(copy.path(), rule),
            Vec::new(),
            "ci.yml breaks `{rule}`"
        );
    }
}

#[test]
fn the_good_fixtures_pass_every_rule() {
    let files = yaml_files(&fixtures().join("good"));
    assert!(files.len() >= 3);
    for file in files {
        let copy = copy_alone(&file);
        for rule in HardeningRule::ALL {
            assert_eq!(
                check(copy.path(), rule),
                Vec::new(),
                "{} breaks `{rule}`",
                file.display()
            );
        }
    }
}

#[test]
fn the_pinning_rule_fails_on_each_bad_fixture() {
    assert_each_bad_fixture_breaks_only(HardeningRule::PinnedActions);
}

#[test]
fn the_locked_rule_fails_on_each_bad_fixture() {
    assert_each_bad_fixture_breaks_only(HardeningRule::LockedCargo);
}

#[test]
fn the_release_reach_rule_fails_on_each_bad_fixture() {
    assert_each_bad_fixture_breaks_only(HardeningRule::ReleaseReach);
}

#[test]
fn the_rule_pack_rule_fails_on_each_bad_fixture() {
    assert_each_bad_fixture_breaks_only(HardeningRule::RulePackNotLatest);
}

/// A temporary copy of `ci.yml` with one edit made, which must exist.
fn ci_with(from: &str, to: &str) -> TempDir {
    let ci = workflows::directory(&repo_root()).join("ci.yml");
    let text = fs::read_to_string(&ci).expect("ci.yml");
    assert!(text.contains(from), "ci.yml no longer holds `{from}`");
    let directory = TempDir::new().expect("a temporary directory");
    fs::write(directory.path().join("ci.yml"), text.replacen(from, to, 1)).expect("the copy");
    directory
}

#[test]
fn a_one_line_edit_to_a_copy_of_ci_breaks_exactly_the_rule_it_touches() {
    let tag = ci_with("@3d3c42e5aac5ba805825da76410c181273ba90b1", "@v7");
    let unlocked = ci_with("cargo test --workspace --locked", "cargo test --workspace");
    let secret = ci_with(
        "CARGO_NET_RETRY: 3",
        "CARGO_NET_RETRY: 3\n  KEY: ${{ secrets.APPLE_API_KEY }}",
    );
    for (copy, broken) in [
        (&tag, HardeningRule::PinnedActions),
        (&unlocked, HardeningRule::LockedCargo),
        (&secret, HardeningRule::ReleaseReach),
    ] {
        for rule in HardeningRule::ALL {
            let violations = check(copy.path(), rule);
            assert_eq!(
                !violations.is_empty(),
                rule == broken,
                "`{rule}` on the copy breaking `{broken}`: {violations:#?}"
            );
        }
    }
    let violations = check(secret.path(), HardeningRule::ReleaseReach);
    assert!(
        violations
            .iter()
            .all(|v| v.job == workflows::WORKFLOW_LEVEL && v.file == "ci.yml"),
        "{violations:#?}"
    );
}

#[test]
fn an_unreadable_workflow_fails_rather_than_passing_unread() {
    let directory = TempDir::new().expect("a temporary directory");
    fs::write(
        directory.path().join("broken.yml"),
        "jobs:\n  a:\n    steps: []\n      stray: 1\n",
    )
    .expect("the file");
    let error = workflows::check_directory(directory.path(), HardeningRule::PinnedActions)
        .expect_err("an unreadable workflow is an error");
    assert!(error.contains("broken.yml"), "{error}");
}
