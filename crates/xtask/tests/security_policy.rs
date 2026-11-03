//! The security policy is complete before the first tagged release (spec
//! section 9.8 item 6): its two key procedures are written out, the planned
//! Rule Pack key rotation matches what the Rule Pack release workflow does
//! with two keys present, the residual risk of a leaked key is stated in the
//! words of ADR 0006, and the file carries no key id and no em-dash.

use std::fs;

use agentsweep_core::pack_signature::RELEASE_KEYS;
use agentsweep_xtask::pack_release::KEY_VARIABLES;
use agentsweep_xtask::repo_root;

fn read(path: &str) -> String {
    fs::read_to_string(repo_root().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// The policy with every run of white space folded to one space, so a phrase
/// is found wherever the prose wraps.
fn policy() -> String {
    read("SECURITY.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The body of the `## heading` section, up to the next second-level heading.
fn section(heading: &str) -> String {
    let text = read("SECURITY.md");
    let start = format!("\n## {heading}\n");
    let (_, rest) = text
        .split_once(&start)
        .unwrap_or_else(|| panic!("SECURITY.md has no section {heading}"));
    let body = rest.split("\n## ").next().unwrap_or(rest);
    body.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_says(text: &str, phrases: &[&str], what: &str) {
    for phrase in phrases {
        assert!(text.contains(phrase), "{what} does not say: {phrase}");
    }
}

#[test]
fn both_procedures_are_written_out() {
    let policy = policy();
    assert!(!policy.contains("Placeholder"), "a placeholder is left");
    assert!(!policy.contains("It will cover"), "a promise is left");
    for heading in ["Planned key rotation", "Key compromise"] {
        assert!(
            section(heading).len() > 1500,
            "the section {heading} is not written out"
        );
    }
}

/// Every step names the role that performs it, and only these three roles.
#[test]
fn every_procedure_names_its_roles() {
    let rotation = section("Planned key rotation");
    let compromise = section("Key compromise");
    for text in [&rotation, &compromise] {
        assert_says(
            text,
            &["The owner", "a reviewer of the `release` environment"],
            "a procedure",
        );
    }
    assert_says(&rotation, &["The Account Holder"], "the rotation");
}

/// The planned rotation of a Rule Pack key, as spec section 9.4 and ADR 0006
/// put it, and as the release workflow does it: it signs with every Rule Pack
/// key present in the `release` environment, the active one and the next one.
#[test]
fn the_rule_pack_rotation_matches_the_release_workflow() {
    assert_eq!(
        KEY_VARIABLES.len(),
        2,
        "the workflow holds an active and a next Rule Pack key"
    );
    let rotation = section("Planned key rotation");
    assert_says(
        &rotation,
        &[
            "An app release adds the new public key to the pinned set",
            "every Rule Pack key present in the `release` environment",
            "carries both signatures",
            "two app releases",
            "drops the old key from the pinned set",
            "signed with the old updater key",
            "carries the new updater public key",
            "Developer ID certificate is renewed before its expiry date",
            "release checklist",
        ],
        "the rotation",
    );
}

/// The compromise procedure, step by step, and the accepted residual risk in
/// the words of spec section 9.4 and ADR 0006.
#[test]
fn the_compromise_procedure_states_every_step_and_the_residual_risk() {
    let compromise = section("Key compromise");
    assert_says(
        &compromise,
        &[
            "Confirming a leak",
            "attestation",
            "within the hour",
            "standby",
            "removes the leaked key",
            "drops the leaked key from the pinned set",
            "notarized DMG",
            "Homebrew cask",
            "GitHub security advisory",
            "has not updated",
            "higher",
            "blind detection",
            "Quarantines",
            "restore",
            "never run code",
        ],
        "the compromise procedure",
    );
}

/// No key id of any kind (sixteen upper-case hex digits), none of the pinned
/// Rule Pack keys by id or value, and no em-dash.
#[test]
fn the_policy_names_no_key_and_keeps_the_house_style() {
    let text = read("SECURITY.md");
    assert!(!text.contains('\u{2014}'), "SECURITY.md has an em-dash");
    for key in &RELEASE_KEYS {
        assert!(!text.contains(&key.key_id()), "a pinned key id is named");
        assert!(!text.contains(key.public_key), "a pinned key is named");
    }
    let mut run = 0;
    for c in text.chars() {
        run = match c.is_ascii_digit() || ('A'..='F').contains(&c) {
            true => run + 1,
            false => 0,
        };
        assert!(
            run < 16,
            "SECURITY.md carries something shaped like a key id"
        );
    }
    for word in ["minisign.key", ".p12", "BEGIN", "untrusted comment"] {
        assert!(!text.contains(word), "SECURITY.md names {word}");
    }
}

/// The false alarm template SECURITY.md sends false positives to exists.
#[test]
fn the_false_alarm_template_the_policy_names_exists() {
    assert_says(&policy(), &["false alarm template"], "SECURITY.md");
    assert!(
        repo_root()
            .join(".github/ISSUE_TEMPLATE/false-alarm.md")
            .is_file(),
        "the repository has no false alarm template"
    );
}
