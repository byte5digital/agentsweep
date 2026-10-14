//! A Rule Pack release from the tag to the feed index: the version gate, the
//! signer, the verification command, the workflow that runs them and a dry
//! run of the whole with the development keys, all in temporary directories.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use agentsweep_core::pack::{Bands, MANIFEST_FILE, Manifest, PACK_TREES};
use agentsweep_core::pack_archive::ARCHIVE_FILE;
use agentsweep_core::pack_signature::{KeyRole, PINNED_KEYS, PinnedKey};
use agentsweep_xtask::pack_release::{self, SigningKey};
use agentsweep_xtask::repo_root;

const RELEASED: &str = "2026-10-14T08:00:00Z";

fn development_secret(role: KeyRole) -> String {
    let name = match role {
        KeyRole::Active => "rule-pack-development-active.secret",
        KeyRole::Standby => "rule-pack-development-standby.secret",
    };
    fs::read_to_string(repo_root().join("crates/core/development-keys").join(name))
        .expect("the development secret half")
}

fn development_key(role: KeyRole) -> SigningKey {
    SigningKey::read(&development_secret(role), None, "the development key").expect("it reads")
}

fn pinned(role: KeyRole) -> PinnedKey {
    *PINNED_KEYS
        .iter()
        .find(|key| key.role == role)
        .expect("both roles are pinned")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("a directory");
    for entry in fs::read_dir(from).expect("a readable tree") {
        let entry = entry.expect("an entry");
        if entry.file_name() == ".DS_Store" {
            continue;
        }
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("a copy");
        }
    }
}

/// The repository's pack copied into a temporary root and built into a
/// release directory beside it, unsigned.
fn an_unsigned_release(version: u64) -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let root = temporary.path().join("pack");
    for tree in PACK_TREES {
        copy_tree(&repo_root().join(tree), &root.join(tree));
    }
    let manifest =
        Manifest::of_pack(&root, version, "0.1.0", Bands::V1, RELEASED).expect("a manifest");
    let release = temporary.path().join("release");
    pack_release::write_release(&root, &manifest, &release).expect("a release");
    (temporary, release)
}

fn names_in(directory: &Path) -> BTreeSet<String> {
    fs::read_dir(directory)
        .expect("a directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The version gate
// ---------------------------------------------------------------------------

#[test]
fn the_gate_lets_a_version_newer_than_both_through() {
    assert_eq!(pack_release::gate("rules-v5", 1, Some(4)), Ok(5));
    assert_eq!(pack_release::gate("rules-v2", 1, None), Ok(2));
}

#[test]
fn the_gate_refuses_a_version_not_newer_than_the_bundled_pack_and_says_so() {
    for tag in ["rules-v3", "rules-v2"] {
        let refusal = pack_release::gate(tag, 3, Some(1)).expect_err("refused");
        assert!(
            refusal.contains("bundled Rule Pack, version 3"),
            "{refusal}"
        );
        assert!(!refusal.contains("feed index"), "{refusal}");
    }
}

#[test]
fn the_gate_refuses_a_version_not_newer_than_the_feed_index_and_says_so() {
    for tag in ["rules-v6", "rules-v4"] {
        let refusal = pack_release::gate(tag, 1, Some(6)).expect_err("refused");
        assert!(
            refusal.contains("pack version 6 the feed index holds"),
            "{refusal}"
        );
        assert!(!refusal.contains("bundled"), "{refusal}");
    }
}

/// The owner's decision 103: the first release publishes the bundled pack at
/// its own version, which the first feed index then points at. That is let
/// through only while no index exists.
#[test]
fn the_first_release_may_be_the_bundled_version_while_no_index_exists() {
    assert_eq!(pack_release::gate("rules-v1", 1, None), Ok(1));
    assert!(pack_release::gate("rules-v1", 1, Some(1)).is_err());
    assert!(pack_release::gate("rules-v1", 2, None).is_err());
}

#[test]
fn the_gate_refuses_a_tag_the_client_would_never_ask_for() {
    for tag in [
        "v0.1.0",
        "rules-v",
        "rules-v07",
        "rules-v1.1",
        "rules-vx",
        "rules-v-1",
    ] {
        let refusal = pack_release::gate(tag, 0, None).expect_err(tag);
        assert!(refusal.contains("not a Rule Pack release tag"), "{refusal}");
    }
}

/// The command the workflow runs: the index comes from a file, N alone is
/// printed, and a refusal is one sentence on stderr with a failing exit.
#[test]
fn the_gate_command_reads_the_index_from_a_file_and_prints_n() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let index = temporary.path().join("latest.json");
    fs::write(&index, pack_release::index_json(4)).expect("an index");
    let bundled = Manifest::bundled().pack_version;

    let newer = format!("rules-v{}", bundled.max(4) + 1);
    let output = xtask(&["pack-gate", &newer, "--index", path(&index)], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), format!("{}\n", bundled.max(4) + 1));

    let output = xtask(&["pack-gate", "rules-v4", "--index", path(&index)], &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("refused"), "{}", stderr(&output));
    assert!(stdout(&output).is_empty());
}

// ---------------------------------------------------------------------------
// Signing and verification
// ---------------------------------------------------------------------------

#[test]
fn a_release_signed_by_the_active_key_verifies_and_names_the_key() {
    let (_temporary, release) = an_unsigned_release(2);
    let ids = pack_release::sign(&release, &[development_key(KeyRole::Active)]).expect("signed");
    assert_eq!(ids, vec![pinned(KeyRole::Active).key_id()]);

    let verified = pack_release::verify(&release, &PINNED_KEYS).expect("it verifies");
    assert_eq!(verified.manifest.pack_version, 2);
    assert_eq!(verified.signed_by, vec![pinned(KeyRole::Active)]);
    assert!(verified.unpinned.is_empty());
    let report = verified.report();
    assert!(
        report.contains(&format!(
            "signed by the pinned active key {}",
            pinned(KeyRole::Active).key_id()
        )),
        "{report}"
    );
}

/// The signature is minisign's own: prehashed, named after the key that made
/// it, carrying minisign's trusted comment.
#[test]
fn the_signature_is_a_prehashed_minisign_signature_named_by_its_key_id() {
    let (_temporary, release) = an_unsigned_release(2);
    pack_release::sign(&release, &[development_key(KeyRole::Active)]).expect("signed");
    let id = pinned(KeyRole::Active).key_id();
    let text = fs::read_to_string(release.join(format!("{id}.minisig"))).expect("the signature");
    let signature = minisign::SignatureBox::from_string(&text).expect("a signature");
    assert!(signature.is_prehashed());
    assert!(
        signature
            .trusted_comment()
            .expect("a trusted comment")
            .contains("file:manifest.json"),
    );
    let public = minisign::PublicKey::from_base64(pinned(KeyRole::Active).public_key)
        .expect("the pinned key");
    let manifest = fs::read(release.join(MANIFEST_FILE)).expect("the manifest");
    minisign::verify(
        &public,
        &signature,
        std::io::Cursor::new(manifest),
        true,
        false,
        false,
    )
    .expect("minisign itself accepts it");
}

#[test]
fn a_manifest_altered_after_signing_is_refused() {
    let (_temporary, release) = an_unsigned_release(2);
    pack_release::sign(&release, &[development_key(KeyRole::Active)]).expect("signed");
    let path = release.join(MANIFEST_FILE);
    let text = fs::read_to_string(&path).expect("the manifest");
    fs::write(
        &path,
        text.replacen("\"pack_version\": 2", "\"pack_version\": 9", 1),
    )
    .expect("altered");
    let refusal = pack_release::verify(&release, &PINNED_KEYS).expect_err("refused");
    assert!(refusal.contains("does not verify"), "{refusal}");
}

#[test]
fn a_signature_renamed_to_another_key_id_is_refused() {
    let (_temporary, release) = an_unsigned_release(2);
    pack_release::sign(&release, &[development_key(KeyRole::Active)]).expect("signed");
    let active = release.join(format!("{}.minisig", pinned(KeyRole::Active).key_id()));

    // Renamed after the standby key, which did not make it.
    let standby = release.join(format!("{}.minisig", pinned(KeyRole::Standby).key_id()));
    fs::rename(&active, &standby).expect("renamed");
    let refusal = pack_release::verify(&release, &PINNED_KEYS).expect_err("refused");
    assert!(refusal.contains("was made by the key"), "{refusal}");

    // Renamed after a key nobody pins.
    let nobody = release.join("0123456789ABCDEF.minisig");
    fs::rename(&standby, &nobody).expect("renamed");
    assert!(pack_release::verify(&release, &PINNED_KEYS).is_err());
}

#[test]
fn a_release_signed_by_a_key_nobody_pins_is_refused() {
    let (_temporary, release) = an_unsigned_release(2);
    pack_release::sign(&release, &[development_key(KeyRole::Standby)]).expect("signed");
    let refusal = pack_release::verify(&release, &[pinned(KeyRole::Active)]).expect_err("refused");
    assert!(refusal.contains("no key this commit pins"), "{refusal}");
}

/// The release holds exactly the manifest, the signatures and the archive.
#[test]
fn a_release_with_anything_else_in_it_or_without_its_archive_is_refused() {
    let (_temporary, release) = an_unsigned_release(2);
    pack_release::sign(&release, &[development_key(KeyRole::Active)]).expect("signed");

    fs::write(release.join("notes.txt"), "hello").expect("a stray file");
    let refusal = pack_release::verify(&release, &PINNED_KEYS).expect_err("refused");
    assert!(refusal.contains("notes.txt"), "{refusal}");
    fs::remove_file(release.join("notes.txt")).expect("removed");

    let lower = release.join(format!(
        "{}.minisig",
        pinned(KeyRole::Active).key_id().to_lowercase()
    ));
    fs::write(&lower, "x").expect("a lower-case name");
    assert!(pack_release::verify(&release, &PINNED_KEYS).is_err());
    fs::remove_file(&lower).expect("removed");

    fs::remove_file(release.join(ARCHIVE_FILE)).expect("removed");
    let refusal = pack_release::verify(&release, &PINNED_KEYS).expect_err("refused");
    assert!(refusal.contains("no pack.tar"), "{refusal}");
}

#[test]
fn an_archive_that_is_not_what_the_signed_manifest_states_is_refused() {
    let (_temporary, release) = an_unsigned_release(2);
    pack_release::sign(&release, &[development_key(KeyRole::Active)]).expect("signed");
    let (_other, different) = an_unsigned_release(3);
    let mut archive = fs::read(different.join(ARCHIVE_FILE)).expect("an archive");
    archive.truncate(archive.len() / 2);
    fs::write(release.join(ARCHIVE_FILE), archive).expect("swapped");
    let refusal = pack_release::verify(&release, &PINNED_KEYS).expect_err("refused");
    assert!(refusal.contains("archive"), "{refusal}");
}

/// The rotation case of ADR 0006: two keys present, two signature files, and
/// a client that pins either key alone accepts the release.
#[test]
fn a_release_signed_by_two_keys_is_accepted_when_either_key_alone_is_pinned() {
    let (_temporary, release) = an_unsigned_release(2);
    let ids = pack_release::sign(
        &release,
        &[
            development_key(KeyRole::Active),
            development_key(KeyRole::Standby),
        ],
    )
    .expect("signed");
    assert_eq!(ids.len(), 2);
    let signatures: Vec<String> = names_in(&release)
        .into_iter()
        .filter(|name| name.ends_with(".minisig"))
        .collect();
    assert_eq!(signatures.len(), 2, "{signatures:?}");

    for role in [KeyRole::Active, KeyRole::Standby] {
        let verified = pack_release::verify(&release, &[pinned(role)]).expect("it verifies");
        assert_eq!(verified.signed_by, vec![pinned(role)]);
        assert_eq!(verified.unpinned.len(), 1, "the other key is carried");
        assert!(verified.report().contains("which this commit does not pin"));
    }
    let both = pack_release::verify(&release, &PINNED_KEYS).expect("it verifies");
    assert_eq!(both.signed_by.len(), 2);
}

#[test]
fn the_same_key_twice_is_refused() {
    let (_temporary, release) = an_unsigned_release(2);
    let refusal = pack_release::sign(
        &release,
        &[
            development_key(KeyRole::Active),
            development_key(KeyRole::Active),
        ],
    )
    .expect_err("refused");
    assert!(refusal.contains("present twice"), "{refusal}");
}

/// Every key present in the environment signs, in the order of the
/// variables; an absent or empty variable is no key.
#[test]
fn every_key_present_in_the_environment_signs() {
    let active = development_secret(KeyRole::Active);
    let standby = development_secret(KeyRole::Standby);
    let one = pack_release::keys_from(|name| match name {
        "RULE_PACK_SECRET_KEY" => Some(active.clone()),
        "RULE_PACK_NEXT_SECRET_KEY" => Some(String::new()),
        _ => None,
    })
    .expect("one key");
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].key_id(), pinned(KeyRole::Active).key_id());

    // The key's second line alone reads as well as the whole file.
    let second_line = standby.lines().nth(1).expect("a key line").to_string();
    let two = pack_release::keys_from(|name| match name {
        "RULE_PACK_SECRET_KEY" => Some(active.clone()),
        "RULE_PACK_NEXT_SECRET_KEY" => Some(second_line.clone()),
        _ => None,
    })
    .expect("two keys");
    let ids: Vec<&str> = two.iter().map(SigningKey::key_id).collect();
    assert_eq!(
        ids,
        vec![
            pinned(KeyRole::Active).key_id(),
            pinned(KeyRole::Standby).key_id()
        ]
    );
    assert_eq!(
        two[0].public_key().expect("a public half"),
        pinned(KeyRole::Active).public_key
    );
    assert!(!format!("{:?}", two[0]).contains(active.lines().nth(1).expect("a key line")));
}

/// An unencrypted key given a password is refused rather than signed with,
/// and the refusal never quotes the key or the password.
#[test]
fn a_password_for_a_key_that_has_none_is_refused_without_quoting_either() {
    let active = development_secret(KeyRole::Active);
    let refusal = pack_release::keys_from(|name| match name {
        "RULE_PACK_SECRET_KEY" => Some(active.clone()),
        "RULE_PACK_SECRET_KEY_PASSWORD" => Some("hunter2-not-real".to_string()),
        _ => None,
    })
    .expect_err("refused");
    assert!(refusal.contains("RULE_PACK_SECRET_KEY"), "{refusal}");
    assert!(!refusal.contains("hunter2-not-real"), "{refusal}");
    assert!(
        !refusal.contains(active.lines().nth(1).expect("a key line")),
        "{refusal}"
    );
}

// ---------------------------------------------------------------------------
// The commands, and the dry run
// ---------------------------------------------------------------------------

fn xtask(arguments: &[&str], environment: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentsweep-xtask"));
    command.args(arguments);
    for (key, _) in pack_release::KEY_VARIABLES {
        command.env_remove(key);
    }
    for (_, password) in pack_release::KEY_VARIABLES {
        command.env_remove(password);
    }
    for (key, value) in environment {
        command.env(key, value);
    }
    command.output().expect("the build tool runs")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The verification command reports which key signed a good release and
/// fails on a bad one, and on a release filed under another version.
#[test]
fn the_verification_command_reports_the_signing_key_and_refuses_a_bad_release() {
    let (_temporary, release) = an_unsigned_release(2);
    pack_release::sign(&release, &[development_key(KeyRole::Active)]).expect("signed");

    let output = xtask(&["pack-verify", path(&release), "--pack-version", "2"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains(&format!(
            "signed by the pinned active key {} (a development key)",
            pinned(KeyRole::Active).key_id()
        )),
        "{}",
        stdout(&output)
    );

    let output = xtask(&["pack-verify", path(&release), "--pack-version", "3"], &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("rules-v3"), "{}", stderr(&output));

    fs::write(release.join(MANIFEST_FILE), "{}\n").expect("altered");
    let output = xtask(&["pack-verify", path(&release)], &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("refused"), "{}", stderr(&output));
}

/// The dry run: the steps of the workflow after the gate, run as the workflow
/// runs them with the development keys in the environment, leave the release
/// layout and the index file in a temporary directory and nothing else.
#[test]
fn the_dry_run_with_the_development_keys_produces_the_release_and_the_index_and_nothing_else() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let release = temporary.path().join("rule-pack-release");
    let index = temporary.path().join("rule-pack-index");
    let version = (Manifest::bundled().pack_version + 1).to_string();
    let active = development_secret(KeyRole::Active);
    let standby = development_secret(KeyRole::Standby);

    let gate = xtask(&["pack-gate", &format!("rules-v{version}")], &[]);
    assert!(gate.status.success(), "{}", stderr(&gate));
    assert_eq!(stdout(&gate).trim(), version);

    type Step<'a> = (Vec<&'a str>, Vec<(&'a str, &'a str)>);
    let steps: [Step<'_>; 4] = [
        (
            vec!["pack", "--pack-version", &version, "--out", path(&release)],
            vec![],
        ),
        (
            vec!["pack-sign", path(&release)],
            vec![
                ("RULE_PACK_SECRET_KEY", active.as_str()),
                ("RULE_PACK_NEXT_SECRET_KEY", standby.as_str()),
            ],
        ),
        (
            vec!["pack-verify", path(&release), "--pack-version", &version],
            vec![],
        ),
        (vec!["pack-index", &version, "--out", path(&index)], vec![]),
    ];
    for (arguments, environment) in steps {
        let output = xtask(&arguments, &environment);
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            stderr(&output)
        );
        assert!(!stdout(&output).contains(active.lines().nth(1).expect("a key line")));
    }

    assert_eq!(
        names_in(temporary.path()),
        BTreeSet::from([
            "rule-pack-index".to_string(),
            "rule-pack-release".to_string()
        ])
    );
    let mut expected = BTreeSet::from([MANIFEST_FILE.to_string(), ARCHIVE_FILE.to_string()]);
    for role in [KeyRole::Active, KeyRole::Standby] {
        expected.insert(format!("{}.minisig", pinned(role).key_id()));
    }
    assert_eq!(names_in(&release), expected);
    assert_eq!(
        names_in(&index),
        BTreeSet::from([pack_release::INDEX_FILE.to_string()])
    );
    assert_eq!(
        fs::read_to_string(index.join(pack_release::INDEX_FILE)).expect("the index"),
        format!("{{\"pack_version\": {version}}}\n")
    );
}

// ---------------------------------------------------------------------------
// The workflow
// ---------------------------------------------------------------------------

fn workflow_text() -> String {
    fs::read_to_string(repo_root().join(".github/workflows/rule-pack-release.yml"))
        .expect("the Rule Pack release workflow")
}

/// The first line holding `needle`, counted from zero.
fn line_of(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("the workflow has no line with `{needle}`"))
}

/// The steps run in the order the ticket asks: the gate, every Fixture, the
/// build, the signature, the verification, the attestation, the release, and
/// only then the index commit.
#[test]
fn the_workflow_publishes_the_release_before_it_points_the_index_at_it() {
    let text = workflow_text();
    let order = [
        "cargo build -p agentsweep-xtask --locked",
        "\"${XTASK}\" pack-gate",
        "\"${XTASK}\" corpus",
        "\"${XTASK}\" pack --pack-version",
        "\"${XTASK}\" pack-sign",
        "\"${XTASK}\" pack-verify",
        "actions/attest-build-provenance@",
        "--method POST \"repos/${GITHUB_REPOSITORY}/releases\"",
        "gh release upload",
        "-F draft=false",
        "\"${XTASK}\" pack-index",
        "git push origin \"${commit}:refs/heads/feed\"",
    ];
    let lines: Vec<usize> = order.iter().map(|needle| line_of(&text, needle)).collect();
    for (pair, needles) in lines.windows(2).zip(order.windows(2)) {
        assert!(
            pair[0] < pair[1],
            "`{}` must come before `{}`",
            needles[0],
            needles[1]
        );
    }
}

/// The release is never the latest release, neither when it is created nor
/// when its draft is published, and it carries exactly the three kinds of
/// asset.
#[test]
fn the_workflow_uploads_exactly_the_three_kinds_of_asset_and_never_makes_the_release_latest() {
    let text = workflow_text();
    assert_eq!(text.matches("-f make_latest=false").count(), 2);
    assert!(!text.contains("make_latest=true"));
    let upload = line_of(&text, "gh release upload");
    let mut assets: Vec<&str> = Vec::new();
    for line in text.lines().skip(upload + 1) {
        assets.push(line.trim());
        if !line.trim_end().ends_with('\\') {
            break;
        }
    }
    assert_eq!(
        assets,
        vec![
            "\"${RELEASE_DIR}/manifest.json\" \\",
            "\"${RELEASE_DIR}\"/*.minisig \\",
            "\"${RELEASE_DIR}/pack.tar\"",
        ]
    );
}

/// The workflow passes every pipeline hardening rule, and the rule that
/// keeps a Rule Pack release from becoming the latest release does see its
/// release step: without `make_latest=false` it fails.
#[test]
fn the_workflow_passes_every_hardening_rule_and_the_release_step_is_seen() {
    use agentsweep_xtask::workflows::{HardeningRule, Workflow};

    let text = workflow_text();
    let workflow = Workflow::parse("rule-pack-release.yml", &text).expect("it reads");
    for rule in HardeningRule::ALL {
        assert_eq!(rule.check(&workflow), Vec::new(), "{rule}");
    }

    let creating = text.replacen("            -f make_latest=false \\\n", "", 1);
    assert_ne!(creating, text);
    let broken = Workflow::parse("rule-pack-release.yml", &creating).expect("it reads");
    let violations = HardeningRule::RulePackNotLatest.check(&broken);
    assert_eq!(violations.len(), 1, "{violations:?}");
}

/// Only the signing step sees a secret, the build tool is compiled before
/// it, and the workspace under the runner's temporary directory is removed
/// whatever the outcome.
#[test]
fn only_the_signing_step_sees_a_secret_and_the_workspace_is_always_removed() {
    let text = workflow_text();
    let secrets: Vec<usize> = text
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("secrets."))
        .map(|(index, _)| index)
        .collect();
    let signing = line_of(&text, "name: Sign the manifest");
    let verifying = line_of(&text, "name: Verify the signed release");
    assert_eq!(secrets.len(), 4);
    assert!(
        secrets
            .iter()
            .all(|line| *line > signing && *line < verifying)
    );
    for (key, password) in pack_release::KEY_VARIABLES {
        assert!(text.contains(&format!("{key}: ${{{{ secrets.{key} }}}}")));
        assert!(text.contains(&format!("{password}: ${{{{ secrets.{password} }}}}")));
    }
    assert!(line_of(&text, "cargo build -p agentsweep-xtask --locked") < signing);
    let cleanup = line_of(&text, "if: always()");
    assert!(cleanup > line_of(&text, "refs/heads/feed"));
    assert!(
        text.lines()
            .nth(cleanup + 1)
            .expect("the cleanup")
            .contains("rm -rf")
    );
    assert!(!text.contains("set -x"));
}
