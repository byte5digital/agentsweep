//! The app release workflow and the scripts it drives (spec sections 9.1 and
//! 9.2), each script run on temporary inputs: the version gate, the staging of
//! the release assets and the updater manifest `latest.json`, the last
//! against good and bad sample files. The workflow itself cannot run here; its
//! text is held to what a release must do: a draft only, the prerelease flag
//! from the tag, attestations, the asset listing, the temporary keychain and
//! no secret echoed. The pipeline hardening rules of `workflows.rs` cover it
//! like every other workflow.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use agentsweep_xtask::repo_root;
use tempfile::TempDir;

fn script(name: &str) -> PathBuf {
    repo_root().join(".github/scripts").join(name)
}

fn run(name: &str, arguments: &[&str]) -> Output {
    Command::new(script(name))
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).expect("a directory");
    fs::write(path, text).expect("a file");
}

/// A temporary repository root with a workspace version and the manifests of
/// the app, the daemon and the CLI, each taking the workspace version.
fn workspace(version: &str) -> TempDir {
    let root = TempDir::new().expect("a temporary directory");
    write(
        &root.path().join("Cargo.toml"),
        &format!(
            "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"{version}\"\nedition = \"2024\"\n\n[workspace.dependencies]\nother = {{ version = \"9.9.9\" }}\n"
        ),
    );
    for member in ["apps/menubar", "crates/daemon", "crates/cli"] {
        write(
            &root.path().join(member).join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion.workspace = true\n",
        );
    }
    root
}

fn gate(tag: &str, root: &Path) -> Output {
    run(
        "release-version-gate.sh",
        &[tag, root.to_str().expect("a UTF-8 path")],
    )
}

#[test]
fn the_gate_passes_a_tag_naming_the_workspace_version() {
    let root = workspace("0.3.1");
    let output = gate("v0.3.1", root.path());
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "version=0.3.1\nprerelease=false\n");
}

#[test]
fn the_gate_refuses_a_tag_naming_another_version_with_a_sentence_naming_both() {
    let root = workspace("0.1.0");
    let output = gate("v0.2.0", root.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty(), "nothing for GITHUB_OUTPUT");
    let message = stderr(&output);
    assert!(
        message.contains("names version 0.2.0") && message.contains("workspace version is 0.1.0"),
        "{message}"
    );
}

#[test]
fn the_gate_makes_a_prerelease_of_a_tag_with_a_prerelease_suffix() {
    let root = workspace("0.2.0-rc.1");
    let output = gate("v0.2.0-rc.1", root.path());
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "version=0.2.0-rc.1\nprerelease=true\n");
}

#[test]
fn the_gate_refuses_an_rc_tag_over_a_final_workspace_version() {
    // An rc build that called itself 0.1.0 would never be offered 0.1.0.
    let root = workspace("0.1.0");
    let output = gate("v0.1.0-rc.1", root.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("names version 0.1.0-rc.1"));
}

#[test]
fn the_gate_refuses_a_tag_that_is_not_v_and_a_semantic_version() {
    let root = workspace("0.1.0");
    for tag in [
        "0.1.0",
        "v0.1",
        "v01.0.0",
        "v0.1.0+build.1",
        "v0.1.0-rc..1",
        "v0.1.0-",
        "vx.y.z",
    ] {
        let output = gate(tag, root.path());
        assert_eq!(output.status.code(), Some(1), "{tag} passed");
        assert!(stderr(&output).contains(tag), "{tag}: {}", stderr(&output));
    }
}

#[test]
fn the_gate_refuses_when_a_member_does_not_take_the_workspace_version() {
    let root = workspace("0.1.0");
    write(
        &root.path().join("crates/daemon/Cargo.toml"),
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
    );
    let output = gate("v0.1.0", root.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("crates/daemon"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_gate_passes_the_repository_at_its_own_version() {
    let manifest = fs::read_to_string(repo_root().join("Cargo.toml")).expect("Cargo.toml");
    let version = manifest
        .lines()
        .skip_while(|line| *line != "[workspace.package]")
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("a workspace version");
    let output = gate(&format!("v{version}"), &repo_root());
    assert!(output.status.success(), "{}", stderr(&output));
}

// The staging of the release assets.

fn bundle(dmgs: &[&str]) -> TempDir {
    let bundle = TempDir::new().expect("a temporary directory");
    write(
        &bundle.path().join("macos/AgentSweep.app.tar.gz"),
        "archive",
    );
    write(
        &bundle.path().join("macos/AgentSweep.app.tar.gz.sig"),
        "signature",
    );
    for dmg in dmgs {
        write(&bundle.path().join("dmg").join(dmg), "dmg");
    }
    bundle
}

#[test]
fn staging_names_each_asset_for_the_version_and_the_architecture() {
    let bundle = bundle(&["AgentSweep_0.1.0_universal.dmg"]);
    let out = TempDir::new().expect("a temporary directory");
    let release = out.path().join("release");
    let output = run(
        "stage-release-assets.sh",
        &[
            bundle.path().to_str().unwrap(),
            "0.1.0",
            "universal",
            release.to_str().unwrap(),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "dmg=AgentSweep_0.1.0_universal.dmg\n\
         archive=AgentSweep_0.1.0_universal.app.tar.gz\n\
         signature=AgentSweep_0.1.0_universal.app.tar.gz.sig\n"
    );
    let read = |name: &str| fs::read_to_string(release.join(name)).expect(name);
    assert_eq!(read("AgentSweep_0.1.0_universal.dmg"), "dmg");
    assert_eq!(read("AgentSweep_0.1.0_universal.app.tar.gz"), "archive");
    assert_eq!(
        read("AgentSweep_0.1.0_universal.app.tar.gz.sig"),
        "signature"
    );
}

#[test]
fn staging_refuses_a_bundle_without_exactly_one_dmg() {
    for dmgs in [&[][..], &["a.dmg", "b.dmg"][..]] {
        let bundle = bundle(dmgs);
        let out = TempDir::new().expect("a temporary directory");
        let output = run(
            "stage-release-assets.sh",
            &[
                bundle.path().to_str().unwrap(),
                "0.1.0",
                "universal",
                out.path().to_str().unwrap(),
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{dmgs:?}");
        assert!(stderr(&output).contains("exactly one DMG"));
    }
}

// The DMG's own signature.

#[cfg(target_os = "macos")]
#[test]
fn an_unsigned_dmg_is_signed_ad_hoc_and_a_signed_one_left_alone() {
    let work = TempDir::new().expect("a temporary directory");
    write(&work.path().join("content/readme.txt"), "fixture");
    let dmg = work.path().join("fixture.dmg");
    let created = Command::new("hdiutil")
        .args([
            "create",
            "-quiet",
            "-fs",
            "HFS+",
            "-volname",
            "Fixture",
            "-srcfolder",
        ])
        .arg(work.path().join("content"))
        .arg(&dmg)
        .status()
        .expect("hdiutil");
    assert!(created.success());
    let verify = || {
        Command::new("codesign")
            .arg("--verify")
            .arg(&dmg)
            .output()
            .expect("codesign")
            .status
            .success()
    };
    assert!(!verify(), "hdiutil makes an unsigned DMG");
    let first = run("sign-unsigned-dmg.sh", &["-", dmg.to_str().unwrap()]);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(stdout(&first).contains("fixture.dmg signed"));
    assert!(verify());
    let second = run("sign-unsigned-dmg.sh", &["-", dmg.to_str().unwrap()]);
    assert!(second.status.success(), "{}", stderr(&second));
    assert!(stdout(&second).contains("signed already"));
}

// The updater manifest. `plutil` reads JSON, and the release runs on macOS.

const ARCHIVE_URL: &str = "https://releases.invalid/v0.1.0/AgentSweep_0.1.0_universal.app.tar.gz";

fn manifest_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/updater-manifest-fixtures")
}

fn json_files(directory: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(directory)
        .expect("a fixture directory")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    files
}

fn check_manifest(manifest: &Path, signature: &Path) -> Output {
    run(
        "updater-manifest.sh",
        &[
            "check",
            manifest.to_str().unwrap(),
            "0.1.0",
            ARCHIVE_URL,
            signature.to_str().unwrap(),
        ],
    )
}

#[cfg(target_os = "macos")]
#[test]
fn the_manifest_check_passes_every_good_sample() {
    let signature = manifest_fixtures().join("archive.sig");
    let good = json_files(&manifest_fixtures().join("good"));
    assert!(!good.is_empty());
    for sample in good {
        let output = check_manifest(&sample, &signature);
        assert!(
            output.status.success(),
            "{}: {}",
            sample.display(),
            stderr(&output)
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn the_manifest_check_fails_every_bad_sample() {
    let signature = manifest_fixtures().join("archive.sig");
    let bad = json_files(&manifest_fixtures().join("bad"));
    assert!(bad.len() >= 8);
    for sample in bad {
        let output = check_manifest(&sample, &signature);
        assert_eq!(output.status.code(), Some(1), "{} passed", sample.display());
        assert!(
            stderr(&output).contains(sample.to_str().unwrap()),
            "{}: {}",
            sample.display(),
            stderr(&output)
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn a_written_manifest_names_one_archive_for_both_darwin_keys_and_passes_the_check() {
    let out = TempDir::new().expect("a temporary directory");
    let signature = manifest_fixtures().join("archive.sig");
    let manifest = out.path().join("latest.json");
    let output = run(
        "updater-manifest.sh",
        &[
            "write",
            "0.1.0",
            ARCHIVE_URL,
            signature.to_str().unwrap(),
            manifest.to_str().unwrap(),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest).expect("latest.json")).expect("JSON");
    let signature_text = fs::read_to_string(&signature).expect("a signature");
    for platform in ["darwin-aarch64", "darwin-x86_64"] {
        assert_eq!(written["platforms"][platform]["url"], ARCHIVE_URL);
        assert_eq!(
            written["platforms"][platform]["signature"],
            signature_text.trim()
        );
    }
    assert_eq!(written["version"], "0.1.0");
    assert!(
        written["pub_date"]
            .as_str()
            .is_some_and(|date| date.ends_with('Z'))
    );
    assert!(check_manifest(&manifest, &signature).status.success());
}

#[test]
fn the_manifest_writer_refuses_an_empty_signature_file() {
    let out = TempDir::new().expect("a temporary directory");
    let signature = out.path().join("empty.sig");
    write(&signature, "");
    let output = run(
        "updater-manifest.sh",
        &[
            "write",
            "0.1.0",
            ARCHIVE_URL,
            signature.to_str().unwrap(),
            out.path().join("latest.json").to_str().unwrap(),
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(!out.path().join("latest.json").exists());
}

// The workflow's text.

fn workflow() -> String {
    fs::read_to_string(repo_root().join(".github/workflows/app-release.yml"))
        .expect("the app release workflow")
}

/// The `run:` blocks and `with:` values of the step named `name`, as text.
fn step(name: &str) -> String {
    let text = workflow();
    let start = text
        .find(&format!("- name: {name}"))
        .unwrap_or_else(|| panic!("no step named {name}"));
    let rest = &text[start + 2..];
    let end = rest.find("\n      - name: ").unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn the_workflow_is_started_by_a_v_tag_push_alone_and_enters_the_release_environment() {
    let text = workflow();
    let on =
        &text[text.find("\non:\n").expect("an on block")..text.find("\npermissions:").unwrap()];
    assert_eq!(
        on.lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>(),
        ["on:", "  push:", "    tags:", "      - \"v*\""]
    );
    assert!(text.contains("    environment:\n      name: release\n"));
}

#[test]
fn the_release_is_always_a_draft_and_a_prerelease_when_the_tag_says_so() {
    let draft = step("Create the draft release");
    assert!(draft.contains("-F draft=true"));
    assert!(!draft.contains("draft=false"));
    assert!(draft.contains("PRERELEASE: ${{ steps.gate.outputs.prerelease }}"));
    assert!(draft.contains("-F prerelease=\"${PRERELEASE}\""));
    assert!(
        !workflow().contains("releaseDraft"),
        "tauri-action makes no release"
    );
    assert!(
        !workflow().contains("tagName"),
        "tauri-action makes no release"
    );
}

#[test]
fn every_check_runs_before_the_draft_exists() {
    let text = workflow();
    let draft = text.find("- name: Create the draft release").unwrap();
    for earlier in [
        "- name: Hold the tag to the version gate",
        "- name: Notarize and staple the DMG",
        "- name: Check the app, the DMG and the updater archive with the release bundle checker",
        "- name: Write and check latest.json",
        "- name: Attest the DMG and the updater archive",
    ] {
        assert!(text.find(earlier).expect(earlier) < draft, "{earlier}");
    }
    let checker =
        step("Check the app, the DMG and the updater archive with the release bundle checker");
    assert!(checker.contains("check-bundle-signature.sh \"${APPLE_SIGNING_IDENTITY}\""));
}

#[test]
fn the_workflow_attests_the_dmg_and_the_updater_archive() {
    let attest = step("Attest the DMG and the updater archive");
    assert!(attest.contains("uses: actions/attest-build-provenance@"));
    assert!(attest.contains("${{ env.RELEASE_DIR }}/${{ steps.stage.outputs.dmg }}"));
    assert!(attest.contains("${{ env.RELEASE_DIR }}/${{ steps.stage.outputs.archive }}"));
}

#[test]
fn the_workflow_lists_the_drafts_assets_and_fails_without_all_four() {
    let check = step("Check the assets of the draft");
    assert!(check.contains("releases/${RELEASE_ID}"));
    assert!(
        check.contains("for name in \"${DMG}\" \"${ARCHIVE}\" \"${SIGNATURE}\" latest.json; do")
    );
    assert!(check.contains("exit \"${status}\""));
    let upload = step("Create the draft release");
    for asset in ["${DMG}", "${ARCHIVE}", "${SIGNATURE}", "latest.json"] {
        assert!(
            upload.contains(&format!("\"${{RELEASE_DIR}}/{asset}\"")),
            "{asset}"
        );
    }
}

#[test]
fn the_certificate_goes_into_a_temporary_keychain_deleted_in_an_always_step() {
    let import = step("Import the certificate into a temporary keychain");
    assert!(import.contains("security create-keychain"));
    assert!(import.contains("security import \"${certificate}\" -k \"${KEYCHAIN}\""));
    assert!(import.contains("rm -f \"${certificate}\""));
    let cleanup = step("Delete the temporary keychain, the API key file and the release workspace");
    assert!(cleanup.contains("if: always()"));
    assert!(cleanup.contains("security delete-keychain \"${KEYCHAIN}\""));
    assert!(cleanup.contains("rm -f \"${APPLE_API_KEY_PATH}\""));
    assert!(
        workflow().trim_end().ends_with(cleanup.trim_end()),
        "the last step"
    );
}

#[test]
fn no_step_echoes_a_secret() {
    let text = workflow();
    let mut secret_variables = Vec::new();
    for line in text.lines() {
        if !line.contains("secrets.") {
            continue;
        }
        // A secret only ever reaches a step as an env value of its own.
        let (key, value) = line
            .trim()
            .split_once(": ")
            .unwrap_or_else(|| panic!("a secret outside an env value: {line}"));
        assert!(
            value.starts_with("${{ secrets.") && value.ends_with(" }}"),
            "a secret outside an env value: {line}"
        );
        secret_variables.push(key.to_string());
    }
    assert!(secret_variables.len() >= 8, "{secret_variables:?}");
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let prints = words
            .iter()
            .any(|word| ["echo", "printf"].contains(word) || word.ends_with("$(echo"));
        if !prints {
            continue;
        }
        for variable in &secret_variables {
            if line.contains(&format!("${{{variable}}}")) {
                assert!(
                    line.contains("| base64 --decode >")
                        || line.contains("> \"${APPLE_API_KEY_PATH}\""),
                    "a secret printed to the log: {line}"
                );
            }
        }
    }
}
