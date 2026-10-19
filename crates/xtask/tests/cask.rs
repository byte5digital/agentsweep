//! The Homebrew cask and the workflow that bumps it in the tap (spec sections
//! 1, 9.2, 9.4 and 9.6). The tag filter runs on sample release event payloads
//! and the renderer on a temporary DMG; the rendered cask is compared with a
//! committed expected cask. The workflow itself cannot run here; its text is
//! held to what the bump must do: act on a plain `v<semver>` release alone,
//! verify the DMG's attestation before its digest is taken, and read the tap
//! token only behind the `release` environment. The pipeline hardening rules
//! of `workflows.rs` cover it like every other workflow.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use agentsweep_xtask::repo_root;
use agentsweep_xtask::workflows::{self, HardeningRule};
use tempfile::TempDir;

const WORKFLOW: &str = "cask-bump.yml";

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

fn expected_cask() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cask-fixtures/agentsweep-0.1.0.rb"),
    )
    .expect("the committed expected cask")
}

// The tag filter, on sample release event payloads.

/// A temporary release event payload, shaped as GitHub sends it for the
/// `release` event: the fields the filter reads and some it does not.
fn event(tag: &str, prerelease: bool, draft: bool) -> TempDir {
    let directory = TempDir::new().expect("a temporary directory");
    let payload = format!(
        r#"{{
  "action": "published",
  "release": {{
    "id": 1,
    "tag_name": "{tag}",
    "name": "AgentSweep",
    "draft": {draft},
    "prerelease": {prerelease},
    "assets": []
  }},
  "repository": {{ "full_name": "byte5digital/agentsweep" }}
}}
"#
    );
    fs::write(directory.path().join("event.json"), payload).expect("a payload");
    directory
}

fn filter(tag: &str, prerelease: bool, draft: bool) -> Output {
    let payload = event(tag, prerelease, draft);
    run(
        "cask-bump-gate.sh",
        &[payload.path().join("event.json").to_str().unwrap()],
    )
}

fn assert_skipped(output: &Output, why: &str) {
    assert!(output.status.success(), "{}", stderr(output));
    assert_eq!(stdout(output), "bump=false\n");
    assert!(stderr(output).contains(why), "{}", stderr(output));
}

#[test]
fn a_plain_v_tag_bumps_the_cask() {
    let output = filter("v0.1.0", false, false);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "bump=true\nversion=0.1.0\ntag=v0.1.0\n");
}

#[test]
fn a_prerelease_does_not_bump_the_cask() {
    assert_skipped(&filter("v0.2.0-rc.1", true, false), "v0.2.0-rc.1");
    // A prerelease tag published without GitHub's prerelease flag still
    // does not reach the tap: the tag decides.
    assert_skipped(&filter("v0.2.0-rc.1", false, false), "v0.2.0-rc.1");
    // And the flag decides as well: a plain tag marked prerelease by hand.
    assert_skipped(&filter("v0.2.0", true, false), "prerelease");
}

#[test]
fn a_rule_pack_release_does_not_bump_the_cask() {
    assert_skipped(&filter("rules-v7", false, false), "rules-v7");
}

#[test]
fn a_draft_never_bumps_the_cask() {
    assert_skipped(&filter("v0.1.0", false, true), "draft");
}

#[test]
fn a_tag_that_is_not_a_semantic_version_does_not_bump_the_cask() {
    for tag in [
        "0.1.0",
        "v0.1",
        "v01.0.0",
        "v0.1.0+build.1",
        "vx.y.z",
        "v0.1.0-",
    ] {
        assert_skipped(&filter(tag, false, false), tag);
    }
}

#[test]
fn a_payload_without_a_release_fails() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = directory.path().join("event.json");
    fs::write(&path, "{\"action\": \"published\"}\n").expect("a payload");
    let output = run("cask-bump-gate.sh", &[path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty(), "nothing for GITHUB_OUTPUT");
}

// The renderer, on a temporary DMG.

/// A temporary stand-in DMG whose digest the expected cask carries.
fn dmg(version: &str) -> (TempDir, PathBuf) {
    let directory = TempDir::new().expect("a temporary directory");
    let path = directory
        .path()
        .join(format!("AgentSweep_{version}_universal.dmg"));
    fs::write(&path, "stand-in disk image\n").expect("a DMG");
    (directory, path)
}

fn render(version: &str, dmg: &Path) -> Output {
    run("render-cask.sh", &[version, dmg.to_str().unwrap()])
}

fn rendered(version: &str) -> String {
    let (_directory, path) = dmg(version);
    let output = render(version, &path);
    assert!(output.status.success(), "{}", stderr(&output));
    stdout(&output)
}

#[test]
fn the_rendered_cask_is_the_committed_expected_cask() {
    assert_eq!(rendered("0.1.0"), expected_cask());
}

#[test]
fn the_rendered_version_url_and_digest_match_the_dmg() {
    let (directory, path) = dmg("0.4.2");
    let output = render("0.4.2", &path);
    assert!(output.status.success(), "{}", stderr(&output));
    let cask = stdout(&output);

    let digest = Command::new("shasum")
        .args(["-a", "256", path.to_str().unwrap()])
        .output()
        .expect("shasum");
    let digest = stdout(&digest);
    let digest = digest.split_whitespace().next().expect("a digest");

    assert!(cask.contains("\n  version \"0.4.2\"\n"), "{cask}");
    assert!(
        cask.contains(&format!("\n  sha256 \"{digest}\"\n")),
        "{cask}"
    );

    // The url, with its interpolated version resolved, names the DMG the app
    // release stages on the GitHub release under the `v<version>` tag.
    let url = cask
        .lines()
        .find_map(|line| line.trim().strip_prefix("url \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("a url")
        .replace("#{version}", "0.4.2");
    let bundle = directory.path().join("bundle");
    fs::create_dir_all(bundle.join("macos")).unwrap();
    fs::create_dir_all(bundle.join("dmg")).unwrap();
    fs::write(bundle.join("macos/AgentSweep.app.tar.gz"), "archive").unwrap();
    fs::write(bundle.join("macos/AgentSweep.app.tar.gz.sig"), "signature").unwrap();
    fs::write(bundle.join("dmg/AgentSweep_0.4.2_universal.dmg"), "dmg").unwrap();
    let staged = run(
        "stage-release-assets.sh",
        &[
            bundle.to_str().unwrap(),
            "0.4.2",
            "universal",
            directory.path().join("release").to_str().unwrap(),
        ],
    );
    assert!(staged.status.success(), "{}", stderr(&staged));
    let staged = stdout(&staged);
    let staged_dmg = staged
        .lines()
        .find_map(|line| line.strip_prefix("dmg="))
        .expect("a staged DMG");
    assert_eq!(
        url,
        format!("https://github.com/byte5digital/agentsweep/releases/download/v0.4.2/{staged_dmg}")
    );
}

#[test]
fn the_cask_has_exactly_the_stanzas_the_ticket_lists() {
    let cask = rendered("0.1.0");
    let stanzas: Vec<&str> = cask
        .lines()
        .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
        .filter_map(|line| line.split_whitespace().next())
        .filter(|word| !word.starts_with('"') && *word != "]")
        .collect();
    assert_eq!(
        stanzas,
        [
            "version",
            "sha256",
            "url",
            "name",
            "desc",
            "homepage",
            "auto_updates",
            "depends_on",
            "app",
            "binary",
            "uninstall",
            "zap",
        ]
    );
    assert!(cask.contains("\n  auto_updates true\n"));
    assert!(cask.contains("\n  depends_on macos: :sonoma\n"));
    assert!(cask.contains("\n  app \"AgentSweep.app\"\n"));
    // The in-bundle CLI, the Tauri sidecar named `agentsweep` (ADR 0008).
    assert!(cask.contains("\n  binary \"#{appdir}/AgentSweep.app/Contents/MacOS/agentsweep\"\n"));
    assert!(cask.contains("uninstall launchctl: \"de.byte5.agentsweep.daemon\",\n"));
    assert!(cask.contains("quit:      \"de.byte5.agentsweep\"\n"));
    for absent in ["postflight", "preflight", "delete:", "rmdir:", "livecheck"] {
        assert!(!cask.contains(absent), "{absent}");
    }
}

#[test]
fn the_daemon_label_in_the_cask_is_the_one_the_bundle_registers() {
    let plist = fs::read_to_string(
        repo_root().join("apps/menubar/LaunchAgents/de.byte5.agentsweep.daemon.plist"),
    )
    .expect("the daemon's launch agent");
    assert!(plist.contains("<string>de.byte5.agentsweep.daemon</string>"));
    assert!(rendered("0.1.0").contains("launchctl: \"de.byte5.agentsweep.daemon\""));
}

/// The paths of the cask's `zap trash:` list.
fn zap_paths(cask: &str) -> Vec<String> {
    let start = cask.find("  zap trash: [\n").expect("a zap trash list");
    let rest = &cask[start..];
    let end = rest.find("\n  ]\n").expect("the end of the zap list");
    rest[..end]
        .lines()
        .skip(1)
        .map(|line| {
            line.trim()
                .trim_end_matches(',')
                .trim_matches('"')
                .to_string()
        })
        .collect()
}

#[test]
fn the_zap_list_names_the_documented_paths_and_nothing_outside_the_users_library() {
    let cask = rendered("0.1.0");
    assert_eq!(cask.matches("zap ").count(), 1);
    let paths = zap_paths(&cask);
    for path in &paths {
        assert!(path.starts_with("~/Library/"), "{path}");
        assert!(!path.contains(".."), "{path}");
        assert!(
            path.contains("de.byte5.agentsweep") || path.ends_with("/AgentSweep"),
            "{path} is not AgentSweep's own"
        );
    }
    // Spec section 6.9 names the data directory and the log directory; the
    // rest is what Delete everything removes beside them (spec section 9.6):
    // the caches, the web view's and the HTTP storage, the preferences and
    // the saved window state. The Keychain items are not files and stay with
    // Delete everything.
    assert_eq!(
        paths,
        [
            "~/Library/Application Support/de.byte5.agentsweep",
            "~/Library/Caches/de.byte5.agentsweep",
            "~/Library/HTTPStorages/de.byte5.agentsweep",
            "~/Library/Logs/AgentSweep",
            "~/Library/Preferences/de.byte5.agentsweep.plist",
            "~/Library/Saved Application State/de.byte5.agentsweep.savedState",
            "~/Library/WebKit/de.byte5.agentsweep",
        ]
    );
}

#[test]
fn the_rendered_cask_is_valid_ruby() {
    let directory = TempDir::new().expect("a temporary directory");
    let path = directory.path().join("agentsweep.rb");
    fs::write(&path, rendered("0.1.0")).expect("a cask");
    let output = Command::new("ruby")
        .args(["-c", path.to_str().unwrap()])
        .output()
        .expect("ruby");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn the_renderer_refuses_a_prerelease_version() {
    let (_directory, path) = dmg("0.2.0-rc.1");
    let output = render("0.2.0-rc.1", &path);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
    assert!(
        stderr(&output).contains("0.2.0-rc.1"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_renderer_refuses_a_missing_or_empty_dmg() {
    let directory = TempDir::new().expect("a temporary directory");
    let missing = directory.path().join("AgentSweep_0.1.0_universal.dmg");
    let output = render("0.1.0", &missing);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());

    fs::write(&missing, "").unwrap();
    let output = render("0.1.0", &missing);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
}

// The workflow's text.

fn workflow() -> String {
    fs::read_to_string(repo_root().join(".github/workflows").join(WORKFLOW))
        .expect("the cask bump workflow")
}

/// The text of the step named `name`, up to the next step or job.
fn step(name: &str) -> String {
    let text = workflow();
    let start = text
        .find(&format!("- name: {name}\n"))
        .unwrap_or_else(|| panic!("no step named {name}"));
    let rest = &text[start + 2..];
    let end = [rest.find("\n      - name: "), rest.find("\n  bump:\n")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

/// The text of the job `name`, up to the next job.
fn job(name: &str) -> String {
    let text = workflow();
    let start = text
        .find(&format!("\n  {name}:\n"))
        .unwrap_or_else(|| panic!("no job named {name}"))
        + 1;
    let mut end = start;
    for (index, line) in text[start..].split_inclusive('\n').enumerate() {
        let another_job = line.starts_with("  ")
            && line[2..].starts_with(|c: char| !c.is_whitespace() && c != '#');
        if index > 0 && another_job {
            break;
        }
        end += line.len();
    }
    text[start..end].to_string()
}

#[test]
fn the_workflow_passes_every_pipeline_hardening_rule() {
    let directory = TempDir::new().expect("a temporary directory");
    fs::copy(
        repo_root().join(".github/workflows").join(WORKFLOW),
        directory.path().join(WORKFLOW),
    )
    .expect("a copy");
    for rule in [
        HardeningRule::PinnedActions,
        HardeningRule::LockedCargo,
        HardeningRule::ReleaseReach,
        HardeningRule::RulePackNotLatest,
    ] {
        let violations = workflows::check_directory(directory.path(), rule).expect("a check");
        assert!(violations.is_empty(), "{rule}: {violations:?}");
    }
}

#[test]
fn the_workflow_is_started_by_a_published_release_alone() {
    let text = workflow();
    let on =
        &text[text.find("\non:\n").expect("an on block")..text.find("\npermissions:").unwrap()];
    assert_eq!(
        on.lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>(),
        ["on:", "  release:", "    types: [published]"]
    );
}

#[test]
fn only_the_bump_job_enters_the_release_environment_and_only_after_the_filter() {
    let gate = job("gate");
    assert!(!gate.contains("environment"), "{gate}");
    assert!(!gate.contains("secrets."), "{gate}");
    assert!(gate.contains("cask-bump-gate.sh \"${GITHUB_EVENT_PATH}\" >> \"${GITHUB_OUTPUT}\""));

    let bump = job("bump");
    assert!(bump.contains("    needs: gate\n"), "{bump}");
    assert!(
        bump.contains("    if: needs.gate.outputs.bump == 'true'\n"),
        "{bump}"
    );
    assert!(
        bump.contains("    environment:\n      name: release\n"),
        "{bump}"
    );
    // The tap token is read once, in the bump job, by the step that checks
    // out the tap; no other secret is named anywhere.
    let text = workflow();
    let secrets: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("secrets."))
        .collect();
    assert_eq!(
        secrets,
        ["          token: ${{ secrets.HOMEBREW_TAP_TOKEN }}"]
    );
    assert!(step("Check out the tap").contains("${{ secrets.HOMEBREW_TAP_TOKEN }}"));
    assert!(bump.contains("secrets.HOMEBREW_TAP_TOKEN"));
}

#[test]
fn the_attestation_is_verified_before_the_digest_is_computed() {
    let text = workflow();
    let order = [
        "- name: Download the DMG from the release",
        "- name: Verify the attestation of the DMG",
        "- name: Render the cask",
        "- name: Check out the tap",
        "- name: Commit the cask to the tap",
    ];
    let positions: Vec<usize> = order
        .iter()
        .map(|name| text.find(name).unwrap_or_else(|| panic!("{name}")))
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "{order:?}"
    );

    let verify = step("Verify the attestation of the DMG");
    assert!(
        verify.contains("gh attestation verify \"${CASK_DIR}/${DMG}\""),
        "{verify}"
    );
    assert!(
        verify.contains("--repo \"${GITHUB_REPOSITORY}\""),
        "{verify}"
    );
    assert!(
        verify.contains(
            "--signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/app-release.yml\""
        ),
        "{verify}"
    );
    assert!(
        verify.contains("--source-ref \"refs/tags/${TAG}\""),
        "{verify}"
    );
    // A failed verification fails the job: nothing swallows it.
    assert!(!text.contains("continue-on-error"));
    assert!(!text.contains("|| true"));
    assert!(!text.contains("set +e"));

    let render = step("Render the cask");
    assert!(render.contains("render-cask.sh \"${VERSION}\" \"${CASK_DIR}/${DMG}\""));
}

#[test]
fn the_cask_is_committed_to_the_tap_and_nothing_else_is_changed() {
    let checkout = step("Check out the tap");
    assert!(checkout.contains("repository: byte5digital/homebrew-tap"));
    let commit = step("Commit the cask to the tap");
    assert!(commit.contains("Casks/agentsweep.rb"));
    assert!(commit.contains("push origin HEAD:main"));
    assert!(!commit.contains("--force"));
    // The release itself is only read.
    let text = workflow();
    for change in [
        "gh release create",
        "gh release edit",
        "gh release upload",
        "--method",
    ] {
        assert!(!text.contains(change), "{change}");
    }
}
