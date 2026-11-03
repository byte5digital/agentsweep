//! The development keys stay out of a release: the release bundle checker
//! knows every development public key it must refuse, by the same values the
//! tests trust, and the app release workflow never merges the development
//! updater override.

use std::fs;

use agentsweep_core::pack_signature::{RELEASE_KEYS, development};
use agentsweep_xtask::repo_root;

fn read(path: &str) -> String {
    fs::read_to_string(repo_root().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// The words of one `name="..."` assignment in the checker.
fn checker_list(name: &str) -> Vec<String> {
    let checker = read(".github/scripts/check-bundle-signature.sh");
    let start = format!("{name}=\"");
    let line = checker
        .lines()
        .find_map(|line| line.strip_prefix(&start))
        .unwrap_or_else(|| panic!("the checker assigns {name}"));
    line.trim_end_matches('"')
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// The development updater public key as the override pins it.
fn development_updater_pubkey() -> String {
    let text = read("apps/menubar/development-keys/tauri.development.conf.json");
    let value: serde_json::Value = serde_json::from_str(&text).expect("the override is JSON");
    value["plugins"]["updater"]["pubkey"]
        .as_str()
        .expect("a key")
        .to_string()
}

#[test]
fn the_checker_refuses_exactly_the_development_rule_pack_keys() {
    let listed = checker_list("development_rule_pack_keys");
    let development: Vec<String> = development::KEYS
        .iter()
        .map(|key| key.public_key.to_string())
        .collect();
    assert_eq!(listed, development);
    for key in RELEASE_KEYS {
        assert!(!listed.contains(&key.public_key.to_string()));
    }
}

#[test]
fn the_checker_refuses_the_development_updater_key_and_not_the_shipped_one() {
    let listed = checker_list("development_updater_keys");
    let pubkey = development_updater_pubkey();
    assert!(listed.contains(&pubkey), "{listed:?}");

    let shipped: serde_json::Value =
        serde_json::from_str(&read("apps/menubar/tauri.conf.json")).expect("JSON");
    let shipped = shipped["plugins"]["updater"]["pubkey"]
        .as_str()
        .expect("a key");
    assert_ne!(shipped, pubkey);
    assert!(listed.iter().all(|key| !shipped.contains(key.as_str())));
}

/// The release builds with the configuration `tauri.conf.json` and the bundle
/// configuration alone; the development override is for the ad hoc CI bundle
/// and the tests.
#[test]
fn the_app_release_never_merges_the_development_override() {
    for path in [
        ".github/workflows/app-release.yml",
        ".github/scripts/release-dry-run.sh",
    ] {
        let text = read(path);
        assert!(text.contains("tauri.bundle.conf.json"), "{path}");
        assert!(!text.contains("development-keys"), "{path}");
        assert!(!text.contains("tauri.development.conf.json"), "{path}");
    }
}
