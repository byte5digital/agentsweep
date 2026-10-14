//! The core as crates.io receives it.
//!
//! The packaged core embeds the bundled Rule Pack from the copies of the rule
//! sources and of the pack statement its package carries, because a published
//! crate sees nothing outside its own directory. These tests package the core
//! the way a release does, offline and without uploading anything, and read
//! the tarball: the Rule Pack inside it must be byte for byte the repository's
//! own, the one the app bundle embeds, and the development secret halves must
//! stay out.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use agentsweep_core::pack::BUNDLED_STATEMENT;
use agentsweep_core::rules::BUNDLED_RULES;
use agentsweep_xtask::repo_root;

/// Every file of the packaged core, by its path inside the package.
fn packaged_core() -> BTreeMap<String, Vec<u8>> {
    let target = tempfile::tempdir().expect("a temporary target directory");
    let output = Command::new(env!("CARGO"))
        .args([
            "package",
            "-p",
            "agentsweep-core",
            "--no-verify",
            "--allow-dirty",
            "--locked",
            "--offline",
            "--target-dir",
        ])
        .arg(target.path())
        .current_dir(repo_root())
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("Cargo runs");
    assert!(
        output.status.success(),
        "`cargo package` failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let version = env!("CARGO_PKG_VERSION");
    let prefix = format!("agentsweep-core-{version}/");
    let tarball = target
        .path()
        .join("package")
        .join(format!("agentsweep-core-{version}.crate"));
    let bytes = fs::read(&tarball).expect("the packaged core");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes.as_slice()));
    let mut files = BTreeMap::new();
    for entry in archive.entries().expect("a readable tarball") {
        let mut entry = entry.expect("a readable entry");
        let path = entry
            .path()
            .expect("an entry path")
            .to_string_lossy()
            .to_string();
        let inside = path
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("{path} sits outside the package directory"))
            .to_string();
        let mut content = Vec::new();
        entry.read_to_end(&mut content).expect("an entry's bytes");
        files.insert(inside, content);
    }
    files
}

/// The rule sources of the repository's `rules/` tree, by origin.
fn repository_rules(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut rules = BTreeMap::new();
    for entry in fs::read_dir(root.join("rules")).expect("the rules tree") {
        let directory = entry.expect("a rule directory").path();
        let rule = directory.join("rule.yar");
        if rule.is_file() {
            let name = directory
                .file_name()
                .expect("a directory name")
                .to_string_lossy()
                .to_string();
            rules.insert(
                format!("{name}/rule.yar"),
                fs::read(&rule).expect("a rule source"),
            );
        }
    }
    rules
}

#[test]
fn the_packaged_core_embeds_the_repositorys_rule_pack_byte_for_byte_and_no_secret_half() {
    let root = repo_root();
    let packaged = packaged_core();

    // The rule sources: exactly the repository's, and nothing else of the
    // rules tree, so no Fixture travels.
    let packaged_rules: BTreeMap<String, Vec<u8>> = packaged
        .iter()
        .filter_map(|(path, content)| {
            path.strip_prefix("rules/")
                .map(|origin| (origin.to_string(), content.clone()))
        })
        .collect();
    let repository = repository_rules(&root);
    assert!(repository.len() >= 11, "{:?}", repository.keys());
    assert_eq!(
        packaged_rules.keys().collect::<Vec<_>>(),
        repository.keys().collect::<Vec<_>>()
    );
    for (origin, source) in &repository {
        assert!(
            packaged_rules[origin] == *source,
            "{origin} differs in the packaged core"
        );
    }

    // The pack statement.
    let statement = fs::read(root.join("pack.json")).expect("the pack statement");
    assert!(
        packaged.get("pack.json") == Some(&statement),
        "the packaged pack statement differs from the repository's"
    );

    // What the core embeds is what it packages: the rule table and the
    // statement compiled into this build are the same bytes.
    let embedded: BTreeMap<String, Vec<u8>> = BUNDLED_RULES
        .iter()
        .map(|rule| (rule.origin.to_string(), rule.source.as_bytes().to_vec()))
        .collect();
    assert_eq!(embedded, packaged_rules);
    assert_eq!(BUNDLED_STATEMENT.as_bytes(), statement.as_slice());

    // No secret half, under its directory or anywhere else.
    for path in packaged.keys() {
        assert!(
            !path.starts_with("development-keys/") && !path.ends_with(".secret"),
            "the packaged core carries {path}"
        );
    }
}
