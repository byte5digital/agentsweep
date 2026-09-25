//! The pack build: what a Rule Pack states about itself.

use std::fs;

use agentsweep_core::item::sha256_hex;
use agentsweep_core::pack::{Bands, MANIFEST_FILE, Manifest, STATEMENT_FILE};
use agentsweep_core::pack_archive;
use agentsweep_xtask::repo_root;

/// The release moment every manifest of this file states.
const RELEASED: &str = "2026-09-25T08:00:00Z";

fn manifest_of_the_corpus() -> Manifest {
    Manifest::of_pack(&repo_root(), 1, "0.1.0", Bands::V1, RELEASED).expect("the pack is readable")
}

#[test]
fn the_manifest_names_every_file_of_both_trees_with_its_hash() {
    let root = repo_root();
    let manifest = manifest_of_the_corpus();

    for path in [
        "iocs/hosts.txt",
        "iocs/ips.txt",
        "iocs/packages.txt",
        "iocs/files.txt",
        "rules/README.md",
        "rules/0001-decode-pipe-exec/rule.yar",
        "rules/0903-ioc-files/rule.yar",
        "rules/0001-decode-pipe-exec/bad/hook-curl-pipe-sh/item.toml",
    ] {
        let hash = manifest
            .files
            .get(path)
            .unwrap_or_else(|| panic!("{path} is not in the manifest"));
        let bytes = fs::read(root.join(path)).expect("the file");
        assert_eq!(hash, &sha256_hex(&bytes), "{path}");
        assert_eq!(hash.len(), 64);
    }
    assert!(!manifest.files.contains_key(MANIFEST_FILE));
}

#[test]
fn the_manifest_states_the_pack_version_the_engine_version_and_the_bands() {
    let manifest =
        Manifest::of_pack(&repo_root(), 7, "0.2.0", Bands::V1, RELEASED).expect("the pack");
    let json: serde_json::Value =
        serde_json::from_str(&manifest.to_json()).expect("the manifest is JSON");

    assert_eq!(json["pack_version"], 7);
    assert_eq!(json["minimum_engine_version"], "0.2.0");
    assert_eq!(json["heuristics"]["ambiguous_at"], 2);
    assert_eq!(json["heuristics"]["suspicious_at"], 4);
    assert!(json["files"].as_object().expect("the files").len() > 50);
}

#[test]
fn a_manifest_written_into_a_pack_reads_back_as_it_was_built() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let manifest = manifest_of_the_corpus();
    let path = manifest
        .write(temporary.path())
        .expect("the manifest is written");

    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(MANIFEST_FILE)
    );
    let read_back = Manifest::parse(&fs::read_to_string(&path).expect("the manifest"))
        .expect("the manifest reads back");
    assert_eq!(read_back, manifest);
}

#[test]
fn a_changed_file_changes_the_hash_the_manifest_states() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let root = temporary.path();
    fs::create_dir_all(root.join("iocs")).expect("the iocs tree");
    fs::create_dir_all(root.join("rules/0001-a-rule")).expect("the rules tree");
    fs::write(root.join("iocs/hosts.txt"), "host.example.invalid\n").expect("a list");
    fs::write(root.join("rules/0001-a-rule/rule.yar"), "rule a {}\n").expect("a rule");

    let before = Manifest::of_pack(root, 1, "0.1.0", Bands::V1, RELEASED).expect("the pack");
    fs::write(root.join("iocs/hosts.txt"), "other.example.invalid\n").expect("a list");
    let after = Manifest::of_pack(root, 1, "0.1.0", Bands::V1, RELEASED).expect("the pack");

    assert_eq!(before.files.len(), 2);
    assert_ne!(
        before.files["iocs/hosts.txt"],
        after.files["iocs/hosts.txt"]
    );
    assert_eq!(
        before.files["rules/0001-a-rule/rule.yar"],
        after.files["rules/0001-a-rule/rule.yar"]
    );
}

/// The manifest names when the pack was released, and the date is what a
/// client shows as "Rules updated".
#[test]
fn the_manifest_states_when_the_pack_was_released() {
    let manifest = manifest_of_the_corpus();
    assert_eq!(manifest.released_at, RELEASED);
    let json: serde_json::Value =
        serde_json::from_str(&manifest.to_json()).expect("the manifest is JSON");
    assert_eq!(json["released_at"], RELEASED);
    assert_eq!(manifest.released_on(), "2026-09-25");
}

/// The archive of a release carries every file of both trees, and unpacks
/// against the manifest into a root that is exactly the pack.
#[test]
fn the_archive_of_the_corpus_unpacks_into_the_pack_it_was_built_from() {
    let manifest = manifest_of_the_corpus();
    let archive = pack_archive::write(&repo_root(), &manifest).expect("an archive");
    let out = tempfile::tempdir().expect("a temporary directory");
    pack_archive::unpack(&archive, &manifest, out.path()).expect("it unpacks");
    manifest
        .check_files(out.path())
        .expect("the unpacked root is the pack");
}

/// The committed `pack.json` is exactly what `pack --statement` writes for
/// the bundled manifest, so the statement and the bundled pack cannot drift
/// apart by hand.
#[test]
fn the_committed_statement_is_the_bundled_manifest_as_the_pack_build_writes_it() {
    let committed = fs::read_to_string(repo_root().join(STATEMENT_FILE)).expect("pack.json");
    assert_eq!(committed, Manifest::bundled().to_json());
    assert!(Manifest::bundled().files.is_empty());
}
