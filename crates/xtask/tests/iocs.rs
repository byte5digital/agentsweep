//! The Indicator Lists and the Rules they render into.
//!
//! Both the list and the generated Rule are committed, so this is where a
//! stale rendering is caught: an entry added to a list without running the
//! renderer fails here, and so does a generated Rule edited by hand.

use std::fs;

use agentsweep_core::rules::RulePack;
use agentsweep_xtask::iocs::{self, GENERATED};
use agentsweep_xtask::repo_root;

#[test]
fn every_generated_rule_is_what_its_indicator_list_renders_to() {
    let root = repo_root();
    for generated in GENERATED {
        let rendered = generated
            .render_from(&root)
            .unwrap_or_else(|error| panic!("{error}"));
        let path = generated.rule_path(&root);
        let committed =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(
            committed,
            rendered,
            "{} is not what iocs/{} renders to; run `cargo run -p agentsweep-xtask -- render-iocs`",
            generated.directory(),
            generated.list
        );
    }
}

#[test]
fn an_entry_added_to_a_list_makes_the_committed_rule_stale() {
    let root = repo_root();
    let generated = GENERATED[0];
    let list = fs::read_to_string(generated.list_path(&root)).expect("the indicator list");

    let mut entries = iocs::entries(&list);
    entries.push("added.example.invalid".to_string());
    let rendered = generated.render(&entries);
    let committed = fs::read_to_string(generated.rule_path(&root)).expect("the generated rule");

    assert_ne!(
        committed, rendered,
        "an entry added to an indicator list must change the rule it renders to"
    );
    assert!(rendered.contains("added.example.invalid"));
}

#[test]
fn the_indicator_lists_render_into_the_ids_the_specification_allocates() {
    let root = repo_root();
    let ids: Vec<i64> = GENERATED.iter().map(|generated| generated.id).collect();
    assert_eq!(ids, vec![900, 901, 902, 903]);

    for generated in GENERATED {
        assert!(
            generated.list_path(&root).is_file(),
            "iocs/{} is missing",
            generated.list
        );
        assert!(
            generated.rule_path(&root).is_file(),
            "{} is missing",
            generated.directory()
        );
    }
}

#[test]
fn every_rule_in_the_generated_band_is_rendered_from_a_list() {
    let pack = RulePack::bundled().expect("the bundled pack compiles");
    for meta in pack.metas() {
        if !(900..=999).contains(&meta.id) {
            continue;
        }
        assert!(
            GENERATED.iter().any(|generated| generated.id == meta.id),
            "rule {:04} sits in the generated band and no indicator list renders it",
            meta.id
        );
    }
}

#[test]
fn a_generated_rule_compiles_and_carries_the_meta_the_contract_requires() {
    let pack = RulePack::bundled().expect("the bundled pack compiles");
    for generated in GENERATED {
        let meta = pack
            .meta(&generated.name())
            .unwrap_or_else(|| panic!("{} is not in the pack", generated.name()));
        assert_eq!(meta.id, generated.id);
        assert!(!meta.kinds.is_empty());
        assert!(!meta.plain.is_empty());
        assert!(!meta.description.is_empty());
    }
}
