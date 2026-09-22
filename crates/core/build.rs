//! Embeds the bundled Rule Pack in the binary.
//!
//! The bundled pack is the `rules/` tree of this repository, embedded at build
//! time (spec section 4.2, "Packs"). The script emits one `include_str!` per
//! rule so the sources travel inside the binary and no path is read at run
//! time. A fetched pack replaces the bundled one wholesale later; that is the
//! Rule Feed's work, not this script's.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("a manifest dir"));
    let rules_dir = manifest_dir
        .join("..")
        .join("..")
        .join("rules")
        .canonicalize()
        .expect("the bundled rules tree");

    println!("cargo::rerun-if-changed={}", rules_dir.display());

    let mut rules: Vec<(String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(&rules_dir).expect("a readable rules tree") {
        let entry = entry.expect("a readable rule directory");
        let rule = entry.path().join("rule.yar");
        if !rule.is_file() {
            continue;
        }
        let origin = format!(
            "{}/rule.yar",
            entry.file_name().to_str().expect("a rule directory name")
        );
        println!("cargo::rerun-if-changed={}", rule.display());
        rules.push((origin, rule));
    }
    rules.sort();

    let mut generated = String::new();
    generated.push_str("/// The rules of the bundled Rule Pack, by origin.\n");
    generated.push_str("pub const BUNDLED_RULES: &[RuleSource] = &[\n");
    for (origin, path) in &rules {
        generated.push_str(&format!(
            "    RuleSource {{ origin: {:?}, source: include_str!({:?}) }},\n",
            origin,
            path.display().to_string()
        ));
    }
    generated.push_str("];\n");

    let out = Path::new(&env::var("OUT_DIR").expect("an out dir")).join("bundled_rules.rs");
    fs::write(&out, generated).expect("the generated rule table");
}
