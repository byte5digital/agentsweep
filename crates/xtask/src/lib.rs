//! Build work for the Rule corpus and the Rule Pack.
//!
//! Jobs that nothing in the app ever does: run every Fixture of the corpus
//! under the Rules it belongs to, render the Indicator Lists into their
//! generated Rules, build, sign and verify a Rule Pack release, and hold every workflow to the
//! pipeline hardening rules. The corpus runner lives
//! here rather than in the YARA-X command line tool because a Rule reads the
//! Item as struct globals and that tool cannot define them (spec section 4.2).
//!
//! Every entry point takes the repository root, so a test can point it at a
//! temporary copy and never at the real corpus when it needs to break one.

#![warn(missing_docs)]

pub mod bad;
pub mod benign;
pub mod corpus;
pub mod eval;
pub mod fixture;
pub mod iocs;
pub mod pack_release;
pub mod workflows;

use std::path::{Path, PathBuf};

/// The repository root, which is the root of the Rule Pack as well: the
/// `rules/` corpus and the `iocs/` Indicator Lists sit directly under it.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits two directories below the repository root")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_repository_root_holds_the_corpus_and_the_indicator_lists() {
        let root = repo_root();
        assert!(root.join("rules/README.md").is_file(), "{root:?}");
        assert!(root.join("iocs/hosts.txt").is_file(), "{root:?}");
    }
}
