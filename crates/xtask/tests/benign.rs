//! The benign corpus, fetched and scanned.
//!
//! Spec section 4.2: a T1 Rule may not quarantine by itself until it has zero
//! hits on content known to be good, and spec section 4.3 asks the same corpus
//! for a hit count per Heuristic with every weight 3 Heuristic at zero. This is
//! where both are measured.
//!
//! Nothing here is committed. The sources are public repositories pinned to
//! commits in `corpus/benign/manifest.toml`, fetched over plain HTTPS into
//! `target/` and laid out there as a machine the Surface Adapters recognise.
//! With no network the test says so and passes, because a developer on a train
//! is not a failing Rule; CI sets `AGENTSWEEP_CORPUS_REQUIRED` so that there a
//! fetch that did not happen is a failure rather than a green tick over an
//! unproven Rule Pack.

use agentsweep_xtask::benign::{self, Run};
use agentsweep_xtask::repo_root;

/// Part of the default suite. The CI job runs the same check through the
/// xtask command with the offline skip turned off.
#[test]
fn the_benign_corpus_meets_the_precision_bar_of_the_rule_tier() {
    let required = std::env::var(benign::REQUIRED).is_ok_and(|value| !value.is_empty());
    match benign::run(&repo_root(), false).expect("the corpus runs") {
        Run::Offline(what) => {
            assert!(
                !required,
                "{} asks for the benign corpus and it could not be fetched: {what}",
                benign::REQUIRED
            );
            println!(
                "the benign corpus was skipped: {what}\nRun it again with a network, or set {}=1 to make this a failure.",
                benign::REQUIRED
            );
        }
        Run::Scanned(scanned) => {
            let report = scanned.render();
            println!("{report}");
            assert!(
                scanned.meets_the_bar(),
                "{report}\n{}",
                scanned.report.failures().join("\n")
            );
        }
    }
}
