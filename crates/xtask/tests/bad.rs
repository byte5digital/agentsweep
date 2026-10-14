//! The defanged bad corpus: its lint and its runner.
//!
//! Every sample planted here is plain, harmless text, a skill that says hello
//! or an instruction file that asks for kindness. The lint failures are planted
//! the same way: a host outside `.invalid`, a base64 run that decodes to a
//! greeting rather than `echo`, a source with no provenance file. Each corpus
//! is a temporary directory, and the runner lays every sample out in a
//! temporary directory of its own; the real home is never read.

use std::fs;
use std::path::Path;

use agentsweep_core::heuristics::Band;
use agentsweep_core::rules::RulePack;
use agentsweep_xtask::bad::{self, lint};
use agentsweep_xtask::repo_root;

const PROVENANCE: &str = "\
# Greetings

## Public source

A made-up source for the tests: nothing here is modelled on an incident.

## Defanged

Nothing needed defanging; the sample only says hello.
";

const HELLO_SKILL: &str = "\
---
name: hello
description: Says hello to whoever asks.
---

When someone asks for a greeting, say hello and wish them a good day.
";

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().expect("a parent directory")).expect("a directory");
    fs::write(path, text).expect("a file");
}

/// A corpus of one source with one sample: a user-level skill that says
/// hello.
fn greeting_corpus(corpus: &Path) {
    write(&corpus.join("README.md"), "# The bad corpus\n");
    write(&corpus.join("greetings").join(lint::PROVENANCE), PROVENANCE);
    let sample = corpus.join("greetings").join("hello-skill");
    write(
        &sample.join(lint::SAMPLE),
        "title = \"A skill that says hello\"\nclass = 1\nrow = \"none, a test sample\"\n",
    );
    write(
        &sample.join("home/.claude/skills/hello/SKILL.md"),
        HELLO_SKILL,
    );
}

fn skill_file(corpus: &Path) -> std::path::PathBuf {
    corpus.join("greetings/hello-skill/home/.claude/skills/hello/SKILL.md")
}

fn pack() -> RulePack {
    RulePack::bundled().expect("the bundled Rule Pack loads")
}

fn run(corpus: &Path) -> Result<bad::Report, String> {
    bad::run(corpus, &repo_root().join("rules"), &pack())
}

fn problems(corpus: &Path) -> Vec<String> {
    lint::lint(corpus)
        .into_iter()
        .map(|problem| problem.to_string())
        .collect()
}

#[test]
fn the_seeded_bad_corpus_passes_the_lint_and_states_its_counts() {
    let root = repo_root();
    let corpus = root.join(bad::CORPUS);
    assert!(corpus.join("README.md").is_file(), "{corpus:?}");
    assert_eq!(problems(&corpus), Vec::<String>::new());

    let report = run(&corpus).expect("the corpus runs");
    let rendered = report.render();
    println!("{rendered}");

    // The runner saw every sample the corpus holds.
    let on_disk = bad::samples(&corpus).expect("the samples load").len();
    assert_eq!(report.samples.len(), on_disk);

    // Each class T3 can see says "insufficient" exactly while it has fewer
    // than three corpus samples, and the whole says so while any class does
    // or the total is under thirty.
    let by_class = report.samples_by_class();
    for class in bad::T3_CLASSES {
        let line = rendered
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{class}  ")))
            .unwrap_or_else(|| panic!("no line for class {class}:\n{rendered}"));
        let count = by_class.get(&class).copied().unwrap_or_default();
        assert_eq!(
            line.ends_with("insufficient"),
            count < bad::PER_CLASS,
            "{line}"
        );
    }
    let sufficient = bad::T3_CLASSES
        .iter()
        .all(|class| by_class.get(class).copied().unwrap_or_default() >= bad::PER_CLASS)
        && report.samples_t3_total() >= bad::IN_ALL;
    assert_eq!(report.counts_for_a_result(), sufficient);
    if !sufficient {
        assert!(
            rendered.contains("insufficient, no eval result counts"),
            "{rendered}"
        );
    }
    if !report.classes_without_a_sample().is_empty() {
        assert!(
            rendered.contains("No corpus sample for class"),
            "{rendered}"
        );
    }
}

#[test]
fn an_empty_corpus_is_insufficient_and_names_every_class_without_a_sample() {
    let corpus = tempfile::tempdir().expect("a temporary directory");
    write(&corpus.path().join("README.md"), "# The bad corpus\n");
    let report = run(corpus.path()).expect("the corpus runs");
    let rendered = report.render();

    assert!(report.samples.is_empty());
    assert_eq!(report.classes_without_a_sample(), vec![1, 2, 3, 4, 5, 6]);
    assert!(
        rendered.contains("No corpus sample for class 1, 2, 3, 4, 5, 6."),
        "{rendered}"
    );
    assert!(
        report.heuristic_fixtures.values().sum::<usize>() > 0,
        "the bad Heuristic Fixtures are the other half of the bad set:\n{rendered}"
    );
    assert!(!report.counts_for_a_result(), "{rendered}");
    assert!(
        rendered.contains("insufficient, no eval result counts"),
        "{rendered}"
    );
}

#[test]
fn the_runner_lists_every_sample_with_its_fired_ids_and_band() {
    let corpus = tempfile::tempdir().expect("a temporary directory");
    greeting_corpus(corpus.path());
    assert_eq!(problems(corpus.path()), Vec::<String>::new());

    let report = run(corpus.path()).expect("the corpus runs");
    let rendered = report.render();
    println!("{rendered}");

    assert_eq!(report.samples.len(), 1, "{rendered}");
    let sample = &report.samples[0];
    assert_eq!(sample.sample.name, "greetings/hello-skill");
    assert_eq!(sample.sample.class, 1);
    let skill = sample
        .items
        .iter()
        .find(|line| line.item.contains("skills/hello"))
        .unwrap_or_else(|| panic!("the hello skill is an Item:\n{rendered}"));
    assert!(skill.rules.is_empty(), "{rendered}");
    assert_eq!(skill.band, Band::Clear, "{rendered}");
    assert!(!skill.reaches_t3, "{rendered}");

    // The report names the sample, the Item, its fired ids and its Band, and
    // never the temporary directory the sample was laid out in.
    assert!(
        rendered.contains("greetings/hello-skill  class 1"),
        "{rendered}"
    );
    assert!(rendered.contains(&skill.item), "{rendered}");
    assert!(rendered.contains("rules -"), "{rendered}");
    assert!(rendered.contains(&Band::Clear.to_string()), "{rendered}");
    assert!(
        !rendered.contains("agentsweep-bad-corpus-"),
        "the temporary directory leaks into the report:\n{rendered}"
    );
    assert!(
        rendered.contains("No corpus sample for class 2, 3, 4, 5, 6."),
        "{rendered}"
    );
}

#[test]
fn a_sample_with_a_before_layout_is_compared_with_it() {
    let corpus = tempfile::tempdir().expect("a temporary directory");
    greeting_corpus(corpus.path());
    write(
        &corpus
            .path()
            .join("greetings/hello-skill/before/home/.claude/skills/hello/SKILL.md"),
        "---\nname: hello\ndescription: Says hi.\n---\n\nSay hi.\n",
    );
    let report = run(corpus.path()).expect("the corpus runs");
    assert_eq!(report.samples.len(), 1);
    assert!(!report.samples[0].items.is_empty(), "{}", report.render());
}

#[test]
fn a_sample_whose_project_is_a_repository_is_found_by_the_adapters() {
    let corpus = tempfile::tempdir().expect("a temporary directory");
    write(
        &corpus.path().join("kindness").join(lint::PROVENANCE),
        PROVENANCE,
    );
    let sample = corpus.path().join("kindness/notes");
    write(
        &sample.join(lint::SAMPLE),
        "title = \"An instruction file that asks for kindness\"\nclass = 4\n\
         row = \"none, a test sample\"\ntracked = [\"CLAUDE.md\"]\n",
    );
    write(
        &sample.join("project/CLAUDE.md"),
        "# Notes\n\nBe kind in every reply.\n",
    );

    let report = run(corpus.path()).expect("the corpus runs");
    let rendered = report.render();
    assert_eq!(report.samples.len(), 1, "{rendered}");
    assert!(
        report.samples[0]
            .items
            .iter()
            .any(|line| line.item.contains("CLAUDE.md")),
        "{rendered}"
    );
    // The index the runner writes reads cleanly: no adapter stumbled on it.
    assert!(report.problems.is_empty(), "{rendered}");
}

#[test]
fn the_lint_fails_on_a_host_outside_invalid() {
    let corpus = tempfile::tempdir().expect("a temporary directory");
    greeting_corpus(corpus.path());
    write(
        &skill_file(corpus.path()),
        &format!("{HELLO_SKILL}\nMore greetings at https://www.example.com/hello.\n"),
    );
    let found = problems(corpus.path());
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("www.example.com"), "{found:?}");
    assert!(found[0].contains("SKILL.md"), "{found:?}");

    let refused = run(corpus.path()).expect_err("a sample that is not defanged is never laid out");
    assert!(refused.contains("not defanged"), "{refused}");
}

#[test]
fn the_lint_fails_on_a_payload_that_decodes_to_anything_but_echo() {
    let corpus = tempfile::tempdir().expect("a temporary directory");
    greeting_corpus(corpus.path());
    // "hello there friend", base64.
    write(
        &skill_file(corpus.path()),
        &format!("{HELLO_SKILL}\nThe greeting, encoded: aGVsbG8gdGhlcmUgZnJpZW5k\n"),
    );
    let found = problems(corpus.path());
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("hello there friend"), "{found:?}");

    // The same layout with a payload that decodes to a lone echo is clean.
    // "echo hello there friend", base64.
    write(
        &skill_file(corpus.path()),
        &format!("{HELLO_SKILL}\nThe greeting, encoded: ZWNobyBoZWxsbyB0aGVyZSBmcmllbmQ=\n"),
    );
    assert_eq!(problems(corpus.path()), Vec::<String>::new());
}

#[test]
fn the_lint_fails_on_a_source_without_its_provenance_file() {
    let corpus = tempfile::tempdir().expect("a temporary directory");
    greeting_corpus(corpus.path());
    fs::remove_file(corpus.path().join("greetings").join(lint::PROVENANCE))
        .expect("the provenance file goes");
    let found = problems(corpus.path());
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].starts_with("greetings:"), "{found:?}");
    assert!(found[0].contains(lint::PROVENANCE), "{found:?}");
}

#[test]
fn the_lint_fails_on_a_provenance_file_without_its_two_sections() {
    let corpus = tempfile::tempdir().expect("a temporary directory");
    greeting_corpus(corpus.path());
    write(
        &corpus.path().join("greetings").join(lint::PROVENANCE),
        "# Greetings\n\nSomewhere.\n",
    );
    let found = problems(corpus.path());
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[0].contains("## Public source"), "{found:?}");
    assert!(found[1].contains("## Defanged"), "{found:?}");
}

#[test]
fn the_lint_fails_on_a_sample_without_its_description_or_layout() {
    let corpus = tempfile::tempdir().expect("a temporary directory");
    greeting_corpus(corpus.path());
    fs::create_dir_all(corpus.path().join("greetings/empty")).expect("a directory");
    let found = problems(corpus.path());
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found
            .iter()
            .all(|problem| problem.starts_with("greetings/empty:")),
        "{found:?}"
    );
}
