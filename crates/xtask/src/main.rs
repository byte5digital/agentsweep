//! The build tool for the Rule corpus and the Rule Pack.
//!
//! Everything here also runs from `cargo test`; the commands exist so a rule
//! author can do one job at a time and see the whole report, and so a release
//! workflow can build a pack without a test harness around it.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use agentsweep_core::pack::Manifest;
use agentsweep_core::rules::RulePack;
use agentsweep_xtask::{corpus, iocs, repo_root};

const USAGE: &str = "\
agentsweep-xtask: build work for the Rule corpus and the Rule Pack.

    corpus                      run every Fixture of every Rule
    render-iocs [--check]       render the Indicator Lists into rules 0900 to 0903,
                                or with --check only report a stale rendering
    pack [options]              write a Rule Pack manifest
        --pack-version <n>      the pack version, a monotonic integer
        --minimum-engine <v>    the lowest engine version that may load it
        --out <dir>             where the manifest lands
                                (default target/agentsweep-pack)
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    let result = match command.as_str() {
        "corpus" => run_corpus(),
        "render-iocs" => render_iocs(arguments.iter().any(|argument| argument == "--check")),
        "pack" => build_pack(&arguments[1..]),
        other => Err(format!("`{other}` is not a command\n\n{USAGE}")),
    };

    match result {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(problem) => {
            eprint!("{problem}");
            ExitCode::FAILURE
        }
    }
}

/// Runs every Fixture and reports what did not hold.
fn run_corpus() -> Result<String, String> {
    let root = repo_root();
    let pack = RulePack::bundled().map_err(|error| format!("{error}\n"))?;
    let fixtures = corpus::fixtures(&root.join("rules")).map_err(|error| format!("{error}\n"))?;
    let outcomes = corpus::run(&pack, &fixtures).map_err(|error| format!("{error}\n"))?;

    let failed: Vec<String> = outcomes
        .iter()
        .filter(|outcome| !outcome.passed())
        .map(|outcome| outcome.report())
        .collect();
    if failed.is_empty() {
        return Ok(format!(
            "{} fixtures over {} rules, all as expected\n",
            fixtures.len(),
            pack.len()
        ));
    }
    Err(format!(
        "{}\n{} of {} fixtures did not hold\n",
        failed.join(""),
        failed.len(),
        fixtures.len()
    ))
}

/// Renders every Indicator List, or reports the ones whose committed Rule is
/// no longer what the list renders to.
fn render_iocs(check: bool) -> Result<String, String> {
    let root = repo_root();
    let mut stale = Vec::new();
    let mut written = Vec::new();

    for generated in iocs::GENERATED {
        let rendered = generated.render_from(&root).map_err(|e| format!("{e}\n"))?;
        let path = generated.rule_path(&root);
        let committed = fs::read_to_string(&path).unwrap_or_default();
        if committed == rendered {
            continue;
        }
        if check {
            stale.push(generated.directory());
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("{}: {error}\n", parent.display()))?;
        }
        fs::write(&path, rendered).map_err(|error| format!("{}: {error}\n", path.display()))?;
        written.push(generated.directory());
    }

    if !stale.is_empty() {
        return Err(format!(
            "no longer what the indicator list renders to: {}\nrun `cargo run -p agentsweep-xtask -- render-iocs`\n",
            stale.join(", ")
        ));
    }
    if written.is_empty() {
        return Ok("every generated rule is what its indicator list renders to\n".to_string());
    }
    Ok(format!("rendered {}\n", written.join(", ")))
}

/// Writes a Rule Pack manifest for the corpus as it stands. What the pack says
/// about itself, thresholds included, comes from the committed `pack.json`;
/// the options below override it for a release that needs something else.
fn build_pack(arguments: &[String]) -> Result<String, String> {
    let root = repo_root();
    let stated = Manifest::bundled();
    let mut pack_version = stated.pack_version;
    let mut minimum_engine = stated.minimum_engine_version.clone();
    let mut out = root.join("target").join("agentsweep-pack");

    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{argument} takes a value\n\n{USAGE}"))
        };
        match argument.as_str() {
            "--pack-version" => {
                pack_version = value()?
                    .parse()
                    .map_err(|_| "the pack version is a monotonic integer\n".to_string())?;
            }
            "--minimum-engine" => minimum_engine = value()?,
            "--out" => out = PathBuf::from(value()?),
            other => return Err(format!("`{other}` is not an option of pack\n\n{USAGE}")),
        }
    }

    let manifest = Manifest::of_pack(&root, pack_version, &minimum_engine, stated.bands)
        .map_err(|error| format!("{error}\n"))?;
    fs::create_dir_all(&out).map_err(|error| format!("{}: {error}\n", out.display()))?;
    let path = manifest.write(&out).map_err(|error| format!("{error}\n"))?;
    Ok(format!(
        "pack {} for engine {} and up, {} files, bands {} and {}\n{}\n",
        manifest.pack_version,
        manifest.minimum_engine_version,
        manifest.files.len(),
        manifest.bands.ambiguous_at,
        manifest.bands.suspicious_at,
        path.display()
    ))
}
