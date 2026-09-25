//! The build tool for the Rule corpus and the Rule Pack.
//!
//! Everything here also runs from `cargo test`; the commands exist so a rule
//! author can do one job at a time and see the whole report, and so a release
//! workflow can build a pack without a test harness around it.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use agentsweep_core::pack::{Manifest, STATEMENT_FILE};
use agentsweep_core::pack_archive::{self, ARCHIVE_FILE};
use agentsweep_core::rules::RulePack;
use agentsweep_xtask::{benign, corpus, iocs, repo_root};

const USAGE: &str = "\
agentsweep-xtask: build work for the Rule corpus and the Rule Pack.

    corpus                      run every Fixture of every Rule
    benign-corpus [--record]    fetch the public sources of corpus/benign/manifest.toml,
                                lay them out as the adapters would see them and report
                                the T1 hits and the hit count per Heuristic; with
                                --record write the digest of what was fetched back into
                                the manifest instead of holding the fetch to it
    render-iocs [--check]       render the Indicator Lists into rules 0900 to 0903,
                                or with --check only report a stale rendering
    pack [options]              write a Rule Pack release: manifest.json, which the
                                release workflow signs with minisign, one detached
                                <KEY ID>.minisig per key, and pack.tar with both trees
        --pack-version <n>      the pack version, a monotonic integer
        --minimum-engine <v>    the lowest engine version that may load it
        --released-at <t>       the release moment, RFC 3339 (default now, UTC)
        --out <dir>             where the release lands
                                (default target/agentsweep-pack)
        --statement             instead, write the bundled pack's own statement,
                                pack.json at the repository root, with the options
                                above and no file hashes
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    let result = match command.as_str() {
        "corpus" => run_corpus(),
        "benign-corpus" => {
            run_benign_corpus(arguments.iter().any(|argument| argument == "--record"))
        }
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
        let hits: Vec<String> = corpus::heuristic_hits(&outcomes)
            .into_iter()
            .map(|(id, count)| format!("{id:04}x{count}"))
            .collect();
        let noticed = if hits.is_empty() {
            String::new()
        } else {
            format!(
                "\nheuristics noticed on other rules' fixtures: {}\n",
                hits.join(" ")
            )
        };
        return Ok(format!(
            "{} fixtures over {} rules, all as expected\n{noticed}",
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

/// Fetches the benign corpus and reports what the bundled Rule Pack makes of
/// it. A T1 hit and a weight 3 Heuristic both fail; everything else is a
/// count a rule author reads.
///
/// Offline the command says so and succeeds, unless the environment asks for
/// the corpus by name, which is what CI does: a job that fetched nothing and
/// said nothing would be a green tick over an unproven Rule Pack.
fn run_benign_corpus(record: bool) -> Result<String, String> {
    let root = repo_root();
    let required = std::env::var(benign::REQUIRED).is_ok_and(|value| !value.is_empty());
    match benign::run(&root, record)? {
        benign::Run::Offline(what) => {
            if required {
                return Err(format!(
                    "the benign corpus could not be fetched and {} asks for it: {what}\n",
                    benign::REQUIRED
                ));
            }
            Ok(format!(
                "the benign corpus was skipped: {what}\nRun it again with a network, or set {}=1 to make this a failure.\n",
                benign::REQUIRED
            ))
        }
        benign::Run::Scanned(scanned) => {
            let mut report = scanned.render();
            if record {
                let path = benign::record(&root, &scanned.digests)?;
                report.push_str(&format!(
                    "\nrecorded {} digests in {}\n",
                    scanned.digests.len(),
                    path.display()
                ));
                return Ok(report);
            }
            if scanned.meets_the_bar() {
                report.push_str("\nThe benign corpus meets the bar of spec section 4.2.\n");
                return Ok(report);
            }
            report.push('\n');
            for failure in scanned.report.failures() {
                report.push_str(&format!("{failure}\n"));
            }
            Err(report)
        }
    }
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

/// Writes a Rule Pack release for the corpus as it stands: the manifest and
/// the archive of both trees, which the release workflow signs and uploads
/// (spec section 9.4). What the pack says about itself, thresholds included,
/// comes from the committed `pack.json`; the options below override it for a
/// release that needs something else.
///
/// With `--statement` it writes `pack.json` itself instead: the bundled pack's
/// statement, which lists no hashes because the bundled pack travels inside
/// the binary and the code signature stands behind it.
fn build_pack(arguments: &[String]) -> Result<String, String> {
    let root = repo_root();
    let stated = Manifest::bundled();
    let mut pack_version = stated.pack_version;
    let mut minimum_engine = stated.minimum_engine_version.clone();
    let mut released_at: Option<String> = None;
    let mut out = root.join("target").join("agentsweep-pack");
    let mut statement = false;

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
            "--released-at" => released_at = Some(value()?),
            "--out" => out = PathBuf::from(value()?),
            "--statement" => statement = true,
            other => return Err(format!("`{other}` is not an option of pack\n\n{USAGE}")),
        }
    }
    let released_at = released_at.unwrap_or_else(now_rfc3339);

    let mut manifest = Manifest::of_pack(
        &root,
        pack_version,
        &minimum_engine,
        stated.bands,
        &released_at,
    )
    .map_err(|error| format!("{error}\n"))?;

    if statement {
        manifest.files.clear();
        let path = root.join(STATEMENT_FILE);
        fs::write(&path, manifest.to_json())
            .map_err(|error| format!("{}: {error}\n", path.display()))?;
        return Ok(format!(
            "the bundled pack states version {}, engine {} and up, released {}\n{}\n",
            manifest.pack_version,
            manifest.minimum_engine_version,
            manifest.released_at,
            path.display()
        ));
    }

    fs::create_dir_all(&out).map_err(|error| format!("{}: {error}\n", out.display()))?;
    let path = manifest.write(&out).map_err(|error| format!("{error}\n"))?;
    let archive = pack_archive::write(&root, &manifest).map_err(|error| format!("{error}\n"))?;
    let archive_path = out.join(ARCHIVE_FILE);
    fs::write(&archive_path, archive)
        .map_err(|error| format!("{}: {error}\n", archive_path.display()))?;
    Ok(format!(
        "pack {} for engine {} and up, released {}, {} files, bands {} and {}\n{}\n{}\n",
        manifest.pack_version,
        manifest.minimum_engine_version,
        manifest.released_at,
        manifest.files.len(),
        manifest.bands.ambiguous_at,
        manifest.bands.suspicious_at,
        path.display(),
        archive_path.display()
    ))
}

/// The moment this runs, in RFC 3339 to the second, UTC.
fn now_rfc3339() -> String {
    let moment = agentsweep_core::envelope::Timestamp::now().to_string();
    format!("{}Z", &moment[..19])
}
