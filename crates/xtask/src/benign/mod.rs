//! The benign corpus: public content that is known to be good, scanned the way
//! the Surface Adapters would see it.
//!
//! Spec section 4.2 puts five conditions on a T1 Rule before it may quarantine
//! by itself, and two of them are measured here: zero T1 hits on the benign
//! corpus, and a hit count per Heuristic with every weight 3 Heuristic at zero.
//! The corpus is the manifest of `corpus/benign/manifest.toml`, fetched at test
//! time over plain HTTPS from commits it pins, laid out as a machine an Agent
//! would recognise, and scanned with the bundled Rule Pack.
//!
//! Three things this never does. It never runs a git binary: an archive is a
//! tarball of one commit and a file is one blob of one commit. It never writes
//! outside the working directory it is given, which is under `target/`. And it
//! never puts a T0 Allowlist in front of the scan: a Rule Pack is proven quiet
//! by running every Rule over the content, not by skipping the content an
//! official marketplace shipped.

pub mod fetch;
pub mod manifest;
pub mod plant;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use agentsweep_adapter_claude_code::ClaudeCode;
use agentsweep_adapter_codex::Codex;
use agentsweep_adapter_workspace::Workspace;
use agentsweep_core::adapter::{Enumeration, SurfaceAdapter};
use agentsweep_core::hits::HitReport;
use agentsweep_core::host::Host;
use agentsweep_core::rules::RulePack;
use agentsweep_core::scan::Scanners;

use crate::benign::fetch::{Cache, Problem};
use crate::benign::manifest::{Manifest, Shape, Source};
use crate::benign::plant::{Content, Ground, Machine};

/// Where the corpus is fetched to and laid out, under the repository root.
pub const WORK: &str = "target/agentsweep-benign-corpus";

/// The environment variable that turns the offline skip off. CI sets it,
/// because a job that fetched nothing and said nothing would be a green tick
/// over an unproven Rule Pack.
pub const REQUIRED: &str = "AGENTSWEEP_CORPUS_REQUIRED";

/// What one run of the benign corpus came to.
#[derive(Debug)]
pub enum Run {
    /// The network did not answer, so nothing was scanned.
    Offline(String),
    /// The corpus was fetched and scanned.
    Scanned(Box<Scanned>),
}

/// What the corpus scan found.
#[derive(Debug)]
pub struct Scanned {
    /// How many sources were fetched.
    pub sources: usize,
    /// How many files were laid out across all of them.
    pub files: usize,
    /// The T1 hits and the hit count per Heuristic.
    pub report: HitReport,
    /// The Surfaces no adapter could read all the way through.
    pub problems: Vec<String>,
    /// The digest of each source, in manifest order, for `--record`.
    pub digests: Vec<(String, String)>,
}

impl Scanned {
    /// True when the bar of spec section 4.2 holds.
    pub fn meets_the_bar(&self) -> bool {
        self.report.meets_the_bar()
    }

    /// The whole report, ready to print.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} sources, {} files laid out as the adapters would see them",
            self.sources, self.files
        );
        let _ = writeln!(out);
        out.push_str(&self.report.render());
        if !self.problems.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{} Surfaces could not be read all the way through:",
                self.problems.len()
            );
            for problem in &self.problems {
                let _ = writeln!(out, "  {problem}");
            }
        }
        out
    }
}

/// Fetches the corpus, lays it out and scans it.
///
/// `record` accepts a digest the manifest does not state yet and reports what
/// it observed instead of refusing; without it, a source whose content is not
/// the content the manifest pins is a failure.
pub fn run(root: &Path, record: bool) -> Result<Run, String> {
    let manifest = Manifest::of(root).map_err(|error| error.to_string())?;
    let work = root.join(WORK);
    let cache = Cache::at(work.join("cache"));
    let mut ground = Ground::fresh(&work.join("machine"))
        .map_err(|error| format!("the corpus machine could not be laid out: {error}"))?;

    let mut digests = Vec::new();
    let mut files = 0;
    for source in &manifest.sources {
        let content = match content_of(&cache, source) {
            Ok(content) => content,
            Err(Problem::Offline(what)) => return Ok(Run::Offline(what)),
            Err(Problem::Refused(what)) => return Err(what),
        };
        let digest = plant::digest(&content);
        digests.push((source.name.clone(), digest.clone()));
        if !record {
            if source.sha256.is_empty() {
                return Err(format!(
                    "the manifest does not pin the content of {}; run `benign-corpus --record` and commit what it writes\n",
                    source.name
                ));
            }
            if source.sha256 != digest {
                return Err(format!(
                    "{} is no longer the content the manifest pins\n  pinned   {}\n  fetched  {}\n  the commit is {}; re-record only after looking at what changed\n",
                    source.name,
                    source.sha256,
                    digest,
                    source.pin()
                ));
            }
        }
        files += plant_source(&mut ground, source, &content)?;
    }

    let machine = ground
        .finish()
        .map_err(|error| format!("the corpus machine could not be finished: {error}"))?;
    let enumeration = enumerate(&machine);
    let pack = RulePack::bundled().map_err(|error| format!("{error}\n"))?;
    let mut scanners = Scanners::new(&pack);
    let report = HitReport::of(&mut scanners, &enumeration.items)
        .map_err(|error| format!("the corpus could not be scanned: {error}\n"))?;

    Ok(Run::Scanned(Box::new(Scanned {
        sources: manifest.sources.len(),
        files,
        report,
        problems: enumeration
            .problems
            .iter()
            .map(|problem| format!("{} {}", problem.reason.as_str(), problem.surface))
            .collect(),
        digests,
    })))
}

/// Writes the digests of what was fetched back into the committed manifest.
pub fn record(root: &Path, digests: &[(String, String)]) -> Result<PathBuf, String> {
    let path = root.join(manifest::MANIFEST);
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}\n", path.display()))?;
    let recorded = Manifest::with_recorded(&text, digests);
    std::fs::write(&path, recorded).map_err(|error| format!("{}: {error}\n", path.display()))?;
    Ok(path)
}

/// The content of one source: the paths taken from its archive, or its one
/// file under its own name.
fn content_of(cache: &Cache, source: &Source) -> Result<Content, Problem> {
    let bytes = cache.bytes(&source.url(), &source.cache_name())?;
    match &source.shape {
        Shape::Archive { take } => {
            let paths: Vec<String> = take.iter().map(|take| take.path.clone()).collect();
            plant::taken(&bytes, &paths)
                .map_err(|what| Problem::Refused(format!("{}: {what}", source.name)))
        }
        Shape::File { path, .. } => {
            let name = path.rsplit('/').next().unwrap_or(path).to_string();
            Ok(Content::from([(name, bytes)]))
        }
    }
}

/// Lays one source out, one presentation at a time.
fn plant_source(ground: &mut Ground, source: &Source, content: &Content) -> Result<usize, String> {
    let mut written = 0;
    match &source.shape {
        Shape::Archive { take } => {
            for take in take {
                let part = plant::under(content, &take.path);
                written += ground
                    .plant(source, &part, take.present, take.agent)
                    .map_err(|error| format!("{} could not be laid out: {error}\n", source.name))?;
            }
        }
        Shape::File { present, agent, .. } => {
            written += ground
                .plant(source, content, *present, *agent)
                .map_err(|error| format!("{} could not be laid out: {error}\n", source.name))?;
        }
    }
    Ok(written)
}

/// What the Surface Adapters find on the machine the corpus was laid out on.
///
/// No system root is given, so no Managed Surface of the machine this runs on
/// is ever read, and no search path, so no binary of it is ever looked for.
fn enumerate(machine: &Machine) -> Enumeration {
    let host = Host::new(machine.home.clone(), machine.project_roots.clone());
    let roots = host.project_roots();
    let workspace = Workspace::new();
    let provenances = workspace.provenances(&host, roots);
    let mut enumeration = Enumeration::default();
    enumeration.extend(workspace.enumerate(&host, roots));
    enumeration.extend(ClaudeCode::new().enumerate(&host, roots));
    enumeration.extend(Codex::new().enumerate(&host, roots));
    provenances.stamp(&mut enumeration);
    enumeration
}
