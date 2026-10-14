//! The defanged bad corpus: samples modelled on documented incidents, laid
//! out the way the Surface Adapters would find them and scanned with the
//! bundled Rule Pack.
//!
//! It is the first of the three sets of the AI Judgement eval (spec section
//! 4.4). With it goes the second half of the bad set the owner fixed: the bad
//! Fixtures of the Heuristics, because a T1 Fixture never reaches T3. The
//! report names, for every sample, the Rules and Heuristics that fired on each
//! of its Items and the Band each Item fell in, so the eval and later rule
//! work can see which samples reach T3; and it counts the bad set per ranked
//! class, because a result counts only with at least three samples for each
//! class T3 can see and thirty in all.
//!
//! The layout of one source, as spec section 4.2 fixes it:
//!
//! - `corpus/bad/<source>/PROVENANCE.md`: the public source and what was
//!   changed to defang it.
//! - `corpus/bad/<source>/<sample>/sample.toml`: the title, the ranked class,
//!   the catalogue row and, for a sample whose project is a repository, the
//!   paths it commits.
//! - `home/`: laid out as the home directory, `~/.claude.json` and all.
//! - `project/`: laid out as one project root. A path segment `dot-git` is
//!   laid out as `.git`, because git refuses to commit a directory of that
//!   name.
//! - `before/`: optional, a `home/` and a `project/` as they stood when the
//!   Baseline was taken. Every Item of the sample is then compared with it:
//!   unchanged, changed or added. Without it no Item has a Baseline, which is
//!   what a first Scan sees.
//!
//! Everything is laid out in a fresh temporary directory per sample and
//! removed afterwards. Nothing here reads the real home, and nothing here ever
//! runs a git binary: a repository is written as files, the index in its
//! documented binary form.

pub mod lint;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use agentsweep_core::finding::{Source, Tier};
use agentsweep_core::heuristics::Band;
use agentsweep_core::item::{BaselineState, Item};
use agentsweep_core::rules::RulePack;
use agentsweep_core::scan::Scanners;

use crate::benign::plant::Machine;
use crate::corpus;

/// Where the bad corpus sits under the repository root.
pub const CORPUS: &str = "corpus/bad";

/// The ranked classes of spec section 2.3 that T3 can see: every class whose
/// Heuristics carry a Weight. Class 6 is Exposure, which raises its own
/// Finding, never contributes to a Score and so never reaches the Ambiguous
/// Band.
pub const T3_CLASSES: [i64; 5] = [1, 2, 3, 4, 5];

/// The least number of corpus samples per class T3 can see for an eval result
/// to count. The Heuristics' bad Fixtures are part of the bad set but not of
/// this count: each is cut to show one Heuristic firing, and they alone would
/// clear the bar before a single sample exists.
pub const PER_CLASS: usize = 3;

/// The least number of corpus samples, over the classes T3 can see, for an
/// eval result to count.
pub const IN_ALL: usize = 30;

/// The commit `HEAD` stands on in every repository a sample lays out.
const HEAD_COMMIT: &str = "0badc0ffee0badc0ffee0badc0ffee0badc0ffee";

/// The ranked classes of spec section 2.3, by number.
pub const CLASSES: [(i64, &str); 6] = [
    (1, "malicious installed content"),
    (2, "repo-planted configuration"),
    (3, "dependency implants on user-level Surfaces"),
    (4, "instruction-file injection"),
    (5, "unexpected change to a user-level Surface"),
    (6, "Exposure"),
];

static NEXT: AtomicU32 = AtomicU32::new(0);

/// What `sample.toml` says about one sample.
#[derive(Clone, Debug)]
pub struct Sample {
    /// `<source>/<sample>`.
    pub name: String,
    /// Where the sample sits on disk.
    pub path: PathBuf,
    /// One line naming what the sample is.
    pub title: String,
    /// The ranked class of spec section 2.3.
    pub class: i64,
    /// The row of `docs/research/attack-catalogue.md` it is modelled on.
    pub row: String,
    /// The project paths the sample commits, when its project is a
    /// repository.
    pub tracked: Option<Vec<String>>,
}

impl Sample {
    /// Reads one sample directory.
    pub fn load(name: &str, path: &Path) -> Result<Sample, String> {
        let fail = |problem: String| format!("{name}: {problem}");
        let text = fs::read_to_string(path.join(lint::SAMPLE))
            .map_err(|error| fail(format!("{} could not be read: {error}", lint::SAMPLE)))?;
        let table: toml::Table = text
            .parse()
            .map_err(|error| fail(format!("{} is not TOML: {error}", lint::SAMPLE)))?;
        for key in table.keys() {
            if !matches!(key.as_str(), "title" | "class" | "row" | "tracked") {
                return Err(fail(format!("`{key}` is not a key of {}", lint::SAMPLE)));
            }
        }
        let text_of = |key: &str| -> Result<String, String> {
            table
                .get(key)
                .and_then(toml::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .ok_or_else(|| fail(format!("`{key}` is missing")))
        };
        let class = table
            .get("class")
            .and_then(toml::Value::as_integer)
            .filter(|class| (1..=6).contains(class))
            .ok_or_else(|| fail("`class` is one of the six ranked classes, 1 to 6".to_string()))?;
        let tracked = match table.get("tracked") {
            None => None,
            Some(value) => Some(
                value
                    .as_array()
                    .ok_or_else(|| fail("`tracked` is a list of project paths".to_string()))?
                    .iter()
                    .map(|path| {
                        path.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| fail("`tracked` is a list of project paths".to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };
        Ok(Sample {
            name: name.to_string(),
            path: path.to_path_buf(),
            title: text_of("title")?,
            class,
            row: text_of("row")?,
            tracked,
        })
    }

    /// The source directory the sample belongs to.
    pub fn source(&self) -> &str {
        self.name.split('/').next().unwrap_or_default()
    }
}

/// Every sample under a `corpus/bad/` directory, in source and sample order.
pub fn samples(corpus: &Path) -> Result<Vec<Sample>, String> {
    let mut loaded = Vec::new();
    for source in directories(corpus)? {
        let source_name = file_name(&source);
        for sample in directories(&source)? {
            let name = format!("{source_name}/{}", file_name(&sample));
            loaded.push(Sample::load(&name, &sample)?);
        }
    }
    Ok(loaded)
}

/// One Item of one sample and what the Tiers made of it.
#[derive(Clone, Debug)]
pub struct ItemLine {
    /// The ItemId, with the temporary directory the sample was laid out in
    /// taken out so the line reads the same on every run.
    pub item: String,
    /// The T1 Rules that fired.
    pub rules: Vec<i64>,
    /// The Heuristics that fired, Exposure Heuristics included.
    pub heuristics: Vec<i64>,
    /// The Score.
    pub score: i64,
    /// The Band that Score falls in.
    pub band: Band,
    /// True when the Item would be handed to AI Judgement: Ambiguous, and
    /// nothing else raised a Finding on it.
    pub reaches_t3: bool,
}

/// One sample and every Item the adapters found in it.
#[derive(Clone, Debug)]
pub struct SampleReport {
    /// The sample as `sample.toml` describes it.
    pub sample: Sample,
    /// Every Item, in id order.
    pub items: Vec<ItemLine>,
}

impl SampleReport {
    /// Every Rule and Heuristic id that fired on any Item of the sample.
    pub fn fired(&self) -> BTreeSet<i64> {
        self.items
            .iter()
            .flat_map(|line| line.rules.iter().chain(&line.heuristics).copied())
            .collect()
    }

    /// True when at least one Item of the sample reaches T3.
    pub fn reaches_t3(&self) -> bool {
        self.items.iter().any(|line| line.reaches_t3)
    }
}

/// What one run of the bad corpus came to.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Every sample, in source and sample order.
    pub samples: Vec<SampleReport>,
    /// The bad Fixtures of the Heuristics, counted per class: the other half
    /// of the bad set.
    pub heuristic_fixtures: BTreeMap<i64, usize>,
    /// What an adapter could not read, per sample.
    pub problems: Vec<String>,
}

impl Report {
    /// The corpus samples per class.
    pub fn samples_by_class(&self) -> BTreeMap<i64, usize> {
        let mut counts = BTreeMap::new();
        for report in &self.samples {
            *counts.entry(report.sample.class).or_default() += 1;
        }
        counts
    }

    /// The ranked classes no corpus sample stands for.
    pub fn classes_without_a_sample(&self) -> Vec<i64> {
        let counts = self.samples_by_class();
        CLASSES
            .iter()
            .map(|(class, _)| *class)
            .filter(|class| !counts.contains_key(class))
            .collect()
    }

    /// The whole bad set per class: corpus samples plus Heuristic bad
    /// Fixtures.
    pub fn bad_set_by_class(&self) -> BTreeMap<i64, usize> {
        let mut counts = self.samples_by_class();
        for (class, count) in &self.heuristic_fixtures {
            *counts.entry(*class).or_default() += count;
        }
        counts
    }

    /// The corpus samples over the classes T3 can see.
    pub fn samples_t3_total(&self) -> usize {
        let counts = self.samples_by_class();
        T3_CLASSES
            .iter()
            .map(|class| counts.get(class).copied().unwrap_or_default())
            .sum()
    }

    /// True when a class T3 can see has fewer corpus samples than an eval
    /// result needs.
    pub fn insufficient(&self, class: i64) -> bool {
        T3_CLASSES.contains(&class)
            && self
                .samples_by_class()
                .get(&class)
                .copied()
                .unwrap_or_default()
                < PER_CLASS
    }

    /// True when the corpus is large enough for an eval result to count: at
    /// least three samples for each class T3 can see, and thirty in all.
    /// Until then the eval reports "insufficient".
    pub fn counts_for_a_result(&self) -> bool {
        !T3_CLASSES.iter().any(|class| self.insufficient(*class))
            && self.samples_t3_total() >= IN_ALL
    }

    /// The report, ready to print.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let items: usize = self.samples.iter().map(|report| report.items.len()).sum();
        let _ = writeln!(
            out,
            "{} samples, {} Items laid out as the adapters would see them",
            self.samples.len(),
            items
        );
        for report in &self.samples {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{}  class {}  row {}",
                report.sample.name, report.sample.class, report.sample.row
            );
            let _ = writeln!(out, "  {}", report.sample.title);
            for line in &report.items {
                let rules = ids(&line.rules);
                let heuristics = ids(&line.heuristics);
                let t3 = if line.reaches_t3 { "  reaches T3" } else { "" };
                let _ = writeln!(out, "  {}", line.item);
                let _ = writeln!(
                    out,
                    "    rules {rules}  heuristics {heuristics}  score {}  {}{t3}",
                    line.score, line.band
                );
            }
        }

        let _ = writeln!(out);
        let reaching = self
            .samples
            .iter()
            .filter(|report| report.reaches_t3())
            .count();
        let silent: Vec<&str> = self
            .samples
            .iter()
            .filter(|report| report.fired().is_empty())
            .map(|report| report.sample.name.as_str())
            .collect();
        let _ = writeln!(out, "{reaching} samples have an Item that reaches T3.");
        if self.samples.is_empty() {
            let _ = writeln!(out, "The corpus holds no sample yet.");
        } else if silent.is_empty() {
            let _ = writeln!(out, "Something fired on every sample.");
        } else {
            let _ = writeln!(out, "Nothing fired on: {}", silent.join(", "));
        }

        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "The bad set per ranked class (corpus samples + Heuristic bad Fixtures):"
        );
        let samples = self.samples_by_class();
        for (class, name) in CLASSES {
            let in_corpus = samples.get(&class).copied().unwrap_or_default();
            let fixtures = self
                .heuristic_fixtures
                .get(&class)
                .copied()
                .unwrap_or_default();
            let seen = if !T3_CLASSES.contains(&class) {
                "  (never reaches T3)"
            } else if self.insufficient(class) {
                "  insufficient"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "  {class}  {in_corpus:>3} + {fixtures:>3} = {:>3}  {name}{seen}",
                in_corpus + fixtures
            );
        }
        let missing = self.classes_without_a_sample();
        if missing.is_empty() {
            let _ = writeln!(out, "Every ranked class has at least one corpus sample.");
        } else {
            let _ = writeln!(
                out,
                "No corpus sample for class {}.",
                missing
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let verdict = if self.counts_for_a_result() {
            "sufficient, an eval result counts"
        } else {
            "insufficient, no eval result counts"
        };
        let _ = writeln!(
            out,
            "{} corpus samples in the classes T3 can see; a result needs at least {PER_CLASS} per class and {IN_ALL} in all: {verdict}.",
            self.samples_t3_total()
        );

        if !self.problems.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "Surfaces an adapter could not read all the way through:"
            );
            for problem in &self.problems {
                let _ = writeln!(out, "  {problem}");
            }
        }
        out
    }
}

fn ids(ids: &[i64]) -> String {
    if ids.is_empty() {
        return "-".to_string();
    }
    ids.iter()
        .map(|id| format!("{id:04}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Lints the corpus, lays every sample out on a temporary copy, scans it and
/// counts the bad set. A lint problem or a sample the adapters found nothing
/// in is a failure, because neither proves anything. An empty corpus is not:
/// it reports every class T3 can see as insufficient.
///
/// `corpus` is a `corpus/bad/` directory and `rules` the Rule corpus whose bad
/// Heuristic Fixtures make up the other half of the bad set; both are taken
/// apart so a test can plant a corpus of its own beside the real Rules.
pub fn run(corpus: &Path, rules: &Path, pack: &RulePack) -> Result<Report, String> {
    let problems = lint::lint(corpus);
    if !problems.is_empty() {
        let mut message = format!(
            "the bad corpus is not defanged ({} problems):\n",
            problems.len()
        );
        for problem in problems {
            let _ = writeln!(message, "  {problem}");
        }
        return Err(message);
    }

    let mut report = Report::default();
    let mut scanners = Scanners::new(pack);
    for sample in samples(corpus)? {
        let (items, problems) = scan_sample(&sample, &mut scanners)?;
        if items.is_empty() {
            return Err(format!(
                "{}: the adapters found no Item in it, so it is not laid out where an Agent looks\n",
                sample.name
            ));
        }
        report.problems.extend(
            problems
                .into_iter()
                .map(|problem| format!("{}: {problem}", sample.name)),
        );
        report.samples.push(SampleReport { sample, items });
    }

    let fixtures = corpus::fixtures(rules).map_err(|error| format!("{error}\n"))?;
    for fixture in fixtures.iter().filter(|fixture| fixture.bad) {
        let Some(meta) = pack.metas().find(|meta| meta.id == fixture.rule_id) else {
            continue;
        };
        if meta.tier == Tier::Heuristics {
            *report.heuristic_fixtures.entry(meta.class).or_default() += 1;
        }
    }
    Ok(report)
}

/// Lays one sample out in a fresh temporary directory, scans every Item the
/// adapters find there and removes the directory again.
fn scan_sample(
    sample: &Sample,
    scanners: &mut Scanners<'_>,
) -> Result<(Vec<ItemLine>, Vec<String>), String> {
    let work = std::env::temp_dir().join(format!(
        "agentsweep-bad-corpus-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let result = scan_in(sample, scanners, &work);
    let _ = fs::remove_dir_all(&work);
    result
}

fn scan_in(
    sample: &Sample,
    scanners: &mut Scanners<'_>,
    work: &Path,
) -> Result<(Vec<ItemLine>, Vec<String>), String> {
    let fail = |error: io::Error| format!("{} could not be laid out: {error}\n", sample.name);
    let project = sample.name.replace('/', "-");

    let before = sample.path.join("before");
    let accepted: Option<BTreeMap<String, String>> = if before.is_dir() {
        let machine = lay_out(&before, work, &project, sample.tracked.as_deref()).map_err(fail)?;
        let enumeration = crate::benign::enumerate(&machine);
        Some(
            enumeration
                .items
                .iter()
                .map(|item| (item.id.to_string(), item.content_hash.clone()))
                .collect(),
        )
    } else {
        None
    };

    let machine = lay_out(&sample.path, work, &project, sample.tracked.as_deref()).map_err(fail)?;
    let mut enumeration = crate::benign::enumerate(&machine);
    if let Some(accepted) = &accepted {
        for item in &mut enumeration.items {
            item.baseline = baseline_of(item, accepted);
        }
    }

    let prefixes = prefixes(work);
    let strip = |text: &str| -> String {
        let mut text = text.to_string();
        for prefix in &prefixes {
            text = text.replace(prefix.as_str(), "");
        }
        text
    };

    let mut lines = Vec::new();
    for item in &enumeration.items {
        let assessment = scanners
            .assess(item)
            .map_err(|error| format!("{}: the scan failed: {error}\n", sample.name))?;
        let mut rules = BTreeSet::new();
        let mut heuristics: BTreeSet<i64> = assessment.fired.iter().map(|fired| fired.id).collect();
        for finding in &assessment.findings {
            let Source::Rule(id) = finding.source else {
                continue;
            };
            match finding.tier {
                Tier::Rules => {
                    rules.insert(id);
                }
                Tier::Heuristics => {
                    heuristics.insert(id);
                }
                _ => {}
            }
            heuristics.extend(finding.heuristics.iter().map(|fired| fired.id));
        }
        lines.push(ItemLine {
            item: strip(&item.id.to_string()),
            rules: rules.into_iter().collect(),
            heuristics: heuristics.into_iter().collect(),
            score: assessment.score,
            band: assessment.band,
            reaches_t3: assessment.awaits_judgement(),
        });
    }
    lines.sort_by(|a, b| a.item.cmp(&b.item));
    let problems = enumeration
        .problems
        .iter()
        .map(|problem| strip(&format!("{} {}", problem.reason.as_str(), problem.surface)))
        .collect();
    Ok((lines, problems))
}

/// The Baseline state of an Item against what the `before/` layout held.
fn baseline_of(item: &Item, accepted: &BTreeMap<String, String>) -> BaselineState {
    match accepted.get(&item.id.to_string()) {
        Some(hash) if *hash == item.content_hash => BaselineState::Unchanged,
        Some(_) => BaselineState::Changed,
        None => BaselineState::Added,
    }
}

/// The spellings of the temporary directory an ItemId may carry: as written
/// and as the file system resolves it, each with a trailing separator.
fn prefixes(work: &Path) -> Vec<String> {
    let mut prefixes = Vec::new();
    for path in [Some(work.to_path_buf()), work.canonicalize().ok()]
        .into_iter()
        .flatten()
    {
        let spelled = format!("{}/", path.display());
        if !prefixes.contains(&spelled) {
            prefixes.push(spelled);
        }
    }
    // The longer spelling first, so a resolved path is not cut in half by its
    // unresolved prefix.
    prefixes.sort_by_key(|prefix| std::cmp::Reverse(prefix.len()));
    prefixes
}

/// Lays one `home/` and `project/` pair out under a fresh working directory.
fn lay_out(
    from: &Path,
    work: &Path,
    project: &str,
    tracked: Option<&[String]>,
) -> io::Result<Machine> {
    let _ = fs::remove_dir_all(work);
    let home = work.join("home");
    fs::create_dir_all(home.join(".claude"))?;
    fs::create_dir_all(home.join(".codex"))?;
    if from.join("home").is_dir() {
        copy_tree(&from.join("home"), &home)?;
    }

    let mut project_roots = Vec::new();
    if from.join("project").is_dir() {
        let root = work.join("projects").join(project);
        fs::create_dir_all(&root)?;
        copy_tree(&from.join("project"), &root)?;
        if let Some(tracked) = tracked {
            make_repository(&root, tracked)?;
        }
        project_roots.push(root);
    }
    Ok(Machine {
        home,
        project_roots,
    })
}

/// Copies a sample tree, laying every `dot-git` segment out as `.git` and
/// giving every git hook the execute bit git needs to run it.
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let target_name = if name == "dot-git" { ".git" } else { &name };
        let target = to.join(target_name);
        if entry.file_type()?.is_dir() {
            fs::create_dir_all(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::write(&target, fs::read(entry.path())?)?;
            let in_hooks = to.file_name().is_some_and(|name| name == "hooks")
                && to
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == ".git");
            if in_hooks {
                set_executable(&target)?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Turns a laid-out project into a repository that commits exactly the given
/// paths: `HEAD`, one ref, a configuration unless the sample brings its own,
/// and the index. A sample whose `.git` is a gitdir pointer is left as it is.
fn make_repository(root: &Path, tracked: &[String]) -> io::Result<()> {
    let git = root.join(".git");
    if git.is_file() {
        return Ok(());
    }
    fs::create_dir_all(git.join("refs").join("heads"))?;
    if !git.join("HEAD").is_file() {
        fs::write(git.join("HEAD"), b"ref: refs/heads/main\n")?;
    }
    fs::write(
        git.join("refs").join("heads").join("main"),
        format!("{HEAD_COMMIT}\n"),
    )?;
    if !git.join("config").is_file() {
        fs::write(
            git.join("config"),
            b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        )?;
    }
    fs::write(git.join("index"), index_bytes(tracked))
}

/// The bytes of a version 2 index tracking these paths, with the trailing
/// checksum a reader verifies. Nothing ever looks an object up, so each entry's
/// object id is a stand-in derived from its path.
fn index_bytes(paths: &[String]) -> Vec<u8> {
    let mut sorted: Vec<&str> = paths.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();

    let mut out = Vec::new();
    out.extend_from_slice(b"DIRC");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for path in sorted {
        // ctime, its nanoseconds, mtime, its nanoseconds, device, inode.
        for _ in 0..6 {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        // A regular file, mode 644.
        out.extend_from_slice(&0o100644u32.to_be_bytes());
        // Owner, group, size.
        for _ in 0..3 {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        out.extend_from_slice(&sha1(path.as_bytes()));
        out.extend_from_slice(&(path.len().min(0xfff) as u16).to_be_bytes());
        out.extend_from_slice(path.as_bytes());
        let padding = 8 - ((62 + path.len()) % 8);
        out.extend(std::iter::repeat_n(0u8, padding));
    }
    let checksum = sha1(&out);
    out.extend_from_slice(&checksum);
    out
}

fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = gix_hash::hasher(gix_hash::Kind::Sha1);
    hasher.update(bytes);
    let id = hasher.try_finalize().expect("a SHA-1 digest");
    let mut digest = [0u8; 20];
    digest.copy_from_slice(&id.as_slice()[..20]);
    digest
}

fn directories(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found: Vec<PathBuf> = fs::read_dir(path)
        .map_err(|error| format!("{} could not be read: {error}\n", path.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    found.sort();
    Ok(found)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_index_of_no_paths_is_a_header_and_a_checksum() {
        let bytes = index_bytes(&[]);
        assert_eq!(&bytes[..4], b"DIRC");
        assert_eq!(bytes.len(), 12 + 20);
    }

    #[test]
    fn the_baseline_of_an_item_compares_its_hash_with_the_accepted_one() {
        let item = Item::file(
            "claude-code",
            agentsweep_core::item::Scope::User,
            agentsweep_core::item::Kind::InstructionFile,
            "~/.claude/CLAUDE.md",
            PathBuf::from("/nowhere/.claude/CLAUDE.md"),
            agentsweep_core::item::Provenance::Manual,
            agentsweep_core::item::Activation::Active,
            b"# notes\n".to_vec(),
        );
        let mut accepted = BTreeMap::new();
        assert_eq!(baseline_of(&item, &accepted), BaselineState::Added);
        accepted.insert(item.id.to_string(), "other".to_string());
        assert_eq!(baseline_of(&item, &accepted), BaselineState::Changed);
        accepted.insert(item.id.to_string(), item.content_hash.clone());
        assert_eq!(baseline_of(&item, &accepted), BaselineState::Unchanged);
    }
}
