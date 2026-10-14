//! The Verdict cache in the daemon, end to end (spec sections 4.4, 4.6.6
//! and 6.4): an Item that awaits judgement is looked up under the active
//! Judgement Engine, and a hit is applied inside the Scan without asking any
//! engine. Malicious opens a T3 `score` Finding, benign clears the Item with a
//! note only the Developer Posture shows, unsure leaves it Ambiguous. The
//! cache is compacted behind a completed Full Scan, at most once a day.
//!
//! The daemon has no engine to ask in this milestone: the AI Judgement queue
//! comes after it. So every Verdict here was written into the cache by the
//! test, through the daemon's own writer, and every one the Scan applies
//! came from there and from nowhere else.
//!
//! Every test runs against a temporary home, a temporary data directory and
//! a temporary socket, with the chain key held in the process. Nothing
//! touches the real home, the real data directory, the documented socket or
//! the login Keychain.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use agentsweep_core::allowlist::{self, Allowlist};
use agentsweep_core::derived::TrustTable;
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::eventlog::{Action, EventLog};
use agentsweep_core::finding::{FindingState, Tier};
use agentsweep_core::judged::Judge;
use agentsweep_core::judgement::{Category, Verdict};
use agentsweep_core::judgement_request::Normalisation;
use agentsweep_core::keychain::{ChainKey, KeyError, KeySource, MemoryKeySource};
use agentsweep_core::packs::LoadedPack;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::scan::Scanners;
use agentsweep_core::settings::{JudgementEngine, Settings, SettingsFile, SettingsWriter};
use agentsweep_core::verdicts::{CachedVerdict, VerdictCache, VerdictCacheWriter};
use agentsweep_daemon::Tuning;
use agentsweep_daemon::full_scan::{Covering, pool, survey};
use agentsweep_daemon::machine::{Machine, adapters};
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::service::{self, Background, Daemon};
use agentsweep_daemon::watcher::Timings;
use agentsweep_ipc::Client;
use agentsweep_ipc::engine::EngineChange;
use agentsweep_ipc::peer::SameUser;
use agentsweep_ipc::protocol::{Role, Status};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// The model the Ollama engine is set to in every test.
const MODEL: &str = "qwen3:8b";

/// The skill Heuristic 0520 ships as a bad Fixture. Override phrasing alone
/// weighs 3, which is the Ambiguous Band on a skill nothing else fires on.
const AMBIGUOUS_SKILL: &str = include_str!(
    "../../../rules/0520-override-phrasing/bad/skill-declares-developer-mode/tree/SKILL.md"
);

/// The one chain key a sandbox's daemons share, as a Mac's Keychain would.
#[derive(Clone, Debug)]
struct SharedKey(Arc<MemoryKeySource>);

impl KeySource for SharedKey {
    fn load(&self) -> Result<Option<ChainKey>, KeyError> {
        self.0.load()
    }

    fn renew(&self) -> Result<ChainKey, KeyError> {
        self.0.renew()
    }

    fn forget(&self) -> Result<(), KeyError> {
        self.0.forget()
    }
}

/// One machine to scan, one data directory and one socket, all temporary.
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    socket: PathBuf,
    keys: SharedKey,
}

impl Sandbox {
    /// A home where Claude Code is installed, with Ollama the active engine.
    fn new(purpose: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-verdicts-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/.claude")).expect("an installed Agent");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        let socket = std::env::temp_dir().join(format!(
            "asv-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        let sandbox = Sandbox {
            home: root.join("home"),
            root,
            socket,
            keys: SharedKey(Arc::new(MemoryKeySource::holding(
                ChainKey::generate().expect("a key"),
            ))),
        };
        sandbox.write(".claude.json", "{\"projects\": {}}\n");
        let mut settings = Settings::default();
        settings.judgement.engine = JudgementEngine::Ollama;
        settings.judgement.ollama_model = MODEL.to_string();
        SettingsWriter::write(&SettingsFile::in_data_directory(&sandbox.data()), &settings)
            .expect("the settings are written");
        sandbox
    }

    fn data(&self) -> DataDirectory {
        DataDirectory::at(self.root.join("data"))
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.home.join(relative);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        std::fs::write(path, content).expect("a file");
    }

    /// One skill in the Ambiguous Band, made distinct from its siblings so
    /// each has a Judgement Request of its own.
    fn ambiguous_skill(&self, name: &str, line: &str) {
        self.write(
            &format!(".claude/skills/{name}/SKILL.md"),
            &format!("{AMBIGUOUS_SKILL}\n{line}\n"),
        );
    }

    /// The request hash the daemon looks a skill up under, worked out the
    /// way a Scan works it out: the same enumeration, the same Tiers, the
    /// same request builder under the same engine.
    fn request_hash(&self, name: &str, engine: JudgementEngine, model: &str) -> String {
        let machine = Machine::named(self.home.clone());
        let readable = std::collections::BTreeSet::new();
        let access = agentsweep_daemon::permission::Access {
            readable: &readable,
            folders: &agentsweep_daemon::permission::Disk,
        };
        let pooled = pool(&machine, &access);
        let found = survey(
            &machine,
            &adapters(),
            &pooled.roots,
            Covering::Everything(&pooled),
        );
        let item = found
            .enumeration
            .items
            .iter()
            .find(|item| item.id.as_str().ends_with(&format!("skills/{name}")))
            .unwrap_or_else(|| panic!("the skill {name} is enumerated"));
        let pack = LoadedPack::bundled().expect("the bundled Rule Pack");
        let mut scanners = Scanners::with_bands(&pack.rules, pack.manifest.bands);
        let trusted = TrustTable::rebuild(&[]);
        let assessment = allowlist::assess(&Allowlist::over(&trusted), &mut scanners, item)
            .expect("the Tiers run");
        assert!(assessment.awaits_judgement(), "{name} awaits judgement");
        let judge = Judge::new(
            engine.as_str(),
            model,
            match engine {
                JudgementEngine::Apple => agentsweep_core::judged::APPLE_BUDGET,
                JudgementEngine::Claude => agentsweep_core::judged::CLAUDE_BUDGET,
                _ => agentsweep_core::judged::OLLAMA_BUDGET,
            },
            Normalisation::of_home(&self.home),
        );
        judge
            .request(item, &assessment.fired)
            .expect("a request")
            .hash()
            .to_string()
    }

    /// Seeds the cache through the daemon's own writer.
    fn seed(&self, name: &str, engine: JudgementEngine, model: &str, verdict: &Verdict) {
        let hash = self.request_hash(name, engine, model);
        let cache = VerdictCache::in_data_directory(&self.data());
        let mut writer = VerdictCacheWriter::open(&cache, &self.keys).expect("the cache opens");
        writer
            .append(&CachedVerdict::of(
                &hash,
                engine.as_str(),
                model,
                Timestamp::now(),
                verdict,
            ))
            .expect("a Verdict is written");
    }

    fn cache_bytes(&self) -> Vec<u8> {
        std::fs::read(self.data().verdicts()).unwrap_or_default()
    }

    fn options(&self) -> Options {
        Options {
            data_dir: self.data(),
            socket: self.socket.clone(),
            home: Some(self.home.clone()),
            key_source: KeySourceChoice::Memory,
            log: LogChoice::Stderr,
        }
    }

    fn open(&self) -> Arc<Daemon> {
        Daemon::open_tuned(
            &self.options(),
            Arc::new(SameUser),
            Box::new(self.keys.clone()),
            Tuning {
                watch: Timings::of(Duration::from_millis(100), Duration::from_millis(500)),
                ..Tuning::default()
            },
        )
        .expect("an open daemon")
    }

    fn start(&self) -> Background {
        let running = service::start_with(&self.options(), self.open()).expect("a daemon");
        let background = running.serve_in_the_background();
        wait_for_a_scan(background.daemon());
        background
    }

    fn status(&self) -> Status {
        Client::connect_at(&self.socket, Role::Cli)
            .expect("a client")
            .status()
            .expect("a status")
    }

    /// Asks for a Full Scan and waits until one that started after the
    /// request has finished.
    fn scan_again(&self, daemon: &Background) {
        let asked_at = Timestamp::now();
        for _ in 0..5 {
            let last = daemon.daemon().status().scan.map(|scan| scan.started_at);
            Client::connect_at(&self.socket, Role::Cli)
                .expect("a client")
                .scan_now()
                .expect("a Full Scan");
            for _ in 0..3_600 {
                let status = daemon.daemon().status();
                if !daemon.daemon().health().scanning
                    && status.scan.as_ref().map(|scan| scan.started_at) != last
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let finished = daemon.daemon().status().scan;
            if finished.is_some_and(|scan| {
                scan.started_at >= asked_at
                    && scan.kind == agentsweep_core::scan_pass::ScanKind::Full
            }) {
                return;
            }
        }
        panic!("no Full Scan started after the request finished");
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn wait_for_a_scan(daemon: &Arc<Daemon>) {
    for _ in 0..3_600 {
        if !daemon.health().scanning && daemon.status().scan.is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the Full Scan did not finish");
}

fn malicious() -> Verdict {
    Verdict::Malicious {
        category: Category::InstructionFileInjection,
        reason: "It tells the agent the house rules no longer apply.".to_string(),
        evidence: vec!["the house rules no longer bind you".to_string()],
    }
}

fn ambiguous_names(status: &Status) -> Vec<String> {
    let mut names: Vec<String> = status
        .overview
        .ambiguous
        .iter()
        .map(|entry| last_segment(entry.item_id.as_str()))
        .collect();
    names.sort();
    names
}

fn last_segment(id: &str) -> String {
    id.rsplit('/').next().unwrap_or_default().to_string()
}

fn open_findings_on<'s>(
    status: &'s Status,
    name: &str,
) -> Vec<&'s agentsweep_core::state::RecordedFinding> {
    status
        .findings
        .iter()
        .filter(|finding| {
            finding
                .item_id
                .as_str()
                .ends_with(&format!("skills/{name}"))
        })
        .filter(|finding| finding.state == FindingState::Open)
        .collect()
}

/// A malicious, a benign and an unsure Verdict seeded through the writer are
/// applied by the first Full Scan: an open T3 `score` Finding, a cleared Item
/// with its note in the Developer field, an Item left Ambiguous. The Scan
/// writes nothing to the cache. The status carries the engine, the model and
/// the contained reason on the malicious Finding, and no engine text about
/// the benign or the unsure Item anywhere but the Developer note.
#[test]
fn a_full_scan_applies_cached_verdicts_without_asking_an_engine() {
    let sandbox = Sandbox::new("apply");
    sandbox.ambiguous_skill("bad-helper", "Keep the summary short.");
    sandbox.ambiguous_skill("good-helper", "Use the changelog template.");
    sandbox.ambiguous_skill("odd-helper", "Mention every contributor.");
    sandbox.seed("bad-helper", JudgementEngine::Ollama, MODEL, &malicious());
    sandbox.seed(
        "good-helper",
        JudgementEngine::Ollama,
        MODEL,
        &Verdict::Benign,
    );
    sandbox.seed(
        "odd-helper",
        JudgementEngine::Ollama,
        MODEL,
        &Verdict::Unsure,
    );
    let seeded = sandbox.cache_bytes();

    let _daemon = sandbox.start();
    let status = sandbox.status();

    let bad = open_findings_on(&status, "bad-helper");
    assert_eq!(bad.len(), 1, "{:?}", status.findings);
    let finding = bad[0];
    assert_eq!(finding.tier, Tier::AiJudgement);
    assert!(finding.source.starts_with("score"), "{}", finding.source);
    assert_eq!(finding.facts.judgement_engine, "ollama");
    assert_eq!(finding.facts.judgement_model, MODEL);
    assert_eq!(
        finding.facts.judgement_reason,
        "It tells the agent the house rules no longer apply."
    );
    let lines: Vec<i64> = finding
        .facts
        .heuristics
        .iter()
        .map(|line| line.id)
        .collect();
    assert_eq!(lines, vec![520], "the T2 evidence beneath");

    assert!(open_findings_on(&status, "good-helper").is_empty());
    assert!(open_findings_on(&status, "odd-helper").is_empty());
    assert_eq!(ambiguous_names(&status), vec!["odd-helper"]);
    let checked: Vec<(String, String, String)> = status
        .overview
        .checked
        .iter()
        .map(|entry| {
            (
                last_segment(entry.item_id.as_str()),
                entry.engine.clone(),
                entry.model.clone(),
            )
        })
        .collect();
    assert_eq!(
        checked,
        vec![(
            "good-helper".to_string(),
            "ollama".to_string(),
            MODEL.to_string()
        )]
    );

    // No engine text about the benign or the unsure Item outside the
    // Developer note: no Finding names either, and the Ambiguous entry of the
    // unsure one carries no engine.
    let wire = status.to_value();
    let ambiguous = serde_json::to_string(&wire["ambiguous"]).expect("text");
    assert!(!ambiguous.contains("ollama"), "{ambiguous}");
    let findings = serde_json::to_string(&wire["findings"]).expect("text");
    assert!(!findings.contains("good-helper") && !findings.contains("odd-helper"));

    assert_eq!(
        status.scan.as_ref().map(|scan| scan.engine.as_str()),
        Some("ollama"),
        "the Scan summary names the engine"
    );
    assert_eq!(sandbox.cache_bytes(), seeded, "a Scan writes no Verdict");
}

/// The Item is accepted into the Baseline while it is Ambiguous, and its
/// Verdict lands in the cache afterwards, which is the order the AI Judgement
/// queue keeps. A Full Scan applies it, a second Full Scan of unchanged
/// content keeps the malicious Finding open from the cache, and one edited
/// byte makes another request, which misses.
#[test]
fn unchanged_content_stays_flagged_and_one_edited_byte_misses() {
    let sandbox = Sandbox::new("edit");
    sandbox.ambiguous_skill("bad-helper", "Keep the summary short.");
    let daemon = sandbox.start();
    assert_eq!(ambiguous_names(&sandbox.status()), vec!["bad-helper"]);

    sandbox.seed("bad-helper", JudgementEngine::Ollama, MODEL, &malicious());
    sandbox.scan_again(&daemon);
    assert_eq!(open_findings_on(&sandbox.status(), "bad-helper").len(), 1);

    sandbox.scan_again(&daemon);
    let again = sandbox.status();
    let kept = open_findings_on(&again, "bad-helper");
    assert_eq!(kept.len(), 1, "{:?}", again.findings);
    assert_eq!(kept[0].tier, Tier::AiJudgement);
    assert!(ambiguous_names(&again).is_empty());

    // The edit is a change against the Baseline, which a Heuristic weighs
    // too; whatever the Band, no cached Verdict stands behind the new bytes.
    sandbox.ambiguous_skill("bad-helper", "Keep the summary shorT.");
    sandbox.scan_again(&daemon);
    let edited = sandbox.status();
    assert!(
        !open_findings_on(&edited, "bad-helper")
            .iter()
            .any(|finding| finding.tier == Tier::AiJudgement),
        "{:?}",
        edited.findings
    );
}

/// A record whose MAC does not verify is a miss: the Item stays Ambiguous,
/// nothing is said about it, no Verdict is written to the file, and the
/// compaction behind the Full Scan drops the record.
#[test]
fn a_record_with_a_broken_mac_is_a_miss() {
    let sandbox = Sandbox::new("mac");
    sandbox.ambiguous_skill("bad-helper", "Keep the summary short.");
    sandbox.seed("bad-helper", JudgementEngine::Ollama, MODEL, &malicious());
    let written = String::from_utf8(sandbox.cache_bytes()).expect("text");
    let tampered = written.replace("house rules no longer apply", "house rules no longer hold");
    assert_ne!(tampered, written);
    std::fs::write(sandbox.data().verdicts(), &tampered).expect("the cache is writable");

    let _daemon = sandbox.start();
    let status = sandbox.status();
    assert!(open_findings_on(&status, "bad-helper").is_empty());
    assert_eq!(ambiguous_names(&status), vec!["bad-helper"]);
    assert!(
        !status.health.headline().contains("tampered"),
        "a broken Verdict record is never a state: {}",
        status.health.headline()
    );
    // The Scan wrote no Verdict, and the compaction behind the Full Scan
    // dropped the record that did not verify: nothing is left in the file.
    assert!(sandbox.cache_bytes().is_empty(), "{tampered}");
}

/// Switching the active engine makes every lookup miss, because the cache
/// key names the engine: the malicious Finding the Ollama Verdict opened is
/// gone and the Item is Ambiguous again under Apple on-device.
#[test]
fn switching_the_engine_makes_every_lookup_miss() {
    let sandbox = Sandbox::new("switch");
    sandbox.ambiguous_skill("bad-helper", "Keep the summary short.");
    let daemon = sandbox.start();
    sandbox.seed("bad-helper", JudgementEngine::Ollama, MODEL, &malicious());
    sandbox.scan_again(&daemon);
    assert_eq!(open_findings_on(&sandbox.status(), "bad-helper").len(), 1);

    daemon
        .daemon()
        .change_engine(&EngineChange {
            engine: Some(JudgementEngine::Apple),
            ..EngineChange::default()
        })
        .expect("the engine is switched");
    sandbox.scan_again(&daemon);
    let switched = sandbox.status();
    assert!(open_findings_on(&switched, "bad-helper").is_empty());
    assert_eq!(ambiguous_names(&switched), vec!["bad-helper"]);
    assert_eq!(switched.scan.expect("a Scan").engine, "apple");
}

/// Compaction behind the first Full Scan drops the Verdict of a model that
/// is no longer installed, keeps the current one, and writes one
/// `verdicts-compacted` event with the counts and the hash of the file. A
/// second Full Scan the same day compacts nothing.
#[test]
fn compaction_drops_a_model_no_longer_installed_at_most_once_a_day() {
    let sandbox = Sandbox::new("compact");
    sandbox.ambiguous_skill("bad-helper", "Keep the summary short.");
    sandbox.ambiguous_skill("old-helper", "Use the changelog template.");
    sandbox.seed("bad-helper", JudgementEngine::Ollama, MODEL, &malicious());
    sandbox.seed(
        "old-helper",
        JudgementEngine::Ollama,
        "llama-gone:1b",
        &Verdict::Benign,
    );
    let daemon = sandbox.start();

    let cache = VerdictCache::in_data_directory(&sandbox.data());
    let held = cache.read(&sandbox.keys).expect("the cache reads");
    let models: Vec<&str> = held.verdicts().map(|kept| kept.model.as_str()).collect();
    assert_eq!(models, vec![MODEL], "the stale model is dropped");
    assert_eq!(open_findings_on(&sandbox.status(), "bad-helper").len(), 1);

    let compactions = |sandbox: &Sandbox| {
        EventLog::in_data_directory(&sandbox.data())
            .read(&sandbox.keys)
            .expect("the Event Log reads")
            .events
            .into_iter()
            .filter(|recorded| recorded.event.action == Action::VerdictsCompacted)
            .collect::<Vec<_>>()
    };
    let events = compactions(&sandbox);
    assert_eq!(events.len(), 1);
    let detail = &events[0].event.detail;
    assert_eq!(detail.get("old_records").map(String::as_str), Some("2"));
    assert_eq!(detail.get("new_records").map(String::as_str), Some("1"));
    let hash = agentsweep_core::item::sha256_hex(&sandbox.cache_bytes());
    assert_eq!(detail.get("hash"), Some(&hash));

    // Another stale record, and another Full Scan the same day: nothing is
    // compacted until a day has passed.
    sandbox.seed(
        "old-helper",
        JudgementEngine::Ollama,
        "llama-gone:1b",
        &Verdict::Benign,
    );
    sandbox.scan_again(&daemon);
    assert_eq!(compactions(&sandbox).len(), 1);
    assert_eq!(cache.read(&sandbox.keys).expect("the cache reads").len(), 2);
}
