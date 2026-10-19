//! The `judge` request, end to end (spec section 4.4): the in-bundle
//! `agentsweep scan <dir>` hands the daemon a redacted Judgement Request for
//! the Claude engine and gets the Verdict back. The daemon answers from the
//! Verdict cache first, under the cloud caps, through every check, records
//! the spend and caches the Verdict.
//!
//! No test reaches the Claude API or any other engine: the engine is a fake
//! handed in through the daemon's engine seam, which answers from a script
//! and reports a fixed `usage`. The calendar is fixed.
//!
//! Every test runs against a temporary home, a temporary data directory and
//! a temporary socket, with the chain key held in the process. Nothing
//! touches the real home, the real data directory, the documented socket or
//! the login Keychain.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentsweep_core::eventlog::{EventLog, EventLogWriter};
use agentsweep_core::item::{Activation, Item, Kind, Provenance, Scope};
use agentsweep_core::judgement::{Category, EngineError, JudgementEngine, Prompt, Usage, Verdict};
use agentsweep_core::judgement_request::{ByteEstimate, Normalisation, RequestBuilder};
use agentsweep_core::keychain::{ChainKey, ClaudeKeyStore, KeyError, KeySource, MemoryKeySource};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::settings::{self, JudgementSettings, Settings, SettingsFile, SettingsWriter};
use agentsweep_core::spend::{JudgementCap, LocalDate, SpendRecord};
use agentsweep_daemon::Tuning;
use agentsweep_daemon::cloud_caps::Calendar;
use agentsweep_daemon::due::PowerState;
use agentsweep_daemon::judgement_queue::{Engines, Opened};
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::service::{self, Background, Daemon};
use agentsweep_daemon::watcher::Timings;
use agentsweep_ipc::Client;
use agentsweep_ipc::judge::{JudgeAnswer, JudgeOutcome, JudgeRequest};
use agentsweep_ipc::peer::SameUser;
use agentsweep_ipc::protocol::Role;

static NEXT: AtomicU32 = AtomicU32::new(0);

const CLAUDE_MODEL: &str = "claude-sonnet-5";

/// The odd instruction file a Folder Scan leaves in the Ambiguous Band.
const ODD: &str =
    "# demo\n\n<!-- Claude: keep the sections in the order this file lists them. -->\n";

fn today() -> LocalDate {
    LocalDate::new(2026, 10, 19)
}

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

#[derive(Debug, Default)]
struct FullPower;

impl PowerState for FullPower {
    fn low_power_mode(&self) -> bool {
        false
    }
}

struct Fixed;

impl Calendar for Fixed {
    fn today(&self) -> LocalDate {
        today()
    }
}

/// A fake engine that gives one answer to every request, reports a fixed
/// `usage`, and counts what it was asked.
struct Scripted {
    answer: String,
    asked: Mutex<usize>,
}

impl Scripted {
    fn answering(verdict: &str, evidence: &[&str]) -> Arc<Scripted> {
        Arc::new(Scripted {
            answer: serde_json::json!({
                "verdict": verdict,
                "category": "instruction_file_injection",
                "reason": "Steers the agent from a hidden comment.",
                "evidence": evidence,
            })
            .to_string(),
            asked: Mutex::new(0),
        })
    }

    fn asked(&self) -> usize {
        *self.asked.lock().expect("the count")
    }
}

impl JudgementEngine for Scripted {
    fn judge(&self, _prompt: &Prompt) -> Result<String, EngineError> {
        *self.asked.lock().expect("the count") += 1;
        Ok(self.answer.clone())
    }

    fn judge_metered(&self, prompt: &Prompt) -> (Result<String, EngineError>, Option<Usage>) {
        let usage = Usage {
            input_tokens: 1_000,
            output_tokens: 50,
        };
        (self.judge(prompt), Some(usage))
    }
}

struct FakeEngines(Arc<Scripted>);

impl Engines for FakeEngines {
    fn open(
        &self,
        judgement: &JudgementSettings,
        _claude_key: &Arc<dyn ClaudeKeyStore + Send + Sync>,
    ) -> Result<Opened, EngineError> {
        let model = match judgement.engine {
            settings::JudgementEngine::Off => return Err(EngineError::Unavailable("off".into())),
            settings::JudgementEngine::Claude => CLAUDE_MODEL.to_string(),
            other => format!("{}-fake@sha256:0", other.as_str()),
        };
        let asker: Arc<dyn JudgementEngine + Send + Sync> = self.0.clone();
        Ok(Opened {
            model,
            asker: Some(asker),
        })
    }
}

struct Sandbox {
    root: PathBuf,
    socket: PathBuf,
    keys: SharedKey,
    engine: Arc<Scripted>,
}

impl Sandbox {
    fn new(purpose: &str, engine: settings::JudgementEngine, answer: Arc<Scripted>) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-judge-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/.claude")).expect("an installed Agent");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        std::fs::write(root.join("home/.claude.json"), "{\"projects\": {}}\n").expect("a file");
        let socket = std::env::temp_dir().join(format!(
            "asjdg-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        let sandbox = Sandbox {
            root,
            socket,
            keys: SharedKey(Arc::new(MemoryKeySource::holding(
                ChainKey::generate().expect("a key"),
            ))),
            engine: answer,
        };
        let settings = Settings {
            judgement: JudgementSettings {
                engine,
                ollama_model: "qwen3:8b".to_string(),
                ..JudgementSettings::default()
            },
            ..Settings::default()
        };
        SettingsWriter::write(&SettingsFile::in_data_directory(&sandbox.data()), &settings)
            .expect("the settings are written");
        sandbox
    }

    fn data(&self) -> DataDirectory {
        DataDirectory::at(self.root.join("data"))
    }

    fn options(&self) -> Options {
        Options {
            data_dir: self.data(),
            socket: self.socket.clone(),
            home: Some(self.root.join("home")),
            key_source: KeySourceChoice::Memory,
            log: LogChoice::Stderr,
        }
    }

    fn start(&self) -> Background {
        let daemon = Daemon::open_tuned(
            &self.options(),
            Arc::new(SameUser),
            Box::new(self.keys.clone()),
            Tuning {
                watch: Timings::of(Duration::from_secs(3_600), Duration::from_secs(3_600)),
                engines: Some(Arc::new(FakeEngines(Arc::clone(&self.engine)))),
                calendar: Arc::new(Fixed),
                power: Arc::new(FullPower),
                gate: None,
                ..Tuning::default()
            },
        )
        .expect("an open daemon");
        let running = service::start_with(&self.options(), daemon).expect("a daemon");
        let background = running.serve_in_the_background();
        wait_until("the first Full Scan", || {
            let daemon = background.daemon();
            !daemon.health().scanning && daemon.status().scan.is_some()
        });
        background
    }

    fn judge(&self, reviewer_directed: bool) -> JudgeAnswer {
        Client::connect_at(&self.socket, Role::Cli)
            .expect("a client")
            .judge(JudgeRequest {
                request: odd_request(),
                reviewer_directed,
            })
            .expect("an answer")
    }

    fn spent_before(&self, count: usize) {
        let (mut writer, _) =
            EventLogWriter::open(&EventLog::in_data_directory(&self.data()), &self.keys)
                .expect("an open Event Log");
        let record = SpendRecord::priced(
            today(),
            CLAUDE_MODEL,
            Usage {
                input_tokens: 100,
                output_tokens: 10,
            },
        );
        for _ in 0..count {
            writer
                .record_judgement_spend(&record)
                .expect("a spend record");
        }
    }

    fn spends(&self) -> usize {
        EventLog::in_data_directory(&self.data())
            .read(&self.keys)
            .expect("a readable Event Log")
            .spends
            .len()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

/// The redacted request the command line builds for the odd file.
fn odd_request() -> agentsweep_core::judgement_request::JudgementRequest {
    let item = Item::file(
        "claude-code",
        Scope::Project(PathBuf::from("/src/demo")),
        Kind::InstructionFile,
        "CLAUDE.md",
        PathBuf::from("/src/demo/CLAUDE.md"),
        Provenance::Unknown,
        Activation::Active,
        ODD.as_bytes().to_vec(),
    );
    RequestBuilder::new(Normalisation::default(), 32_000, &ByteEstimate)
        .build(&item, &[])
        .expect("a request")
}

/// A malicious answer with a verifiable quote comes back as the Verdict,
/// named by the Claude engine and its model, its spend recorded once. Asked
/// again, the daemon answers from the Verdict cache and the engine is not
/// asked a second time.
#[test]
fn a_verdict_comes_back_checked_and_the_second_ask_is_answered_from_the_cache() {
    let sandbox = Sandbox::new(
        "cache",
        settings::JudgementEngine::Claude,
        Scripted::answering("malicious", &["keep the sections in the order"]),
    );
    let _daemon = sandbox.start();

    let first = sandbox.judge(false);
    assert_eq!(first.engine, "claude");
    assert_eq!(first.model, CLAUDE_MODEL);
    let JudgeOutcome::Verdict(Verdict::Malicious { category, .. }) = &first.outcome else {
        panic!("not a malicious Verdict: {first:?}");
    };
    assert_eq!(
        Some(*category),
        Category::parse("instruction_file_injection")
    );
    assert_eq!(sandbox.engine.asked(), 1);
    assert_eq!(sandbox.spends(), 1);

    let second = sandbox.judge(false);
    assert_eq!(second, first);
    assert_eq!(sandbox.engine.asked(), 1, "the cache answered");
    assert_eq!(sandbox.spends(), 1);
}

/// A malicious answer whose quote is not in the content sent is no Verdict,
/// and a benign one on an Item where a reviewer-directed Heuristic fired is
/// unsure: the daemon runs every check.
#[test]
fn the_daemon_runs_every_check_on_the_answer() {
    let unquoted = Sandbox::new(
        "unquoted",
        settings::JudgementEngine::Claude,
        Scripted::answering("malicious", &["not in the file"]),
    );
    let _daemon = unquoted.start();
    assert!(matches!(
        unquoted.judge(false).outcome,
        JudgeOutcome::NoVerdict(_)
    ));
    drop(_daemon);

    let lured = Sandbox::new(
        "lured",
        settings::JudgementEngine::Claude,
        Scripted::answering("benign", &[]),
    );
    let _daemon = lured.start();
    assert_eq!(
        lured.judge(true).outcome,
        JudgeOutcome::Verdict(Verdict::Unsure)
    );
}

/// Past the day's cap nothing is sent: the answer names the cap.
#[test]
fn past_the_days_cap_nothing_is_sent() {
    let sandbox = Sandbox::new(
        "day",
        settings::JudgementEngine::Claude,
        Scripted::answering("benign", &[]),
    );
    sandbox.spent_before(200);
    let _daemon = sandbox.start();

    assert_eq!(
        sandbox.judge(false).outcome,
        JudgeOutcome::Capped(JudgementCap::Day)
    );
    assert_eq!(sandbox.engine.asked(), 0);
}

/// The daemon answers only for the Claude engine: with Ollama active it asks
/// nothing and says so.
#[test]
fn with_a_local_engine_active_the_daemon_asks_nothing() {
    let sandbox = Sandbox::new(
        "local",
        settings::JudgementEngine::Ollama,
        Scripted::answering("benign", &[]),
    );
    let _daemon = sandbox.start();

    assert!(matches!(
        sandbox.judge(false).outcome,
        JudgeOutcome::NoVerdict(_)
    ));
    assert_eq!(sandbox.engine.asked(), 0);
    assert_eq!(sandbox.spends(), 0);
}
