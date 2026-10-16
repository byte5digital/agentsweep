//! The cloud caps on the Claude engine, end to end (spec section 4.4): at
//! most 200 Items a day and $5 a month, counted from the `usage` each answer
//! reports and written to the Event Log as `judgement-spend` records, on top
//! of the per-Scan cap. A request that would start past a cap is not sent,
//! the Item gets no Verdict and waits for the next Scan, and the cap notice
//! in status names how many wait.
//!
//! No test reaches the Claude API or any other engine. The engine is a fake
//! handed in through the daemon's engine seam: it answers unsure in-process
//! and reports a fixed `usage`. The calendar is one the test moves.
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
use agentsweep_core::judgement::{EngineError, JudgementEngine, Prompt, Usage};
use agentsweep_core::keychain::{ChainKey, ClaudeKeyStore, KeyError, KeySource, MemoryKeySource};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::settings::{self, JudgementSettings, Settings, SettingsFile, SettingsWriter};
use agentsweep_core::spend::{CapNotice, JudgementCap, LocalDate, SpendRecord};
use agentsweep_core::state::Trigger;
use agentsweep_daemon::Tuning;
use agentsweep_daemon::cloud_caps::Calendar;
use agentsweep_daemon::due::PowerState;
use agentsweep_daemon::judgement_queue::{Engines, Opened};
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::service::{self, Background, Daemon};
use agentsweep_daemon::watcher::Timings;
use agentsweep_ipc::Client;
use agentsweep_ipc::peer::SameUser;
use agentsweep_ipc::protocol::{Role, Status};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// The skill Heuristic 0520 ships as a bad Fixture: the Ambiguous Band on a
/// skill nothing else fires on.
const AMBIGUOUS_SKILL: &str = include_str!(
    "../../../rules/0520-override-phrasing/bad/skill-declares-developer-mode/tree/SKILL.md"
);

/// The model the fake answers as when the Claude engine is active: the one
/// the price table names.
const CLAUDE_MODEL: &str = "claude-sonnet-5";

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

/// Never Low Power Mode, whatever the Mac running the suite is in, so the
/// Full Scan at start feeds the queue.
#[derive(Debug, Default)]
struct FullPower;

impl PowerState for FullPower {
    fn low_power_mode(&self) -> bool {
        false
    }
}

/// A calendar the test moves.
struct MovedCalendar(Mutex<LocalDate>);

impl MovedCalendar {
    fn set(&self, date: LocalDate) {
        *self.0.lock().expect("the calendar") = date;
    }
}

impl Calendar for MovedCalendar {
    fn today(&self) -> LocalDate {
        *self.0.lock().expect("the calendar")
    }
}

/// A fake engine that answers unsure and reports the same `usage` for every
/// request, and keeps the marker of every skill it was asked about.
struct Metered {
    usage: Usage,
    asked: Mutex<Vec<String>>,
}

impl Metered {
    fn new(input_tokens: u64, output_tokens: u64) -> Arc<Metered> {
        Arc::new(Metered {
            usage: Usage {
                input_tokens,
                output_tokens,
            },
            asked: Mutex::new(Vec::new()),
        })
    }

    fn asked(&self) -> Vec<String> {
        let mut asked = self.asked.lock().expect("the list").clone();
        asked.sort();
        asked
    }
}

impl JudgementEngine for Metered {
    fn judge(&self, prompt: &Prompt) -> Result<String, EngineError> {
        let marker = prompt
            .user()
            .split("Marker: ")
            .nth(1)
            .and_then(|rest| rest.split('.').next())
            .unwrap_or_default()
            .to_string();
        self.asked.lock().expect("the list").push(marker);
        Ok(serde_json::json!({
            "verdict": "unsure",
            "category": "instruction_file_injection",
            "reason": "",
            "evidence": [],
        })
        .to_string())
    }

    fn judge_metered(&self, prompt: &Prompt) -> (Result<String, EngineError>, Option<Usage>) {
        (self.judge(prompt), Some(self.usage))
    }
}

/// The engine seam: every engine the settings name is the one fake.
struct FakeEngines(Arc<Metered>);

impl Engines for FakeEngines {
    fn open(
        &self,
        judgement: &JudgementSettings,
        _claude_key: &Arc<dyn ClaudeKeyStore + Send + Sync>,
    ) -> Result<Opened, EngineError> {
        let model = match judgement.engine {
            settings::JudgementEngine::Off => {
                return Err(EngineError::Unavailable("off".into()));
            }
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

/// One machine to scan, one data directory and one socket, all temporary.
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    socket: PathBuf,
    keys: SharedKey,
    calendar: Arc<MovedCalendar>,
    engine: Arc<Metered>,
}

impl Sandbox {
    fn new(
        purpose: &str,
        judgement: JudgementSettings,
        engine: Arc<Metered>,
        today: LocalDate,
    ) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-caps-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/.claude")).expect("an installed Agent");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        let socket = std::env::temp_dir().join(format!(
            "ascap-{}-{}.sock",
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
            calendar: Arc::new(MovedCalendar(Mutex::new(today))),
            engine,
        };
        sandbox.write(".claude.json", "{\"projects\": {}}\n");
        let settings = Settings {
            judgement,
            ..Settings::default()
        };
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

    /// One skill in the Ambiguous Band, told apart by its marker line.
    fn ambiguous_skill(&self, name: &str) {
        self.write(
            &format!(".claude/skills/{name}/SKILL.md"),
            &format!("{AMBIGUOUS_SKILL}\nMarker: {name}.\n"),
        );
    }

    /// Writes `count` spend records of one small request each on `date`, as
    /// earlier requests of a daemon would have.
    fn spent_before(&self, date: LocalDate, count: usize) {
        let (mut writer, _) =
            EventLogWriter::open(&EventLog::in_data_directory(&self.data()), &self.keys)
                .expect("an open Event Log");
        let record = SpendRecord::priced(
            date,
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

    fn spends(&self) -> Vec<SpendRecord> {
        EventLog::in_data_directory(&self.data())
            .read(&self.keys)
            .expect("a readable Event Log")
            .spends
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

    /// A daemon whose watcher never closes a batch during a test. It waits
    /// for the Full Scan at start and for the queue that Scan fed.
    fn start(&self) -> Background {
        let daemon = Daemon::open_tuned(
            &self.options(),
            Arc::new(SameUser),
            Box::new(self.keys.clone()),
            Tuning {
                watch: Timings::of(Duration::from_secs(3_600), Duration::from_secs(3_600)),
                engines: Some(Arc::new(FakeEngines(Arc::clone(&self.engine)))),
                calendar: self.calendar.clone(),
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
        wait_for_the_queue(background.daemon());
        background
    }

    fn client(&self) -> Client {
        Client::connect_at(&self.socket, Role::Cli).expect("a client")
    }

    fn status(&self) -> Status {
        self.client().status().expect("a status")
    }

    /// Asks for "Scan now", waits until a Full Scan that started after the
    /// request has finished, and for the queue it fed.
    fn scan_now(&self, daemon: &Background) {
        let last = daemon.daemon().status().scan.expect("a Scan").started_at;
        daemon.daemon().scan(Trigger::ScanNow);
        wait_until("a Full Scan after the request", || {
            !daemon.daemon().health().scanning
                && daemon
                    .daemon()
                    .status()
                    .scan
                    .is_some_and(|scan| scan.started_at > last)
        });
        wait_for_the_queue(daemon.daemon());
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

fn wait_for_the_queue(daemon: &Arc<Daemon>) {
    wait_until("the AI Judgement queue to drain", || {
        !daemon.judgement_pending()
    });
}

fn claude() -> JudgementSettings {
    JudgementSettings {
        engine: settings::JudgementEngine::Claude,
        ..JudgementSettings::default()
    }
}

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| name.to_string()).collect()
}

fn ambiguous(status: &Status) -> Vec<String> {
    let mut names: Vec<String> = status
        .overview
        .ambiguous
        .iter()
        .map(|entry| {
            entry
                .item_id
                .as_str()
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    names.sort();
    names
}

/// 199 requests were already made today. Of two Items, the 200th of the day
/// is sent and the 201st is not: it gets no Verdict, stays Ambiguous and
/// waits, which the cap notice in status and the engine state says. A
/// restart, even over a lost state file, keeps the day's count, so the next
/// Scan still sends nothing. The next day the waiting Item is asked and the
/// notice clears.
#[test]
fn the_201st_item_of_a_day_waits_across_a_restart_and_is_asked_the_next_day() {
    let today = LocalDate::new(2026, 10, 16);
    let sandbox = Sandbox::new("day", claude(), Metered::new(1_000, 50), today);
    sandbox.spent_before(today, 199);
    sandbox.ambiguous_skill("alpha-helper");
    sandbox.ambiguous_skill("beta-helper");

    let daemon = sandbox.start();
    let asked = sandbox.engine.asked();
    assert_eq!(asked.len(), 1, "only the 200th of the day: {asked:?}");
    let waiting = if asked == names(&["alpha-helper"]) {
        "beta-helper"
    } else {
        "alpha-helper"
    };
    let status = sandbox.status();
    assert_eq!(
        status.health.judgement_cap,
        Some(CapNotice {
            cap: JudgementCap::Day,
            waiting: 1
        })
    );
    assert!(status.findings.is_empty(), "{:?}", status.findings);
    assert!(ambiguous(&status).contains(&waiting.to_string()));
    let engine = sandbox.client().engine().expect("the engine state");
    assert_eq!(engine.cloud_use.items_today, 200);
    assert!(engine.cloud_use.model_priced);
    assert_eq!(engine.cloud_use.judgement_cap, status.health.judgement_cap);
    let spends = sandbox.spends();
    assert_eq!(spends.len(), 200);
    let last = spends.last().expect("the request just made");
    assert_eq!(last.date, today);
    assert_eq!(last.model, CLAUDE_MODEL);
    assert_eq!((last.input_tokens, last.output_tokens), (1_000, 50));
    assert_eq!(last.cost_microdollars, 2_000 + 500);

    // A restart over a lost state file still counts the day from the Event
    // Log: the Full Scan at start sends nothing.
    drop(daemon);
    std::fs::remove_file(sandbox.data().state_file()).expect("the state file goes");
    let daemon = sandbox.start();
    assert_eq!(sandbox.engine.asked().len(), 1, "nothing more today");
    let engine = sandbox.client().engine().expect("the engine state");
    assert_eq!(engine.cloud_use.items_today, 200);
    assert_eq!(
        sandbox.status().health.judgement_cap,
        Some(CapNotice {
            cap: JudgementCap::Day,
            waiting: 1
        })
    );

    sandbox.calendar.set(LocalDate::new(2026, 10, 17));
    sandbox.scan_now(&daemon);
    assert_eq!(
        sandbox.engine.asked(),
        names(&["alpha-helper", "beta-helper"])
    );
    assert_eq!(sandbox.status().health.judgement_cap, None);
    let engine = sandbox.client().engine().expect("the engine state");
    assert_eq!(engine.cloud_use.items_today, 1);
    assert_eq!(engine.cloud_use.judgement_cap, None);
}

/// One request whose usage costs exactly $5 uses up the month: the next
/// Item that month is not sent and waits. On the first of the next month it
/// is sent. The per-Scan cap of one keeps the second Item for the second
/// Scan.
#[test]
fn usage_that_adds_up_to_five_dollars_stops_the_month_until_it_rolls_over() {
    let judgement = JudgementSettings {
        caps: settings::CloudCaps {
            items_per_scan: 1,
            ..settings::CloudCaps::default()
        },
        ..claude()
    };
    // 2.5 million input tokens at $2 per million.
    let sandbox = Sandbox::new(
        "month",
        judgement,
        Metered::new(2_500_000, 0),
        LocalDate::new(2026, 10, 31),
    );
    sandbox.ambiguous_skill("first-helper");
    sandbox.ambiguous_skill("second-helper");
    let daemon = sandbox.start();
    assert_eq!(sandbox.engine.asked(), names(&["first-helper"]));
    let engine = sandbox.client().engine().expect("the engine state");
    assert_eq!(engine.cloud_use.microdollars_this_month, 5_000_000);
    assert_eq!(
        engine.cloud_use.judgement_cap,
        Some(CapNotice {
            cap: JudgementCap::Scan,
            waiting: 1
        })
    );

    sandbox.scan_now(&daemon);
    assert_eq!(sandbox.engine.asked(), names(&["first-helper"]));
    let status = sandbox.status();
    assert!(
        ambiguous(&status).contains(&"second-helper".to_string()),
        "{:?} {:?}",
        ambiguous(&status),
        status.findings
    );
    assert_eq!(
        status.health.judgement_cap,
        Some(CapNotice {
            cap: JudgementCap::Month,
            waiting: 1
        })
    );

    sandbox.calendar.set(LocalDate::new(2026, 11, 1));
    sandbox.scan_now(&daemon);
    assert_eq!(
        sandbox.engine.asked(),
        names(&["first-helper", "second-helper"])
    );
    assert_eq!(sandbox.status().health.judgement_cap, None);
    let engine = sandbox.client().engine().expect("the engine state");
    assert_eq!(engine.cloud_use.microdollars_this_month, 5_000_000);
    let costs: Vec<u64> = sandbox
        .spends()
        .iter()
        .map(|spend| spend.cost_microdollars)
        .collect();
    assert_eq!(costs, vec![5_000_000, 5_000_000]);
}

/// The per-Scan cap holds Items back too, and the cap notice names them
/// until a Scan has asked them.
#[test]
fn the_per_scan_cap_raises_the_notice_until_the_items_are_asked() {
    let judgement = JudgementSettings {
        caps: settings::CloudCaps {
            items_per_scan: 2,
            ..settings::CloudCaps::default()
        },
        ..claude()
    };
    let sandbox = Sandbox::new(
        "per-scan",
        judgement,
        Metered::new(10, 1),
        LocalDate::new(2026, 10, 16),
    );
    for name in ["one-helper", "two-helper", "three-helper"] {
        sandbox.ambiguous_skill(name);
    }
    let daemon = sandbox.start();
    assert_eq!(sandbox.engine.asked().len(), 2);
    assert_eq!(
        sandbox.status().health.judgement_cap,
        Some(CapNotice {
            cap: JudgementCap::Scan,
            waiting: 1
        })
    );
    sandbox.scan_now(&daemon);
    assert_eq!(sandbox.engine.asked().len(), 3);
    assert_eq!(sandbox.status().health.judgement_cap, None);
}

/// A local engine is never counted against the day or month caps, even
/// when it reports usage and the caps are as small as they go.
#[test]
fn local_engines_are_never_counted_against_the_day_or_month_caps() {
    let judgement = JudgementSettings {
        engine: settings::JudgementEngine::Ollama,
        ollama_model: "qwen3:8b".to_string(),
        caps: settings::CloudCaps {
            items_per_scan: 25,
            items_per_day: 1,
            cents_per_month: 1,
        },
        ..JudgementSettings::default()
    };
    let sandbox = Sandbox::new(
        "local",
        judgement,
        Metered::new(2_500_000, 0),
        LocalDate::new(2026, 10, 16),
    );
    for name in ["one-helper", "two-helper", "three-helper"] {
        sandbox.ambiguous_skill(name);
    }
    let _daemon = sandbox.start();
    assert_eq!(sandbox.engine.asked().len(), 3);
    assert!(sandbox.spends().is_empty(), "{:?}", sandbox.spends());
    assert_eq!(sandbox.status().health.judgement_cap, None);
    let engine = sandbox.client().engine().expect("the engine state");
    assert_eq!(engine.cloud_use.items_today, 0);
    assert_eq!(engine.cloud_use.microdollars_this_month, 0);
}
