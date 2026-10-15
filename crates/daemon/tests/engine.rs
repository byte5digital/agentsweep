//! Choosing a Judgement Engine through the daemon, end to end (spec sections
//! 4.4, 6.9 and 8.10).
//!
//! Every daemon here runs against a temporary home, data directory and
//! socket, with the chain key and the Claude API key held in the process
//! (`KeySourceChoice::Memory`). No test reads, writes or deletes a Keychain
//! item. The keys below are defanged stand-ins with the shape of a key.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use agentsweep_core::eventlog::{Action, Event, EventLog};
use agentsweep_core::keychain::{ChainKey, ClaudeKey, KeyError, KeySource, MemoryKeySource};
use agentsweep_core::ollama::OllamaPresence;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::settings::{JudgementEngine, SettingsFile};
use agentsweep_daemon::Tuning;
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::service::{self, Background, Daemon};
use agentsweep_ipc::peer::{Nobody, PeerCheck, SameUser};
use agentsweep_ipc::protocol::{EngineChange, Hello, Message, Request, Role};
use agentsweep_ipc::{Client, ClientError, connect};

#[path = "../../core/tests/fixture_ollama/mod.rs"]
mod fixture_ollama;

/// A defanged stand-in for a Claude API key.
const A_KEY: &str = "sk-ant-api03-defanged-engine-test-1111-4f2a";

/// Another one, for handing over a second key.
const ANOTHER_KEY: &str = "sk-ant-api03-defanged-engine-test-2222-7b3e";

static NEXT: AtomicU32 = AtomicU32::new(0);

/// Everything the daemons of this test binary log, captured. Tests never
/// start the daemon's own log, so this subscriber is the only one there is.
fn captured_log() -> &'static Arc<Mutex<Vec<u8>>> {
    static LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOG.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&buffer);
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || Capture(Arc::clone(&writer)))
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("one subscriber");
        buffer
    })
}

struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("the log").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The one chain key a sandbox's daemons share, as in the other suites.
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

struct Sandbox {
    root: PathBuf,
    socket: PathBuf,
    keys: SharedKey,
}

impl Sandbox {
    fn new(purpose: &str) -> Sandbox {
        captured_log();
        let root = std::env::temp_dir().join(format!(
            "agentsweep-engine-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home")).expect("a fake home");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        let socket = std::env::temp_dir().join(format!(
            "ase-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        Sandbox {
            root,
            socket,
            keys: SharedKey(Arc::new(MemoryKeySource::empty())),
        }
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
        self.start_answering(Arc::new(SameUser))
    }

    fn start_answering(&self, check: Arc<dyn PeerCheck>) -> Background {
        self.start_tuned(check, Tuning::default())
    }

    fn start_tuned(&self, check: Arc<dyn PeerCheck>, tuning: Tuning) -> Background {
        let options = self.options();
        let daemon = Daemon::open_tuned(&options, check, Box::new(self.keys.clone()), tuning)
            .expect("an open daemon");
        let running = service::start_with(&options, daemon).expect("a listening daemon");
        let background = running.serve_in_the_background();
        wait_for_a_scan(background.daemon());
        background
    }

    fn client(&self) -> Client {
        Client::connect_at(&self.socket, Role::App).expect("a connected client")
    }

    fn settings_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(SettingsFile::in_data_directory(&self.data()).path()).ok()
    }

    /// The `engine-changed` events of the Event Log, in the order written.
    fn engine_events(&self) -> Vec<Event> {
        EventLog::in_data_directory(&self.data())
            .read(&self.keys)
            .expect("a readable Event Log")
            .events
            .into_iter()
            .map(|recorded| recorded.event)
            .filter(|event| event.action == Action::EngineChanged)
            .collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn wait_for_a_scan(daemon: &Arc<Daemon>) {
    for _ in 0..2_400 {
        let health = daemon.health();
        if !health.scanning && daemon.status().scan.is_some() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("the Full Scan did not finish");
}

fn key(text: &str) -> ClaudeKey {
    ClaudeKey::new(text).expect("a plausible key")
}

fn engine(engine: JudgementEngine) -> EngineChange {
    EngineChange {
        engine: Some(engine),
        ..EngineChange::default()
    }
}

fn change(event: &Event) -> &str {
    event.detail.get("change").map(String::as_str).unwrap_or("")
}

fn refusal_code(error: ClientError) -> String {
    match error {
        ClientError::Request(error) => error.code,
        other => panic!("not a refusal: {other}"),
    }
}

/// Every file under a directory, read whole, so a test can look for a value
/// in all of them at once.
fn every_file_under(directory: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).expect("a readable directory") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                found.push((path, bytes));
            }
        }
    }
    found
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Before any choice the engine is off, every choice is at its default and
/// no key is set; reading moves nothing and writes nothing.
#[test]
fn the_engine_state_starts_at_every_default() {
    let sandbox = Sandbox::new("defaults");
    let _daemon = sandbox.start();
    let state = sandbox.client().engine().expect("the engine state");
    assert_eq!(state.engine, JudgementEngine::Off);
    assert_eq!(state.ollama_address, "127.0.0.1:11434");
    assert_eq!(state.ollama_model, "");
    assert_eq!(state.claude_model, "");
    assert_eq!(state.claude_model_in_use, "claude-sonnet-5");
    assert_eq!(state.caps.items_per_scan, 25);
    assert_eq!(state.caps.items_per_day, 200);
    assert_eq!(state.caps.cents_per_month, 500);
    assert_eq!(state.claude_key_ending, None);
    assert_eq!(state.recorded, 0);
    assert_eq!(state.ollama, None, "a developer run asks no Ollama");
    assert_eq!(state.apple, None, "a developer run starts no Apple helper");
    assert_eq!(sandbox.settings_bytes(), None, "a read writes nothing");
    assert!(sandbox.engine_events().is_empty());
}

/// The engine state names whether Ollama runs at the configured loopback
/// address and every model it has pulled, a model under 4B marked too small
/// for the suggestion. Only that address is asked, and only to read.
#[test]
fn the_engine_state_names_ollama_s_presence_and_its_models() {
    use fixture_ollama::{Behaviour, FixtureOllama, closed_port, tags};

    let ollama = FixtureOllama::start(vec![
        (
            "/api/version",
            Behaviour::Json(200, serde_json::json!({ "version": "0.12.6" })),
        ),
        (
            "/api/tags",
            Behaviour::Json(
                200,
                tags(&[
                    ("qwen3:1.7b", "1.7B", "1111"),
                    ("gemma3:4b", "4B", "2222"),
                    ("gemma3:26b", "26B", "3333"),
                ]),
            ),
        ),
    ]);
    let sandbox = Sandbox::new("ollama-presence");
    let _daemon = sandbox.start_tuned(
        Arc::new(SameUser),
        Tuning {
            detect_ollama: Some(true),
            ..Tuning::default()
        },
    );
    let mut client = sandbox.client();
    let state = client
        .change_engine(EngineChange {
            ollama_address: Some(ollama.address().to_string()),
            ..EngineChange::default()
        })
        .expect("a loopback address is taken");
    let Some(OllamaPresence::Running { version, models }) = state.ollama else {
        panic!("Ollama is running: {:?}", state.ollama);
    };
    assert_eq!(version, "0.12.6");
    let seen: Vec<(&str, bool)> = models
        .iter()
        .map(|model| (model.name.as_str(), model.large_enough))
        .collect();
    assert_eq!(
        seen,
        [
            ("qwen3:1.7b", false),
            ("gemma3:4b", true),
            ("gemma3:26b", true)
        ]
    );
    let read = client.engine().expect("the engine state");
    assert_eq!(
        read.ollama,
        Some(OllamaPresence::Running { version, models })
    );
    let paths: Vec<String> = ollama
        .all_received()
        .into_iter()
        .map(|request| {
            assert_eq!(request.method, "GET");
            request.path
        })
        .collect();
    assert_eq!(
        paths,
        ["/api/version", "/api/tags", "/api/version", "/api/tags"]
    );
    assert_eq!(ollama.connections(), 4);

    let state = client
        .change_engine(EngineChange {
            ollama_address: Some(closed_port().to_string()),
            ..EngineChange::default()
        })
        .expect("a loopback address is taken");
    assert_eq!(state.ollama, Some(OllamaPresence::Absent));
}

/// The engine state names whether Apple's on-device model is available, and
/// the reason when it is not, as the helper the daemon was pointed at answers
/// its check. Here the helper is a fake: a script answering canned JSON. Each
/// check spawns it once, and it is gone when the answer arrives.
#[cfg(unix)]
#[test]
fn the_engine_state_names_apple_s_availability_and_its_reason() {
    use agentsweep_core::apple::AppleAvailability;
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new("apple-availability");
    let fake = sandbox.root.join("agentsweep-apple-judge");
    let answer = sandbox.root.join("check");
    let script = format!(
        "#!/bin/sh\ncat > /dev/null\necho \"$$\" >> \"{}\"\ncat \"{}\"\n",
        sandbox.root.join("pids").display(),
        answer.display()
    );
    std::fs::write(&fake, script).expect("the fake helper is written");
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
        .expect("the fake helper is executable");
    std::fs::write(
        &answer,
        r#"{"available":false,"reason":"apple_intelligence_not_enabled","model_version":"26.6.2 (25G83)"}"#,
    )
    .expect("the check answer is written");

    let _daemon = sandbox.start_tuned(
        Arc::new(SameUser),
        Tuning {
            apple_helper: Some(fake.clone()),
            ..Tuning::default()
        },
    );
    let mut client = sandbox.client();
    let state = client.engine().expect("the engine state");
    assert_eq!(
        state.apple,
        Some(AppleAvailability::Unavailable {
            reason: "apple_intelligence_not_enabled".to_string()
        })
    );

    std::fs::write(
        &answer,
        r#"{"available":true,"context_size":4096,"model_version":"26.6.2 (25G83)"}"#,
    )
    .expect("the check answer is written");
    let state = client.engine().expect("the engine state");
    assert_eq!(
        state.apple,
        Some(AppleAvailability::Available {
            model_version: "26.6.2 (25G83)".to_string(),
            context_size: Some(4096),
        })
    );

    let pids: Vec<String> = std::fs::read_to_string(sandbox.root.join("pids"))
        .expect("the helper ran")
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(pids.len(), 2, "one helper per check");
    for pid in pids {
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid])
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        assert!(!alive, "helper {pid} outlived its check");
    }
    assert_eq!(
        sandbox.settings_bytes(),
        None,
        "asking the helper writes nothing"
    );
}

/// A non-loopback address, or a host name that is not `localhost`, is
/// refused and the settings file is left byte for byte as it was, the other
/// choices of the same request included.
#[test]
fn an_ollama_address_off_this_mac_is_refused_and_nothing_moves() {
    let sandbox = Sandbox::new("loopback");
    let _daemon = sandbox.start();
    let mut client = sandbox.client();
    let moved = client
        .change_engine(EngineChange {
            ollama_address: Some("localhost:11500".to_string()),
            ollama_model: Some("qwen3:8b".to_string()),
            ..EngineChange::default()
        })
        .expect("a loopback address is taken");
    assert_eq!(moved.ollama_address, "localhost:11500");
    let before = sandbox.settings_bytes().expect("a settings file");

    for address in [
        "192.0.2.10:11434",
        "0.0.0.0:11434",
        "[2001:db8::1]:11434",
        "ollama.example.invalid:11434",
        "localhost.example.invalid:11434",
    ] {
        let error = client
            .change_engine(EngineChange {
                engine: Some(JudgementEngine::Ollama),
                ollama_address: Some(address.to_string()),
                ..EngineChange::default()
            })
            .expect_err(address);
        assert_eq!(refusal_code(error), "refused", "{address}");
        assert_eq!(
            sandbox.settings_bytes().as_ref(),
            Some(&before),
            "{address}"
        );
    }
    let state = client.engine().expect("the engine state");
    assert_eq!(state.engine, JudgementEngine::Off);
    assert_eq!(state.ollama_address, "localhost:11500");
    assert!(sandbox.engine_events().is_empty());
}

/// The Claude engine needs a key first.
#[test]
fn the_claude_engine_is_refused_without_a_key() {
    let sandbox = Sandbox::new("no-key");
    let _daemon = sandbox.start();
    let error = sandbox
        .client()
        .change_engine(engine(JudgementEngine::Claude))
        .expect_err("no key");
    assert_eq!(refusal_code(error), "claude-key-missing");
    assert_eq!(sandbox.settings_bytes(), None);
    assert!(sandbox.engine_events().is_empty());
}

/// Handing over a key stores it, the engine state answers with its last four
/// characters only, and removing it turns an active Claude engine off with
/// two Event Log events.
#[test]
fn a_handed_over_key_is_kept_and_removing_it_turns_claude_off() {
    let sandbox = Sandbox::new("key");
    let _daemon = sandbox.start();
    let mut client = sandbox.client();

    let state = client.set_claude_key(key(A_KEY)).expect("the key is kept");
    assert_eq!(state.claude_key_ending.as_deref(), Some("4f2a"));
    assert_eq!(state.recorded, 1);
    assert_eq!(
        state.engine,
        JudgementEngine::Off,
        "a key switches nothing on"
    );
    let read = client.engine().expect("the engine state");
    assert_eq!(read.claude_key_ending.as_deref(), Some("4f2a"));
    assert!(!contains(read.to_value().to_string().as_bytes(), A_KEY));

    let state = client
        .change_engine(engine(JudgementEngine::Claude))
        .expect("the Claude engine");
    assert_eq!(state.engine, JudgementEngine::Claude);
    assert_eq!(state.recorded, 1);
    let events_before = sandbox.engine_events().len();

    let state = client.remove_claude_key().expect("the key goes");
    assert_eq!(state.engine, JudgementEngine::Off);
    assert_eq!(state.claude_key_ending, None);
    assert_eq!(state.recorded, 2);
    let events = sandbox.engine_events();
    assert_eq!(events.len(), events_before + 2);
    let removed = &events[events_before];
    assert_eq!(change(removed), "key-removed");
    assert_eq!(
        removed.detail.get("engine").map(String::as_str),
        Some("claude")
    );
    let disabled = &events[events_before + 1];
    assert_eq!(change(disabled), "disabled");
    assert_eq!(
        disabled.detail.get("from_engine").map(String::as_str),
        Some("claude")
    );
    assert_eq!(
        disabled.detail.get("from_model").map(String::as_str),
        Some("claude-sonnet-5")
    );
    assert_eq!(
        disabled.detail.get("to_engine").map(String::as_str),
        Some("off")
    );

    // Removing a key that is not there changes nothing and records nothing.
    let state = client.remove_claude_key().expect("nothing to remove");
    assert_eq!(state.recorded, 0);
    assert_eq!(sandbox.engine_events().len(), events_before + 2);
}

/// Enabling, switching and disabling each append one event; nothing in the
/// daemon moves the engine by itself; and the key is in none of the Event
/// Log, the state file, the settings file, any other file of the data
/// directory, or the daemon's log.
#[test]
fn every_engine_change_is_one_event_and_the_key_is_nowhere() {
    let sandbox = Sandbox::new("events");
    let daemon = sandbox.start();
    let mut client = sandbox.client();

    client.set_claude_key(key(A_KEY)).expect("a key");
    client
        .set_claude_key(key(ANOTHER_KEY))
        .expect("another key");
    let steps = [
        (engine(JudgementEngine::Apple), "enabled"),
        (engine(JudgementEngine::Ollama), "switched"),
        (engine(JudgementEngine::Claude), "switched"),
        (
            EngineChange {
                claude_model: Some("claude-opus-5".to_string()),
                ..EngineChange::default()
            },
            "switched",
        ),
        (engine(JudgementEngine::Off), "disabled"),
    ];
    for (step, expected) in &steps {
        let before = sandbox.engine_events().len();
        let state = client.change_engine(step.clone()).expect("a change");
        assert_eq!(state.recorded, 1, "{expected}");
        let events = sandbox.engine_events();
        assert_eq!(events.len(), before + 1, "{expected}");
        assert_eq!(change(&events[before]), *expected);
    }
    // A choice that is not an engine change, and a choice made twice, record
    // nothing.
    let before = sandbox.engine_events().len();
    let state = client
        .change_engine(EngineChange {
            items_per_scan: Some(10),
            ..EngineChange::default()
        })
        .expect("a cap");
    assert_eq!((state.recorded, state.caps.items_per_scan), (0, 10));
    let state = client
        .change_engine(engine(JudgementEngine::Off))
        .expect("off again");
    assert_eq!(state.recorded, 0);
    assert_eq!(sandbox.engine_events().len(), before);

    let events = sandbox.engine_events();
    let switch = events
        .iter()
        .find(|event| event.detail.get("to_model").map(String::as_str) == Some("claude-opus-5"))
        .expect("the model switch");
    assert_eq!(
        switch.detail.get("from_model").map(String::as_str),
        Some("claude-sonnet-5")
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| change(event) == "key-added")
            .count(),
        2
    );

    // A Scan, and a restart, leave the engine where the user put it.
    client
        .change_engine(engine(JudgementEngine::Apple))
        .expect("Apple on");
    daemon
        .daemon()
        .scan(agentsweep_core::state::Trigger::ScanNow);
    wait_for_a_scan(daemon.daemon());
    assert_eq!(
        client.engine().expect("the state").engine,
        JudgementEngine::Apple
    );
    drop(client);
    drop(daemon);
    let restarted = sandbox.start();
    assert_eq!(
        sandbox.client().engine().expect("the state").engine,
        JudgementEngine::Apple
    );
    drop(restarted);

    let log = captured_log().lock().expect("the log").clone();
    assert!(!log.is_empty(), "the daemon logged");
    for secret in [A_KEY, ANOTHER_KEY] {
        assert!(!contains(&log, secret), "the key reached the log");
        for (path, bytes) in every_file_under(sandbox.data().root()) {
            assert!(
                !contains(&bytes, secret),
                "the key reached {}",
                path.display()
            );
        }
    }
    for name in ["events.jsonl", "state.json", "settings.json"] {
        assert!(
            sandbox.data().root().join(name).exists(),
            "{name} was looked at"
        );
    }
}

/// The new requests are refused for an unsigned peer exactly as the existing
/// ones are: at the handshake, before any request is read.
#[test]
fn the_engine_requests_are_refused_for_an_unsigned_peer() {
    let sandbox = Sandbox::new("unsigned");
    let _daemon = sandbox.start_answering(Arc::new(Nobody::because("not signed by byte5")));

    let requests = [
        Request::Engine {
            change: EngineChange::default(),
        },
        Request::Engine {
            change: engine(JudgementEngine::Apple),
        },
        Request::SetClaudeKey { key: key(A_KEY) },
        Request::RemoveClaudeKey,
    ];
    for request in requests {
        let name = request.as_str();
        let mut connection = connect(&sandbox.socket).expect("a connection");
        connection
            .send(&Message::Hello(Hello::of(Role::App)))
            .expect("a handshake sent");
        let answer = connection.receive().expect("an answer");
        assert!(
            matches!(answer, Some(Message::Refused(_))),
            "{name}: {answer:?}"
        );
        let _ = connection.send(&Message::Request {
            id: "1".to_string(),
            request,
        });
        assert!(
            matches!(connection.receive(), Ok(None) | Err(_)),
            "{name}: the connection is over"
        );
    }
    let error = Client::connect_at(&sandbox.socket, Role::App).expect_err("nobody is admitted");
    assert!(error.to_string().contains("not signed by byte5"));
    assert_eq!(sandbox.settings_bytes(), None);
    assert!(sandbox.engine_events().is_empty());
}
