//! The AI check in the Settings pane against a real daemon: the Claude API
//! key handed over once and kept nowhere in the app, the engine turned on
//! and off, the recorded line after every change, an Ollama address off this
//! Mac refused before it is sent, and "Preview a request" showing the
//! daemon's redacted request.
//!
//! The daemon runs in this process on a temporary home, a temporary data
//! directory and a temporary socket, with its chain key and the Claude API
//! key held in memory. It is a developer run, so it reaches no Rule Feed, no
//! Ollama and no Apple helper, and no engine is ever asked: the Claude call
//! is never made in the suite. Nothing touches the real home, the documented
//! socket, the real data directory or the Keychain.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use agentsweep_core::keychain::MemoryKeySource;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::settings::{JudgementEngine, Posture};
use agentsweep_daemon::Tuning;
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::service::{self, Background, Daemon};
use agentsweep_daemon::watcher::Timings;
use agentsweep_ipc::peer::SameUser;
use agentsweep_ipc::preview::PreviewOutcome;
use agentsweep_menubar::ai_check;
use agentsweep_menubar::asking::Asking;
use agentsweep_menubar::frame::Frame;
use agentsweep_menubar::link::Socket;
use serde_json::{Value, json};

/// A defanged key of a plausible shape. It is no real key.
const A_KEY: &str = "sk-ant-defanged-test-key-0000000000000000000000004f2a";

static NEXT: AtomicU32 = AtomicU32::new(0);

/// One machine, one data directory and one socket, all temporary.
struct Sandbox {
    root: PathBuf,
    socket: PathBuf,
}

impl Sandbox {
    fn new(purpose: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-ai-check-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/.claude")).expect("a home");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        std::fs::write(
            root.join("home/.claude.json"),
            b"{\n  \"projects\": {}\n}\n",
        )
        .expect("a registry");
        let socket = std::env::temp_dir().join(format!(
            "asw-ai-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        Sandbox { root, socket }
    }

    fn start(&self) -> Background {
        let options = Options {
            data_dir: DataDirectory::at(self.root.join("data")),
            socket: self.socket.clone(),
            home: Some(self.root.join("home")),
            key_source: KeySourceChoice::Memory,
            log: LogChoice::Stderr,
        };
        let daemon = Daemon::open_tuned(
            &options,
            Arc::new(SameUser),
            Box::new(MemoryKeySource::empty()),
            Tuning {
                watch: Timings::of(Duration::from_millis(100), Duration::from_millis(500)),
                gate: None,
                ..Tuning::default()
            },
        )
        .expect("an open daemon");
        let running = service::start_with(&options, daemon).expect("a listening daemon");
        let background = running.serve_in_the_background();
        wait_for_a_scan(background.daemon());
        background
    }

    fn asking(&self) -> Asking {
        Asking::new(Socket::At(self.socket.clone()))
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

/// A frame loaded the way the app loads it: the status, then the settings.
fn loaded(asking: &Asking) -> Frame {
    let mut frame = Frame::new();
    frame.load(&asking.status().expect("a status"));
    frame.settings(&asking.settings().expect("the settings"));
    frame
}

/// Every file under `directory`, read as text.
fn every_file(directory: &Path, found: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            every_file(&path, found);
        } else if let Ok(bytes) = std::fs::read(&path) {
            found.push((path, String::from_utf8_lossy(&bytes).into_owned()));
        }
    }
}

/// The card of one engine in the pane.
fn card(frame: &Frame, engine: &str) -> Value {
    frame.to_value()["settings"]["aiCheck"]["cards"]
        .as_array()
        .expect("the cards")
        .iter()
        .find(|card| card["engine"] == engine)
        .cloned()
        .expect("a card")
}

/// "I agree, turn it on" hands the key to the daemon once and turns the
/// Claude engine on; afterwards the key is in no app state, no view the
/// window is sent, and no file the daemon wrote. Removing the key turns the
/// card to off, and each change says it was recorded.
#[test]
fn the_key_is_handed_over_once_and_kept_nowhere_in_the_app() {
    let sandbox = Sandbox::new("key");
    let _daemon = sandbox.start();
    let asking = sandbox.asking();
    let mut frame = loaded(&asking);
    assert_eq!(card(&frame, "off")["selected"], true);
    assert_eq!(frame.to_value()["settings"]["aiCheck"]["key"]["set"], false);

    // With no key typed and none set, nothing turns on.
    let refused = ai_check::turn_on_claude(&asking, None).expect_err("no key");
    assert!(refused.starts_with("Nothing was changed"), "{refused}");
    let refused = ai_check::turn_on_claude(&asking, Some("   ".to_string())).expect_err("no key");
    assert!(refused.starts_with("Nothing was changed"), "{refused}");

    let state = ai_check::turn_on_claude(&asking, Some(A_KEY.to_string())).expect("turned on");
    assert_eq!(state.engine, JudgementEngine::Claude);
    assert_eq!(state.claude_key_ending.as_deref(), Some("4f2a"));
    assert_eq!(state.recorded, 2, "the key added and the engine enabled");
    assert!(ai_check::recorded_line(&state, Posture::Simple).contains("recorded"));
    frame.engine(&state);

    let pane = frame.to_value()["settings"]["aiCheck"].clone();
    assert_eq!(pane["key"]["line"], "Key set, ending in …4f2a");
    assert_eq!(card(&frame, "claude")["selected"], true);

    // Nothing of the key stays in the app or reaches a file.
    assert!(
        !frame.to_value().to_string().contains(A_KEY),
        "the view holds the key"
    );
    assert!(
        !format!("{frame:?}").contains(A_KEY),
        "the frame holds the key"
    );
    assert!(
        !format!("{asking:?}").contains(A_KEY),
        "the asking holds the key"
    );
    let mut files = Vec::new();
    every_file(&sandbox.root, &mut files);
    assert!(!files.is_empty());
    for (path, text) in &files {
        assert!(!text.contains(A_KEY), "{} holds the key", path.display());
    }

    // Removing the key turns the engine off, recorded twice.
    let removed = ai_check::remove_claude_key(&asking).expect("removed");
    assert_eq!(removed.engine, JudgementEngine::Off);
    assert_eq!(removed.claude_key_ending, None);
    assert_eq!(
        removed.recorded, 2,
        "the key removed and the engine disabled"
    );
    frame.engine(&removed);
    assert_eq!(card(&frame, "off")["selected"], true);
    assert_eq!(frame.to_value()["settings"]["aiCheck"]["key"]["set"], false);
}

/// Every engine change through the cards says it was recorded; an Ollama
/// address off this Mac is refused before it is sent and moves nothing.
#[test]
fn every_engine_change_is_recorded_and_a_remote_ollama_is_refused() {
    let sandbox = Sandbox::new("change");
    let _daemon = sandbox.start();
    let asking = sandbox.asking();
    let mut frame = loaded(&asking);

    let apple = ai_check::change(&asking, &json!({ "engine": "apple" })).expect("apple");
    assert_eq!(apple.recorded, 1);
    assert_eq!(
        ai_check::recorded_line(&apple, Posture::Developer),
        "Recorded in the Event Log."
    );
    frame.engine(&apple);
    assert_eq!(card(&frame, "apple")["selected"], true);

    let off = ai_check::change(&asking, &json!({ "engine": "off" })).expect("off");
    assert_eq!(off.recorded, 1);
    assert!(ai_check::recorded_line(&off, Posture::Simple).contains("recorded"));

    let refused = ai_check::change(&asking, &json!({ "ollama_address": "10.0.0.7:11434" }))
        .expect_err("not on this Mac");
    assert!(refused.starts_with("Nothing was changed"), "{refused}");
    assert_eq!(
        asking.engine().expect("the engine").ollama_address,
        "127.0.0.1:11434"
    );
    let moved = ai_check::change(&asking, &json!({ "ollama_address": "localhost:11500" }))
        .expect("loopback");
    assert_eq!(moved.ollama_address, "localhost:11500");
}

/// "Preview a request" shows the daemon's redacted request verbatim: the
/// sample Item with no Item named, and an MCP server's env value only as
/// its placeholder.
#[test]
fn preview_shows_the_daemons_redacted_request_verbatim() {
    const NOTES: &str = "claude-code/user/mcp-server/~/.claude.json#notes";
    let sandbox = Sandbox::new("preview");
    std::fs::write(
        sandbox.root.join("home/.claude.json"),
        r#"{
  "projects": {},
  "mcpServers": {
    "notes": {
      "type": "stdio",
      "command": "notes-server",
      "env": {"NOTES_TOKEN": "defanged-env-value-1234"}
    }
  }
}
"#,
    )
    .expect("a registry");
    let _daemon = sandbox.start();
    let asking = sandbox.asking();

    let sample = ai_check::preview(&asking, None).expect("the sample");
    assert!(!sample["user"].as_str().expect("a request").is_empty());
    assert!(!sample["system"].as_str().expect("a prompt").is_empty());

    let shown = ai_check::preview(&asking, Some(NOTES)).expect("a preview");
    let user = shown["user"].as_str().expect("a request");
    assert!(!user.contains("defanged-env-value-1234"), "{user}");
    assert!(user.contains("NOTES_TOKEN"), "{user}");
    assert!(user.contains("<redacted:"), "{user}");

    // Verbatim: the daemon's own user turn, apart from the fresh nonce.
    let direct = asking
        .preview_request(Some(NOTES), JudgementEngine::Claude)
        .expect("a preview");
    let PreviewOutcome::Request {
        user: direct_user,
        nonce,
        ..
    } = direct.outcome
    else {
        panic!("a request");
    };
    let own_nonce = shown["nonce"].as_str().expect("a nonce");
    assert_eq!(user.replace(own_nonce, &nonce), direct_user);
}
