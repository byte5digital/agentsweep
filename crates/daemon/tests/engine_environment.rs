//! `OLLAMA_HOST` and `ANTHROPIC_API_KEY` in the daemon's environment change
//! nothing (spec section 4.4, ADR 0005).
//!
//! The environment is the process's, so this check has a test binary of its
//! own with one test in it: nothing else runs beside it while the variables
//! are set. The daemon runs against a temporary home, data directory and
//! socket, with both keys held in the process; no Keychain item is touched.

use std::sync::Arc;

use agentsweep_core::keychain::MemoryKeySource;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::settings::JudgementEngine;
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::service::{self, Daemon};
use agentsweep_ipc::peer::SameUser;
use agentsweep_ipc::protocol::{EngineChange, Role};
use agentsweep_ipc::{Client, ClientError};

/// A defanged stand-in for a Claude API key in the environment.
const ENVIRONMENT_KEY: &str = "sk-ant-api03-defanged-environment-0000-e9e9";

#[test]
fn ollama_host_and_anthropic_api_key_in_the_environment_change_nothing() {
    let root = std::env::temp_dir().join(format!(
        "agentsweep-engine-environment-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home")).expect("a fake home");
    let socket = std::env::temp_dir().join(format!("asv-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);

    // SAFETY: this binary runs this one test and no other thread reads the
    // environment while it is set.
    unsafe {
        std::env::set_var("OLLAMA_HOST", "http://192.0.2.10:11434");
        std::env::set_var("ANTHROPIC_API_KEY", ENVIRONMENT_KEY);
    }

    let options = Options {
        data_dir: DataDirectory::at(root.join("data")),
        socket: socket.clone(),
        home: Some(root.join("home")),
        key_source: KeySourceChoice::Memory,
        log: LogChoice::Stderr,
    };
    let daemon = Daemon::open_with(
        &options,
        Arc::new(SameUser),
        Box::new(MemoryKeySource::empty()),
    )
    .expect("an open daemon");
    let running = service::start_with(&options, daemon).expect("a listening daemon");
    let background = running.serve_in_the_background();

    let mut client = Client::connect_at(&socket, Role::App).expect("a connected client");
    let state = client.engine().expect("the engine state");
    assert_eq!(state.ollama_address, "127.0.0.1:11434");
    assert_eq!(
        state.claude_key_ending, None,
        "the environment's key is not a key"
    );

    let state = client
        .change_engine(EngineChange {
            engine: Some(JudgementEngine::Ollama),
            ..EngineChange::default()
        })
        .expect("Ollama on");
    assert_eq!(state.ollama_address, "127.0.0.1:11434");
    match client.change_engine(EngineChange {
        engine: Some(JudgementEngine::Claude),
        ..EngineChange::default()
    }) {
        Err(ClientError::Request(error)) => assert_eq!(error.code, "claude-key-missing"),
        other => panic!("the environment's key enabled Claude: {other:?}"),
    }
    let settings = std::fs::read_to_string(options.data_dir.settings_file()).expect("settings");
    assert!(!settings.contains("192.0.2.10"), "{settings}");
    assert!(!settings.contains(ENVIRONMENT_KEY), "{settings}");

    drop(client);
    drop(background);
    unsafe {
        std::env::remove_var("OLLAMA_HOST");
        std::env::remove_var("ANTHROPIC_API_KEY");
    }
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_dir_all(&root);
}
