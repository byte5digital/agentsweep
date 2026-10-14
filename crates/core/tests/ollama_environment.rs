//! The Ollama Judgement Engine never reads `OLLAMA_HOST` (spec section 4.4).
//!
//! This is a test binary of its own because it sets the variable for the whole
//! process: no other test may run beside it. Two fixture servers listen on
//! loopback ports of their own; the environment names one, the settings the
//! other, and only the one the settings name may ever see a connection.

mod fixture_ollama;

use std::path::Path;

use agentsweep_core::item::{Activation, Item, Kind, Provenance, Scope};
use agentsweep_core::judgement::judge;
use agentsweep_core::judgement_request::Normalisation;
use agentsweep_core::ollama::{OllamaClient, OllamaEngine, OllamaPresence, request_builder};
use agentsweep_core::settings::OllamaAddress;
use serde_json::json;

use fixture_ollama::{Behaviour, FixtureOllama, tags};

fn script() -> Vec<(&'static str, Behaviour)> {
    let answer = json!({
        "verdict": "unsure", "category": "exposure", "reason": "", "evidence": []
    })
    .to_string();
    vec![
        (
            "/api/version",
            Behaviour::Json(200, json!({ "version": "0.12.6" })),
        ),
        (
            "/api/tags",
            Behaviour::Json(200, tags(&[("qwen3:8b", "8.2B", "3333")])),
        ),
        (
            "/api/chat",
            Behaviour::Json(
                200,
                json!({
                    "message": { "role": "assistant", "content": answer },
                    "done": true,
                    "done_reason": "stop",
                    "prompt_eval_count": 100,
                }),
            ),
        ),
    ]
}

#[test]
fn ollama_host_in_the_environment_is_never_read_and_only_the_configured_address_is_asked() {
    let configured = FixtureOllama::start(script());
    let decoy = FixtureOllama::start(script());
    // SAFETY: this test binary holds this one test, so no other thread reads
    // or writes the environment while it runs.
    unsafe {
        std::env::set_var("OLLAMA_HOST", format!("http://{}", decoy.address()));
    }

    let address = OllamaAddress::parse(&configured.address().to_string()).expect("loopback");
    let client = OllamaClient::new(&address);
    assert_eq!(client.address(), configured.address());
    assert!(matches!(client.presence(), OllamaPresence::Running { .. }));
    let engine = OllamaEngine::for_model(client, "qwen3:8b").expect("pulled");
    let item = Item::file(
        "claude-code",
        Scope::User,
        Kind::InstructionFile,
        "CLAUDE.md",
        Path::new("/home/nobody/.claude/CLAUDE.md").to_path_buf(),
        Provenance::Unknown,
        Activation::Active,
        b"Be brief.\n".to_vec(),
    );
    let request = request_builder(Normalisation::new(Path::new("/home/nobody"), "nobody"))
        .build(&item, &[])
        .expect("a request");
    judge(&engine, &request, &[]).expect("a Verdict");

    assert_eq!(decoy.connections(), 0, "OLLAMA_HOST was followed");
    // Detection (version and model list), the engine's model list and one
    // chat: every connection the engine opened, the fixture saw.
    assert_eq!(configured.connections(), 4);
    let paths: Vec<String> = configured
        .all_received()
        .into_iter()
        .map(|request| request.path)
        .collect();
    assert_eq!(
        paths,
        ["/api/version", "/api/tags", "/api/tags", "/api/chat"]
    );
}
