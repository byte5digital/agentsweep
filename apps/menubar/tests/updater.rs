//! The app updater against a local fixture server (spec section 9.4).
//!
//! The real Tauri updater plugin runs on Tauri's mock runtime with the
//! plugin configuration `tauri.conf.json` ships, except for two things: its
//! endpoint is a loopback fixture server, which serves a `latest.json` and an
//! archive signed with the development updater key and counts every request,
//! and its public key is the development one, from the configuration override
//! beside that key's secret half. The shipped file pins byte5's updater key,
//! whose secret half the repository never holds. Nothing here reaches the
//! network, and nothing is installed: the install at quit is tested at its
//! seam in the `updater` module.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine;
use serde_json::{Value, json};
use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};

use agentsweep_menubar::updater::{ENDPOINT, Look, PluginSource, READY, Ready, Source, Updates};

/// The configuration the app ships.
const SHIPPED: &str = include_str!("../tauri.conf.json");

/// The development updater key's secret half, in the form the Tauri command
/// line interface reads: base64 of the minisign secret key, encrypted with
/// an empty password.
const DEVELOPMENT_SECRET: &str = include_str!("../development-keys/updater-development.secret");

/// The configuration override that pins the development updater key's public
/// half in place of byte5's, for the tests and the CI bundle alone.
const DEVELOPMENT_OVERRIDE: &str = include_str!("../development-keys/tauri.development.conf.json");

/// The key id of byte5's updater key, as the owner noted it when the pair was
/// generated.
const RELEASE_KEY_ID: &str = "7539592E07DACF55";

/// The public half of the development updater key, as the override pins it:
/// base64 of the whole minisign `.pub` file.
fn development_pubkey() -> String {
    let development: Value =
        serde_json::from_str(DEVELOPMENT_OVERRIDE).expect("the override is JSON");
    development["plugins"]["updater"]["pubkey"]
        .as_str()
        .expect("a key")
        .to_string()
}

/// The key id minisign names a public key by: bytes 2 to 9 of the key line,
/// read as a little-endian integer, in sixteen upper-case hex digits.
fn key_id(pub_file: &str) -> String {
    let line = pub_file.lines().nth(1).expect("a key line");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(line.trim())
        .expect("base64");
    let id: [u8; 8] = bytes[2..10].try_into().expect("eight bytes");
    format!("{:016X}", u64::from_le_bytes(id))
}

/// The archive the fixture serves: a stand-in, never unpacked.
const ARCHIVE: &[u8] = b"a stand-in for AgentSweep.app.tar.gz, never installed\n";

/// The version the mock runtime runs as.
const CURRENT: &str = "0.1.0";

fn base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unbase64(text: &str) -> String {
    String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .expect("base64"),
    )
    .expect("text")
}

/// Signs `bytes` with the development key, as the release signs its
/// archive, and answers the `signature` field of `latest.json`.
fn signed(bytes: &[u8]) -> String {
    let secret = minisign::SecretKeyBox::from_string(&unbase64(DEVELOPMENT_SECRET))
        .and_then(|secret| secret.into_secret_key(Some(String::new())))
        .expect("the development secret key reads");
    let signature = minisign::sign(None, &secret, bytes, Some("AgentSweep.app.tar.gz"), None)
        .expect("the development key signs");
    base64(signature.to_string().as_bytes())
}

/// Signs `bytes` with a key made on the spot, which nothing pins.
fn signed_with_an_unpinned_key(bytes: &[u8]) -> String {
    let pair = minisign::KeyPair::generate_unencrypted_keypair().expect("a throwaway key pair");
    let signature = minisign::sign(None, &pair.sk, bytes, None, None).expect("the key signs");
    base64(signature.to_string().as_bytes())
}

/// One request the fixture server saw.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
}

/// A loopback HTTP server that answers fixed bodies by path and records
/// every request.
struct Fixture {
    address: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Fixture {
    /// Serves `latest.json` announcing `version` with `signature`, and the
    /// archive.
    fn serving(version: &str, signature: &str) -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = format!("http://{}", listener.local_addr().expect("an address"));
        let archive_url = format!("{address}/download/AgentSweep.app.tar.gz");
        let platform = json!({"signature": signature, "url": archive_url});
        // Both darwin keys point at the same universal archive (spec 9.1).
        let latest = json!({
            "version": version,
            "notes": "defanged fixture release",
            "pub_date": "2026-10-19T00:00:00Z",
            "platforms": {
                "darwin-aarch64": platform,
                "darwin-x86_64": platform,
            },
        })
        .to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                answer(stream, &latest, &recorded);
            }
        });
        Fixture { address, seen }
    }

    fn endpoint(&self) -> String {
        format!("{}/releases/latest/download/latest.json", self.address)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("the requests").clone()
    }

    fn count(&self, path: &str) -> usize {
        self.seen().iter().filter(|seen| seen.path == path).count()
    }
}

/// Reads one request and answers it, closing the connection.
fn answer(stream: TcpStream, latest: &str, seen: &Mutex<Vec<Seen>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("the stream"));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    seen.lock().expect("the requests").push(Seen {
        method,
        path: path.clone(),
        headers,
    });
    let (status, kind, body): (&str, &str, &[u8]) = match path.as_str() {
        "/releases/latest/download/latest.json" => {
            ("200 OK", "application/json", latest.as_bytes())
        }
        "/download/AgentSweep.app.tar.gz" => ("200 OK", "application/octet-stream", ARCHIVE),
        _ => ("404 Not Found", "text/plain", b"not here"),
    };
    let mut stream = stream;
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// The app as it ships, its updater asking `endpoint` instead and trusting
/// the development key the fixture signs with.
fn app_against(endpoint: &str) -> tauri::App<MockRuntime> {
    app_trusting(endpoint, Some(&development_pubkey()))
}

/// The app as it ships, its updater asking `endpoint` instead and trusting
/// `pubkey`, or the key the shipped configuration pins when that is `None`.
fn app_trusting(endpoint: &str, pubkey: Option<&str>) -> tauri::App<MockRuntime> {
    let shipped: Value = serde_json::from_str(SHIPPED).expect("tauri.conf.json is JSON");
    let mut updater = shipped["plugins"]["updater"].clone();
    updater["endpoints"] = json!([endpoint]);
    if let Some(pubkey) = pubkey {
        updater["pubkey"] = json!(pubkey);
    }
    let mut context = mock_context(noop_assets());
    context
        .config_mut()
        .plugins
        .0
        .insert("updater".to_string(), updater);
    mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(context)
        .expect("the mock app builds")
}

const LATEST: &str = "/releases/latest/download/latest.json";
const ARCHIVE_PATH: &str = "/download/AgentSweep.app.tar.gz";

fn launch() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

#[test]
fn the_shipped_configuration_pins_the_fixed_endpoint_and_byte5s_updater_key() {
    let shipped: Value = serde_json::from_str(SHIPPED).expect("tauri.conf.json is JSON");
    assert_eq!(shipped["bundle"]["createUpdaterArtifacts"], json!(true));
    assert_eq!(
        shipped["plugins"]["updater"]["endpoints"],
        json!([ENDPOINT]),
        "one fixed endpoint, no variables"
    );
    assert!(!ENDPOINT.contains("{{"));
    // The pinned key is byte5's (spec section 9.8), never the development
    // key whose secret half is committed beside the tests: the development
    // secret signs nothing the shipped key verifies.
    let pubkey = shipped["plugins"]["updater"]["pubkey"]
        .as_str()
        .expect("a key");
    assert_ne!(pubkey, development_pubkey());
    let pinned = unbase64(pubkey);
    assert!(!pinned.contains("DEVELOPMENT"), "{pinned}");
    assert_eq!(key_id(&pinned), RELEASE_KEY_ID);
    assert_ne!(key_id(&unbase64(&development_pubkey())), RELEASE_KEY_ID);
    assert!(verifies(&pinned, &signed(ARCHIVE)).is_err());
    // The webview may not call the plugin: the capability grants no
    // updater permission.
    assert!(!include_str!("../capabilities/default.json").contains("updater"));
}

/// The override changes the updater's public key and nothing else, and the
/// development secret committed beside it signs what it pins.
#[test]
fn the_development_override_pins_the_development_key_and_nothing_else() {
    let development: Value =
        serde_json::from_str(DEVELOPMENT_OVERRIDE).expect("the override is JSON");
    let mut keys: Vec<&str> = development
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .filter(|key| *key != "$schema")
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["plugins"]);
    assert_eq!(
        development["plugins"],
        json!({"updater": {"pubkey": development_pubkey()}})
    );
    let pinned = unbase64(&development_pubkey());
    assert!(pinned.contains("DEVELOPMENT"), "{pinned}");
    verifies(&pinned, &signed(ARCHIVE))
        .expect("the development secret signs what the override pins");
}

/// The shipped key refuses an update signed with the development key: the
/// committed secret half signs nothing an install accepts.
#[test]
fn an_update_signed_with_the_development_key_is_refused_by_the_shipped_key() {
    let fixture = Fixture::serving("0.2.0", &signed(ARCHIVE));
    let app = app_trusting(&fixture.endpoint(), None);
    let updates: Updates<Ready> = Updates::new();
    let look = updates.look(launch(), || true, &PluginSource(app.handle().clone()));
    let Look::Failed(why) = look else {
        panic!("an update signed with the development key was taken: {look:?}");
    };
    assert!(why.to_lowercase().contains("key"), "{why}");
    assert_eq!(updates.line(), None);
}

/// Whether the minisign `.pub` file `pub_file` verifies the `signature`
/// field of `latest.json` over the fixture archive.
fn verifies(pub_file: &str, signature: &str) -> Result<(), minisign::PError> {
    let public = minisign::PublicKeyBox::from_string(pub_file)?.into_public_key()?;
    let signature = minisign::SignatureBox::from_string(&unbase64(signature))?;
    minisign::verify(
        &public,
        &signature,
        std::io::Cursor::new(ARCHIVE),
        true,
        false,
        false,
    )
}

#[test]
fn a_newer_version_is_downloaded_and_verified_and_the_popover_says_so() {
    let fixture = Fixture::serving("0.2.0", &signed(ARCHIVE));
    let app = app_against(&fixture.endpoint());
    let updates: Updates<Ready> = Updates::new();
    let look = updates.look(launch(), || true, &PluginSource(app.handle().clone()));
    assert_eq!(look, Look::Ready);
    assert_eq!(updates.line(), Some(READY));
    assert_eq!(fixture.count(LATEST), 1);
    assert_eq!(fixture.count(ARCHIVE_PATH), 1);
}

#[test]
fn the_ready_update_carries_the_verified_archive() {
    let fixture = Fixture::serving("0.2.0", &signed(ARCHIVE));
    let app = app_against(&fixture.endpoint());
    let ready = PluginSource(app.handle().clone())
        .fetch()
        .expect("the check answers")
        .expect("an update");
    assert_eq!(ready.version(), "0.2.0");
    assert_eq!(ready.bytes(), ARCHIVE);
}

#[test]
fn a_bad_signature_is_refused_and_nothing_is_shown() {
    let fixture = Fixture::serving("0.2.0", &signed_with_an_unpinned_key(ARCHIVE));
    let app = app_against(&fixture.endpoint());
    let updates: Updates<Ready> = Updates::new();
    let look = updates.look(launch(), || true, &PluginSource(app.handle().clone()));
    let Look::Failed(why) = look else {
        panic!("a bad signature was taken: {look:?}");
    };
    assert!(why.to_lowercase().contains("key"), "{why}");
    assert_eq!(updates.line(), None);
    // Refused after the download, by the signature check, not before.
    assert_eq!(fixture.count(ARCHIVE_PATH), 1);
}

#[test]
fn a_signature_over_other_bytes_is_refused() {
    let fixture = Fixture::serving("0.2.0", &signed(b"some other archive"));
    let app = app_against(&fixture.endpoint());
    let Err(why) = PluginSource(app.handle().clone()).fetch() else {
        panic!("the archive does not match its signature");
    };
    assert!(why.to_lowercase().contains("signature"), "{why}");
}

#[test]
fn an_older_version_is_refused_without_a_download_and_nothing_is_shown() {
    let fixture = Fixture::serving("0.0.9", &signed(ARCHIVE));
    let app = app_against(&fixture.endpoint());
    let updates: Updates<Ready> = Updates::new();
    let look = updates.look(launch(), || true, &PluginSource(app.handle().clone()));
    assert_eq!(look, Look::Current);
    assert_eq!(updates.line(), None);
    assert_eq!(fixture.count(LATEST), 1);
    assert_eq!(fixture.count(ARCHIVE_PATH), 0);
}

#[test]
fn the_same_version_is_refused() {
    let fixture = Fixture::serving(CURRENT, &signed(ARCHIVE));
    let app = app_against(&fixture.endpoint());
    let answer = PluginSource(app.handle().clone()).fetch();
    assert!(matches!(answer, Ok(None)));
    assert_eq!(fixture.count(ARCHIVE_PATH), 0);
}

#[test]
fn with_the_toggle_off_no_request_is_made_at_launch_or_after_a_day() {
    let fixture = Fixture::serving("0.2.0", &signed(ARCHIVE));
    let app = app_against(&fixture.endpoint());
    let source = PluginSource(app.handle().clone());
    let updates: Updates<Ready> = Updates::new();
    assert_eq!(updates.look(launch(), || false, &source), Look::Off);
    let day = Duration::from_secs(24 * 60 * 60);
    assert_eq!(updates.look(launch() + day, || false, &source), Look::Off);
    assert_eq!(
        updates.look(launch() + day * 2, || false, &source),
        Look::Off
    );
    assert!(fixture.seen().is_empty(), "{:?}", fixture.seen());
}

#[test]
fn with_the_toggle_on_each_check_is_exactly_one_get() {
    let fixture = Fixture::serving(CURRENT, &signed(ARCHIVE));
    let app = app_against(&fixture.endpoint());
    let source = PluginSource(app.handle().clone());
    let updates: Updates<Ready> = Updates::new();
    let day = Duration::from_secs(24 * 60 * 60);
    assert_eq!(updates.look(launch(), || true, &source), Look::Current);
    assert_eq!(fixture.seen().len(), 1);
    assert_eq!(
        updates.look(launch() + Duration::from_secs(3600), || true, &source),
        Look::NotDue
    );
    assert_eq!(fixture.seen().len(), 1);
    assert_eq!(
        updates.look(launch() + day, || true, &source),
        Look::Current
    );
    let seen = fixture.seen();
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter()
            .all(|seen| seen.method == "GET" && seen.path == LATEST)
    );
}

#[test]
fn the_request_carries_no_identifier() {
    let fixture = Fixture::serving(CURRENT, &signed(ARCHIVE));
    let app = app_against(&fixture.endpoint());
    PluginSource(app.handle().clone())
        .fetch()
        .expect("the check answers");
    let seen = fixture.seen();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    // The fixed endpoint, with no query and nothing appended.
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, LATEST);
    assert!(ENDPOINT.ends_with(LATEST));
    // Only the plugin's fixed headers: the host, its own name and version as
    // the user agent, and what it accepts.
    let names: Vec<&str> = request.headers.keys().map(String::as_str).collect();
    for name in &names {
        assert!(
            ["host", "user-agent", "accept", "accept-encoding"].contains(name),
            "an unexpected header {name}: {:?}",
            request.headers
        );
    }
    let agent = &request.headers["user-agent"];
    assert!(agent.starts_with("tauri-plugin-updater/"), "{agent}");
    assert_eq!(request.headers["accept"], "application/json");
    let everything = format!("{} {:?}", request.path, request.headers);
    for identifier in [
        "de.byte5.agentsweep",
        "agentsweep",
        CURRENT,
        "darwin",
        "aarch64",
        "x86_64",
    ] {
        assert!(
            !everything.contains(identifier),
            "the request names {identifier}: {everything}"
        );
    }
}
