//! The Settings pane against a real daemon, and what the app may say about
//! Full Disk Access and what AgentSweep does not protect against.
//!
//! The daemon runs in this process on a temporary home, a temporary data
//! directory and a temporary socket, with its chain key held in memory. It
//! is a developer run, so it reaches no Rule Feed. Nothing touches the real
//! home, the documented socket, the real data directory or the Keychain.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use agentsweep_core::health::SETTINGS_UNREADABLE;
use agentsweep_core::keychain::MemoryKeySource;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::settings::Posture;
use agentsweep_daemon::Tuning;
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::service::{self, Background, Daemon};
use agentsweep_daemon::watcher::Timings;
use agentsweep_ipc::peer::SameUser;
use agentsweep_menubar::asking::Asking;
use agentsweep_menubar::frame::Frame;
use agentsweep_menubar::link::Socket;
use agentsweep_menubar::settings_pane::{
    FULL_DISK_ACCESS, NOT_PROTECTED, NOT_PROTECTED_LINK, NOT_PROTECTED_TITLE, change_of,
};
use serde_json::json;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// One machine, one data directory and one socket, all temporary.
struct Sandbox {
    root: PathBuf,
    socket: PathBuf,
}

impl Sandbox {
    fn new(purpose: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-settings-{purpose}-{}-{}",
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
            "asw-set-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        Sandbox { root, socket }
    }

    fn settings_file(&self) -> PathBuf {
        self.root.join("data/settings.json")
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

/// Detail and both toggles move through the daemon's `settings` request,
/// and the pane shows what the daemon answered.
#[test]
fn each_choice_moves_through_the_daemon_and_the_pane_follows_the_answer() {
    let sandbox = Sandbox::new("choices");
    let _daemon = sandbox.start();
    let asking = sandbox.asking();
    let mut frame = loaded(&asking);
    let pane = frame.to_value()["settings"].clone();
    assert_eq!(pane["available"], true);
    assert_eq!(pane["note"], serde_json::Value::Null);
    assert_eq!(pane["background"]["toggles"][0]["on"], true);
    assert_eq!(pane["background"]["toggles"][1]["on"], true);
    assert_eq!(pane["detail"]["choices"][0]["selected"], true);

    for (asked, check) in [
        (json!({ "rule_feed": false }), "rule feed"),
        (json!({ "update_check": false }), "update check"),
        (json!({ "posture": "developer" }), "posture"),
    ] {
        let change = change_of(&asked).expect("a change");
        let answer = asking.change_settings(&change).expect(check);
        frame.settings(&answer);
    }
    let value = frame.to_value();
    let pane = &value["settings"];
    assert_eq!(pane["background"]["toggles"][0]["on"], false);
    assert_eq!(pane["background"]["toggles"][1]["on"], false);
    assert_eq!(pane["detail"]["choices"][1]["selected"], true);
    assert_eq!(value["posture"], "developer");
    assert_eq!(frame.posture(), Posture::Developer);
    // The daemon wrote them, and reads them back.
    let reread = asking.settings().expect("the settings");
    assert!(!reread.rule_feed && !reread.update_check);
    assert_eq!(reread.posture, Posture::Developer);

    // An override per Agent, set and cleared, under Advanced.
    let dir = sandbox.root.join("work-codex");
    let set = change_of(&json!({ "agent": "codex", "dir": dir.display().to_string() }))
        .expect("a change");
    frame.settings(&asking.change_settings(&set).expect("an override"));
    assert_eq!(
        frame.to_value()["settings"]["advanced"]["configDirs"][1]["dir"],
        dir.display().to_string()
    );
    let cleared = change_of(&json!({ "agent": "codex", "dir": "" })).expect("a change");
    frame.settings(&asking.change_settings(&cleared).expect("cleared"));
    assert_eq!(
        frame.to_value()["settings"]["advanced"]["configDirs"][1]["dir"],
        serde_json::Value::Null
    );
}

/// An unreadable settings file shows the Health note in the pane, and a
/// choice can still be made; making it writes the file and clears the note.
#[test]
fn an_unreadable_settings_file_shows_the_note_and_still_takes_a_choice() {
    let sandbox = Sandbox::new("unreadable");
    std::fs::write(sandbox.settings_file(), b"{ not json").expect("a broken file");
    let _daemon = sandbox.start();
    let asking = sandbox.asking();
    let mut frame = loaded(&asking);
    let pane = frame.to_value()["settings"].clone();
    assert_eq!(pane["note"], SETTINGS_UNREADABLE);
    assert_eq!(pane["available"], true);
    // Every default while the file cannot be read.
    assert_eq!(pane["background"]["toggles"][0]["on"], true);

    let change = change_of(&json!({ "update_check": false })).expect("a change");
    let answer = asking.change_settings(&change).expect("taken");
    assert!(!answer.update_check);
    frame.settings(&answer);
    frame.load(&asking.status().expect("a status"));
    let pane = frame.to_value()["settings"].clone();
    assert_eq!(pane["background"]["toggles"][1]["on"], false);
    assert_eq!(pane["note"], serde_json::Value::Null);
    let written = std::fs::read_to_string(sandbox.settings_file()).expect("written");
    assert!(written.contains("\"update_check\": false"), "{written}");
}

/// Every file of the app, and of the crates whose sentences it shows,
/// without its comment lines.
fn produced_strings() -> Vec<(PathBuf, String)> {
    let app = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates = app.join("../../crates");
    let mut files = Vec::new();
    for directory in [
        app.join("src"),
        app.join("ui"),
        crates.join("core/src"),
        crates.join("ipc/src"),
        crates.join("daemon/src"),
    ] {
        walk(&directory, &mut files);
    }
    for file in [
        "Info.plist",
        "tauri.conf.json",
        "tauri.bundle.conf.json",
        "capabilities/default.json",
    ] {
        files.push(app.join(file));
    }
    files
        .into_iter()
        .map(|file| {
            let text = std::fs::read_to_string(&file).expect("a readable source");
            let code: Vec<&str> = text
                .lines()
                .filter(|line| {
                    let line = line.trim_start();
                    !line.starts_with("//") && !line.starts_with("<!--") && !line.starts_with('*')
                })
                .collect();
            (file, code.join("\n"))
        })
        .collect()
}

fn walk(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("a source directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            walk(&path, files);
        } else if path
            .extension()
            .is_some_and(|extension| ["rs", "js", "html", "css"].iter().any(|e| extension == *e))
        {
            files.push(path);
        }
    }
}

/// Full Disk Access is named by the Settings pane's module alone, which puts
/// it under Advanced only (the frame's own test holds that): no other pane,
/// notification, onboarding screen, Health line or refusal of the app says
/// it. The pane addresses go with it.
#[test]
fn full_disk_access_is_said_nowhere_but_under_advanced() {
    let own = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/settings_pane.rs");
    let mut named = Vec::new();
    for (file, code) in produced_strings() {
        let lower = code.to_lowercase();
        if (lower.contains(&FULL_DISK_ACCESS.to_lowercase()) || code.contains("Privacy_AllFiles"))
            && file != own
        {
            named.push(file.display().to_string());
        }
    }
    assert!(named.is_empty(), "Full Disk Access is named in {named:?}");
}

/// GitHub's anchor for a heading: lower case, spaces as hyphens, everything
/// but letters, digits, hyphens and underscores dropped.
fn anchor(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

/// The README carries the list of spec section 2.4 under the heading the
/// Settings link points at, every line marked as possibly supported later.
#[test]
fn the_not_protected_link_points_at_the_readme_section_with_the_list() {
    let readme =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
            .expect("the README");
    let heading = format!("## {NOT_PROTECTED_TITLE}");
    let start = readme.find(&heading).expect("the README section");
    let section = &readme[start + heading.len()..];
    let section = &section[..section.find("\n## ").unwrap_or(section.len())];

    let (page, fragment) = NOT_PROTECTED_LINK.split_once('#').expect("an anchor");
    assert_eq!(page, "https://github.com/byte5digital/agentsweep");
    assert_eq!(fragment, anchor(NOT_PROTECTED_TITLE));

    let items: Vec<&str> = section
        .lines()
        .filter_map(|line| line.strip_prefix("- "))
        .collect();
    assert_eq!(items.len(), NOT_PROTECTED.len(), "{section}");
    for (item, line) in items.iter().zip(NOT_PROTECTED) {
        assert_eq!(
            *item,
            format!("{line} Possibly supported in a future version.")
        );
    }
    assert!(!section.contains('\u{2014}'));
}
