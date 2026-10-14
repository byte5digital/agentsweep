//! `agentsweep gate`, the Gate both Agents run as a hook, run as the Agents
//! run it: the event JSON on stdin, the decision on stdout, exit 0.
//!
//! The daemon here is a stand-in on a socket under the temporary directory: it
//! shakes hands, records every byte of the `gate` request it is sent and
//! answers with the verdict the test chose, or never answers at all. That is
//! how a test sees exactly what leaves the command, which a real daemon would
//! not show. The end-to-end run against a real daemon on a temporary home is
//! in the variants suite, beside the daemon it builds.
//!
//! Only the in-bundle build has the Gate.

#![cfg(feature = "bundle")]

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use agentsweep_ipc::{Message, read_frame, welcome, write_frame};
use serde_json::{Value, json};

/// Keeps one test's temporary paths apart from another's.
static NEXT: AtomicU32 = AtomicU32::new(0);

/// What every failure prints, the fixed fail-open answer.
const FAIL_OPEN: &str = "{\"systemMessage\":\"AgentSweep is not running, nothing was checked.\"}\n";

/// The deadline of spec section 7.4 plus what starting a process may take on
/// a busy machine.
const DEADLINE_PLUS_START_UP: Duration = Duration::from_millis(2000 + 1500);

/// The prompt and the command the recorded events carry, which must never
/// reach the daemon whole.
const CLAUDE_PROMPT: &str = "Summarise the open tickets for the hidden-project-alpha release";
const CODEX_PROMPT: &str =
    "Please use $deploy-preview and then $notes:jot for the hidden-project-beta changelog";
const BASH_COMMAND: &str = "cd ~/.claude/skills/setup && bash ./scripts/install.sh --token-file=./secret-name.txt | tee /tmp/install-hidden.log";

fn socket_path() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "asg-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_file(&path);
    path
}

/// A temporary folder of this suite's own.
struct Temporary(PathBuf);

impl Temporary {
    fn new(purpose: &str) -> Temporary {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-gate-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("a temporary folder");
        Temporary(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Every entry under a folder with its size and modification time.
fn listing(root: &Path) -> BTreeSet<String> {
    let mut entries = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory).expect("a readable folder") {
            let path = entry.expect("a readable entry").path();
            let metadata = fs::symlink_metadata(&path).expect("metadata");
            entries.insert(format!(
                "{} {} {:?}",
                path.display(),
                metadata.len(),
                metadata.modified().ok()
            ));
            if metadata.is_dir() {
                stack.push(path);
            }
        }
    }
    entries
}

/// A stream that keeps a copy of every byte read from it.
struct Recording {
    stream: UnixStream,
    read: Vec<u8>,
}

impl Read for Recording {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.stream.read(buffer)?;
        self.read.extend_from_slice(&buffer[..count]);
        Ok(count)
    }
}

/// What the stand-in daemon was sent: the raw bytes of the `gate` request
/// frame and the request as it reads.
struct Sent {
    bytes: Vec<u8>,
    request: Value,
}

/// A stand-in daemon that answers one `gate` request with `verdict`.
fn answering(socket: &Path, verdict: Value) -> JoinHandle<Sent> {
    let listener = UnixListener::bind(socket).expect("a socket");
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("a connection");
        let mut out = stream.try_clone().expect("a second handle");
        let mut recording = Recording {
            stream,
            read: Vec::new(),
        };
        let hello = read_frame(&mut recording)
            .expect("a frame")
            .expect("a hello");
        assert_eq!(hello["type"], "hello", "{hello}");
        write_frame(&mut out, &welcome().to_value()).expect("the welcome");
        recording.read.clear();
        let request = read_frame(&mut recording)
            .expect("a frame")
            .expect("a request");
        let id = request["id"].as_str().expect("an id").to_string();
        let response = Message::Response {
            id,
            result: Ok(verdict),
        };
        write_frame(&mut out, &response.to_value()).expect("the answer");
        Sent {
            bytes: recording.read,
            request,
        }
    })
}

/// Runs the Gate with one event on stdin, in a working directory and under a
/// home of the test's own, and says how long it took.
fn gate(agent: &str, socket: &Path, stdin: &[u8], home: &Path) -> (Output, Duration) {
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsweep"))
        .args(["gate", "--agent", agent, "--socket"])
        .arg(socket)
        .current_dir(home)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the CLI starts");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("the event is written");
    let output = child.wait_with_output().expect("the CLI ran");
    (output, started.elapsed())
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("the output is text")
}

/// One recorded event, what the request must carry, and what must never be
/// in the bytes sent.
struct Recorded {
    agent: &'static str,
    event: Value,
    tool: Value,
    secret: &'static str,
}

fn recorded(cwd: &str) -> Vec<Recorded> {
    vec![
        Recorded {
            agent: "claude-code",
            event: json!({
                "session_id": "s", "transcript_path": "/x.invalid/t.jsonl", "cwd": cwd,
                "permission_mode": "default", "hook_event_name": "UserPromptSubmit",
                "prompt": CLAUDE_PROMPT,
            }),
            tool: Value::Null,
            secret: CLAUDE_PROMPT,
        },
        Recorded {
            agent: "claude-code",
            event: json!({
                "session_id": "s", "transcript_path": "/x.invalid/t.jsonl", "cwd": cwd,
                "permission_mode": "default", "hook_event_name": "PreToolUse",
                "tool_name": "Bash", "tool_use_id": "u",
                "tool_input": { "command": BASH_COMMAND, "description": "Install" },
            }),
            tool: json!({
                "name": "Bash",
                "paths": [
                    "cd", "~/.claude/skills/setup", "bash", "./scripts/install.sh",
                    "./secret-name.txt", "tee", "/tmp/install-hidden.log"
                ],
                "skills": [],
            }),
            secret: BASH_COMMAND,
        },
        Recorded {
            agent: "claude-code",
            event: json!({
                "session_id": "s", "cwd": cwd, "hook_event_name": "PreToolUse",
                "tool_name": "Skill", "tool_use_id": "u",
                "tool_input": { "skill": "setup", "args": "for hidden-project-gamma" },
            }),
            tool: json!({ "name": "Skill", "skill": "setup", "paths": [], "skills": [] }),
            secret: "hidden-project-gamma",
        },
        Recorded {
            agent: "claude-code",
            event: json!({
                "session_id": "s", "cwd": cwd, "hook_event_name": "PreToolUse",
                "tool_name": "mcp__tracker__list_issues", "tool_use_id": "u",
                "tool_input": { "query": "hidden-project-delta" },
                "mcp_server": { "name": "tracker", "source": "user" },
            }),
            tool: json!({
                "name": "mcp__tracker__list_issues",
                "mcp_server": { "name": "tracker", "source": "user" },
                "paths": [], "skills": [],
            }),
            secret: "hidden-project-delta",
        },
        Recorded {
            agent: "claude-code",
            event: json!({
                "session_id": "s", "cwd": cwd, "hook_event_name": "UserPromptExpansion",
                "expansion_type": "slash_command", "command_name": "notes:jot",
                "command_args": "hidden-project-epsilon", "command_source": "plugin",
                "prompt": "/notes:jot hidden-project-epsilon",
            }),
            tool: json!({ "skill": "notes:jot", "paths": [], "skills": [] }),
            secret: "hidden-project-epsilon",
        },
        Recorded {
            agent: "codex",
            event: json!({
                "session_id": "s", "transcript_path": null, "cwd": cwd,
                "hook_event_name": "UserPromptSubmit", "model": "m",
                "permission_mode": "default", "turn_id": "t",
                "prompt": CODEX_PROMPT,
            }),
            tool: json!({ "paths": [], "skills": ["deploy-preview", "notes:jot"] }),
            secret: CODEX_PROMPT,
        },
        Recorded {
            agent: "codex",
            event: json!({
                "session_id": "s", "cwd": cwd, "hook_event_name": "PreToolUse",
                "model": "m", "turn_id": "t", "tool_name": "mcp__tracker__create_issue",
                "tool_use_id": "u", "tool_input": { "title": "hidden-project-zeta" },
            }),
            tool: json!({
                "name": "mcp__tracker__create_issue",
                "mcp_server": { "name": "tracker" },
                "paths": [], "skills": [],
            }),
            secret: "hidden-project-zeta",
        },
        Recorded {
            agent: "codex",
            event: json!({
                "session_id": "s", "cwd": cwd, "hook_event_name": "PreToolUse",
                "model": "m", "turn_id": "t", "tool_name": "Bash", "tool_use_id": "u",
                "tool_input": { "command": BASH_COMMAND },
            }),
            tool: json!({
                "name": "Bash",
                "paths": [
                    "cd", "~/.claude/skills/setup", "bash", "./scripts/install.sh",
                    "./secret-name.txt", "tee", "/tmp/install-hidden.log"
                ],
                "skills": [],
            }),
            secret: BASH_COMMAND,
        },
    ]
}

/// Each of the five event and Agent pairs of spec section 7.2, from recorded
/// event JSON: the request carries the Agent, the event, `cwd` and exactly
/// the Item-naming fields, and the prompt text and the full shell command are
/// nowhere in the bytes sent.
#[test]
fn each_event_sends_only_its_item_naming_fields() {
    let home = Temporary::new("fields");
    let cwd = home.path().to_string_lossy().to_string();
    for one in recorded(&cwd) {
        let socket = socket_path();
        let daemon = answering(&socket, json!({ "verdict": "clear" }));
        let (output, _) = gate(
            one.agent,
            &socket,
            one.event.to_string().as_bytes(),
            home.path(),
        );
        let sent = daemon.join().expect("the stand-in daemon");
        let _ = fs::remove_file(&socket);

        assert_eq!(output.status.code(), Some(0));
        assert_eq!(text(&output.stdout), "", "clear prints nothing");
        let request = &sent.request;
        assert_eq!(request["request"], "gate", "{request}");
        assert_eq!(request["agent"], one.agent, "{request}");
        assert_eq!(request["event"], one.event["hook_event_name"], "{request}");
        assert_eq!(request["cwd"], cwd.as_str(), "{request}");
        assert_eq!(
            request.get("tool").cloned().unwrap_or(Value::Null),
            one.tool,
            "{request}"
        );
        let bytes = String::from_utf8_lossy(&sent.bytes).to_string();
        assert!(!bytes.contains(one.secret), "{} sent: {bytes}", one.secret);
        for whole in [CLAUDE_PROMPT, CODEX_PROMPT, BASH_COMMAND] {
            assert!(!bytes.contains(whole), "{bytes}");
        }
        assert!(!bytes.contains("hidden-project"), "{bytes}");
    }
}

/// Each reason code, through the binary, prints the decision the Agent reads
/// for that event with the section 7.5 sentence in it.
#[test]
fn each_reason_code_prints_the_fixed_sentence_where_the_agent_reads_it() {
    let home = Temporary::new("wording");
    let cwd = home.path().to_string_lossy().to_string();
    let turn =
        json!({ "hook_event_name": "UserPromptSubmit", "cwd": cwd, "prompt": "hello" }).to_string();
    let call = json!({
        "hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Bash",
        "tool_input": { "command": "./run.sh" },
    })
    .to_string();
    let project = "AgentSweep stopped this turn. 3 items in this project need your decision. \
                   Open AgentSweep, decide, then try again.";
    let item = "AgentSweep blocked this step: the skill, tool or script it uses is flagged and \
                waits for the user's decision. Do not retry or work around it. Tell the user to \
                open AgentSweep.";
    let cases = [
        (
            "claude-code",
            turn.clone(),
            "project",
            3,
            json!({
                "decision": "block", "reason": project,
            }),
        ),
        (
            "codex",
            turn.clone(),
            "project",
            3,
            json!({
                "decision": "block", "reason": project,
            }),
        ),
        (
            "claude-code",
            turn.clone(),
            "user_instructions",
            1,
            json!({
                "decision": "block",
                "reason": "AgentSweep stopped this turn. Your Claude Code instructions file was \
                           flagged and needs your decision. Open AgentSweep.",
            }),
        ),
        (
            "codex",
            turn.clone(),
            "user_instructions",
            1,
            json!({
                "decision": "block",
                "reason": "AgentSweep stopped this turn. Your Codex instructions file was flagged \
                           and needs your decision. Open AgentSweep.",
            }),
        ),
        (
            "claude-code",
            call.clone(),
            "item",
            1,
            json!({ "hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "deny",
                "permissionDecisionReason": item,
            }}),
        ),
        (
            "codex",
            call.clone(),
            "item",
            2,
            json!({ "hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "deny",
                "permissionDecisionReason": item,
            }}),
        ),
    ];
    for (agent, event, reason, count, expected) in cases {
        let socket = socket_path();
        let daemon = answering(
            &socket,
            json!({ "verdict": "block", "count": count, "reason": reason }),
        );
        let (output, _) = gate(agent, &socket, event.as_bytes(), home.path());
        daemon.join().expect("the stand-in daemon");
        let _ = fs::remove_file(&socket);
        assert_eq!(output.status.code(), Some(0));
        let printed: Value = serde_json::from_slice(&output.stdout).expect("one JSON object");
        assert_eq!(printed, expected, "{agent} {reason}");
        assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
    }

    // `unknown` allows as silently as `clear`.
    let socket = socket_path();
    let daemon = answering(&socket, json!({ "verdict": "unknown" }));
    let (output, _) = gate("claude-code", &socket, call.as_bytes(), home.path());
    daemon.join().expect("the stand-in daemon");
    let _ = fs::remove_file(&socket);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "{}", text(&output.stdout));
}

fn a_turn(cwd: &Path) -> Vec<u8> {
    json!({ "hook_event_name": "UserPromptSubmit", "cwd": cwd, "prompt": "hello" })
        .to_string()
        .into_bytes()
}

/// No daemon listening: allow with the fail-open message, exit 0, within the
/// deadline.
#[test]
fn with_no_daemon_the_gate_allows_with_the_fail_open_message() {
    let home = Temporary::new("nobody");
    let socket = socket_path();
    let (output, took) = gate("claude-code", &socket, &a_turn(home.path()), home.path());
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(text(&output.stdout), FAIL_OPEN);
    assert!(took < DEADLINE_PLUS_START_UP, "{took:?}");
}

/// A daemon that accepts the connection and never answers: the deadline
/// passes and the Gate allows, rather than holding the turn for the hook's
/// whole timeout.
#[test]
fn with_a_daemon_that_never_answers_the_gate_allows_after_the_deadline() {
    let home = Temporary::new("silent");
    let socket = socket_path();
    let listener = UnixListener::bind(&socket).expect("a socket");
    let holder = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("a connection");
        std::thread::sleep(Duration::from_secs(6));
        drop(stream);
    });
    // The listener accepts once; the second run finds a socket that is bound
    // but no one accepting, which waits the same way.
    for agent in ["claude-code", "codex"] {
        let (output, took) = gate(agent, &socket, &a_turn(home.path()), home.path());
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(text(&output.stdout), FAIL_OPEN);
        assert!(took >= Duration::from_millis(1900), "{took:?}");
        assert!(took < DEADLINE_PLUS_START_UP, "{took:?}");
    }
    let _ = fs::remove_file(&socket);
    drop(holder);
}

/// Stdin that is not an event, empty stdin, an event without `cwd` and a
/// command line the Gate does not understand: allow with the fail-open
/// message and exit 0, each well within the deadline.
#[test]
fn malformed_input_allows_with_the_fail_open_message() {
    let home = Temporary::new("malformed");
    let socket = socket_path();
    let daemon = answering(
        &socket,
        json!({ "verdict": "block", "count": 1, "reason": "item" }),
    );
    for stdin in [
        b"not json at all".to_vec(),
        Vec::new(),
        b"{\"hook_event_name\":\"UserPromptSubmit\"}".to_vec(),
        b"{\"hook_event_name\":\"Stop\",\"cwd\":\"/w\"}".to_vec(),
        vec![0xff, 0xfe, 0x00],
    ] {
        let (output, took) = gate("claude-code", &socket, &stdin, home.path());
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(text(&output.stdout), FAIL_OPEN);
        assert!(took < DEADLINE_PLUS_START_UP, "{took:?}");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_agentsweep"))
        .args(["gate", "--agent", "cursor"])
        .stdin(Stdio::null())
        .output()
        .expect("the CLI ran");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(text(&output.stdout), FAIL_OPEN);

    // The stand-in was never asked: nothing malformed reached a daemon.
    let _ = fs::remove_file(&socket);
    assert!(!daemon.is_finished());
}

/// The command writes nothing to disk: not under the home it runs with, not
/// in its working directory, whatever the verdict.
#[test]
fn the_gate_writes_nothing_to_disk() {
    let home = Temporary::new("nothing-written");
    fs::create_dir_all(home.path().join(".claude/skills/setup")).expect("a skill folder");
    fs::write(home.path().join(".claude/settings.json"), b"{}\n").expect("settings");
    let before = listing(home.path());
    let call = json!({
        "hook_event_name": "PreToolUse", "cwd": home.path(), "tool_name": "Skill",
        "tool_input": { "skill": "setup" },
    })
    .to_string();

    for verdict in [
        json!({ "verdict": "block", "count": 1, "reason": "item" }),
        json!({ "verdict": "clear" }),
    ] {
        let socket = socket_path();
        let daemon = answering(&socket, verdict);
        let (output, _) = gate("claude-code", &socket, call.as_bytes(), home.path());
        daemon.join().expect("the stand-in daemon");
        let _ = fs::remove_file(&socket);
        assert_eq!(output.status.code(), Some(0));
    }
    let (output, _) = gate("codex", &socket_path(), call.as_bytes(), home.path());
    assert_eq!(text(&output.stdout), FAIL_OPEN);

    assert_eq!(listing(home.path()), before, "the Gate wrote");
}
