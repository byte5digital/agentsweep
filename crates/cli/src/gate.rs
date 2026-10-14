//! `agentsweep gate --agent claude-code|codex`: the Gate, the hook both Agents
//! run before a turn and before a tool call (spec sections 7.2 to 7.5, ADR
//! 0008, ADR 0009).
//!
//! The Agent hands the event as JSON on stdin. This command takes the event
//! from `hook_event_name` and `cwd` from the event, extracts the fields that
//! name an Item, sends one `gate` request to the daemon and turns the verdict
//! into the output the Agent reads. The prompt text and the shell command never
//! leave this process: only the skill names extracted from a prompt and the
//! tokens of a command that may be paths do.
//!
//! On `block` it prints the decision the Agent honours with the fixed wording
//! of spec section 7.5: a turn (or a `/skill-name` expansion) blocked with
//! `decision: "block"` and its reason, a tool call denied through
//! `hookSpecificOutput.permissionDecision: "deny"` with its reason. On `clear`
//! and `unknown` it prints nothing. When the daemon cannot be reached, the
//! two-second deadline passes, stdin cannot be read or anything else goes
//! wrong, it allows with the fail-open `systemMessage`.
//!
//! The command keeps no state, writes nothing to disk and always exits 0, so
//! neither Agent ever reads a failure of AgentSweep as a decision. Fail-closed
//! is neither wanted nor enforceable (ADR 0009).

use std::io::Read;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use agentsweep_ipc::Client;
use agentsweep_ipc::gate::{
    GateEvent, GateReason, GateRequest, GateTool, GateVerdict, McpServerRef,
};
use agentsweep_ipc::protocol::Role;
use serde_json::{Value, json};

/// The connect-and-read deadline (spec section 7.4), well under the five
/// seconds each hook entry allows.
pub const DEADLINE: Duration = Duration::from_secs(2);

/// What the Gate tells the user when it could not check anything.
pub const FAIL_OPEN: &str = "AgentSweep is not running, nothing was checked.";

/// The key of a `Skill` call's `tool_input` that holds the skill's name.
///
/// Held in this one place because it is observed in the running Claude Code
/// binary rather than documented (spec section 12, verified live in ticket 45).
pub const SKILL_INPUT_KEY: &str = "skill";

/// The Agent a Gate runs in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Agent {
    /// Claude Code.
    ClaudeCode,
    /// Codex.
    Codex,
}

impl Agent {
    /// The spelling the hook entry and the `gate` request carry.
    pub fn as_str(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "claude-code",
            Agent::Codex => "codex",
        }
    }

    fn parse(text: &str) -> Option<Agent> {
        [Agent::ClaudeCode, Agent::Codex]
            .into_iter()
            .find(|agent| agent.as_str() == text)
    }

    /// The Agent's name as a person reads it in the instruction-file sentence.
    fn display_name(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "Claude Code",
            Agent::Codex => "Codex",
        }
    }
}

/// One `gate` command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// The Agent whose hook this is.
    pub agent: Agent,
    /// The socket to ask at, the documented one unless named.
    pub socket: Option<PathBuf>,
}

/// Reads the command line after `gate`.
pub fn parse(arguments: &[String]) -> Result<Invocation, String> {
    let mut agent = None;
    let mut socket = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--agent" => {
                let name = rest
                    .next()
                    .ok_or_else(|| "`--agent` takes claude-code or codex".to_string())?;
                agent = Some(
                    Agent::parse(name)
                        .ok_or_else(|| format!("`{name}` is not an agent the Gate runs in"))?,
                );
            }
            "--socket" => {
                let path = rest
                    .next()
                    .ok_or_else(|| "`--socket` takes a path".to_string())?;
                socket = Some(PathBuf::from(path));
            }
            other => return Err(format!("`gate` does not take `{other}`")),
        }
    }
    Ok(Invocation {
        agent: agent.ok_or_else(|| "`gate` takes `--agent`".to_string())?,
        socket,
    })
}

/// Runs the Gate on one event and answers with what to print. Whatever
/// happens, the caller prints the answer and exits 0.
///
/// Reading stdin, connecting and the daemon's answer all happen on a worker
/// thread under one deadline: when it passes, the answer is the fail-open one
/// and the process exits with the worker still waiting, which is how a daemon
/// that accepts and never answers costs no more than the deadline.
pub fn run(
    invocation: Result<Invocation, String>,
    stdin: impl Read + Send + 'static,
    deadline: Duration,
) -> String {
    let Ok(invocation) = invocation else {
        return fail_open();
    };
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(ask(&invocation, stdin));
    });
    match receiver.recv_timeout(deadline) {
        Ok(Some(answer)) => answer,
        Ok(None) | Err(_) => fail_open(),
    }
}

/// Reads the event, asks the daemon and renders its verdict, or nothing when
/// any step fails.
fn ask(invocation: &Invocation, mut stdin: impl Read) -> Option<String> {
    let mut bytes = Vec::new();
    stdin.read_to_end(&mut bytes).ok()?;
    let input: Value = serde_json::from_slice(&bytes).ok()?;
    let request = request_of(invocation.agent, &input)?;
    let event = request.event;
    let mut client = match &invocation.socket {
        Some(socket) => Client::connect_at(socket, Role::Cli),
        None => Client::connect(Role::Cli),
    }
    .ok()?;
    let verdict = client.gate(request).ok()?;
    Some(answer(invocation.agent, event, verdict))
}

/// The `gate` request for one event, or nothing when the event is not one the
/// Gate is registered for in this Agent or carries no absolute-looking `cwd`.
///
/// Only names and tokens are taken from the event: the prompt text and the
/// shell command stay here.
pub fn request_of(agent: Agent, input: &Value) -> Option<GateRequest> {
    let text = |value: &Value, field: &str| -> Option<String> {
        value
            .get(field)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    let event = GateEvent::parse(input.get("hook_event_name")?.as_str()?)?;
    let cwd = text(input, "cwd")?;
    let tool = match (agent, event) {
        (Agent::ClaudeCode, GateEvent::UserPromptSubmit) => None,
        (Agent::Codex, GateEvent::UserPromptSubmit) => {
            let skills = mentions(input.get("prompt").and_then(Value::as_str).unwrap_or(""));
            (!skills.is_empty()).then(|| GateTool {
                skills,
                ..GateTool::default()
            })
        }
        // The direct `/skill-name` path. The name a plugin's skill is invoked
        // by already carries its plugin (`plugin:skill`), so the source class
        // beside it adds nothing the request could match on: the reference is
        // the name.
        (Agent::ClaudeCode, GateEvent::UserPromptExpansion) => {
            text(input, "command_name").map(|skill| GateTool {
                skill: Some(skill),
                ..GateTool::default()
            })
        }
        (Agent::Codex, GateEvent::UserPromptExpansion) => return None,
        (agent, GateEvent::PreToolUse) => Some(tool_call(agent, input)?),
    };
    Some(GateRequest {
        agent: agent.as_str().to_string(),
        event,
        cwd,
        tool,
    })
}

/// The Item-naming fields of one tool call.
fn tool_call(agent: Agent, input: &Value) -> Option<GateTool> {
    let name = input.get("tool_name")?.as_str()?.to_string();
    let tool_input = input.get("tool_input").unwrap_or(&Value::Null);
    let skill = match agent {
        Agent::ClaudeCode => tool_input
            .get(SKILL_INPUT_KEY)
            .and_then(Value::as_str)
            .filter(|skill| !skill.is_empty())
            .map(str::to_string),
        Agent::Codex => None,
    };
    let reported = match agent {
        Agent::ClaudeCode => input.get("mcp_server").and_then(|server| {
            let name = server.get("name")?.as_str()?;
            (!name.is_empty()).then(|| McpServerRef {
                name: name.to_string(),
                source: server
                    .get("source")
                    .and_then(Value::as_str)
                    .filter(|source| !source.is_empty())
                    .map(str::to_string),
            })
        }),
        Agent::Codex => None,
    };
    let mcp_server = reported.or_else(|| {
        server_of(&name).map(|server| McpServerRef {
            name: server.to_string(),
            source: None,
        })
    });
    let paths = if name == "Bash" {
        let command = match tool_input.get("command") {
            Some(Value::String(command)) => command.clone(),
            Some(Value::Array(words)) => words
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            _ => String::new(),
        };
        path_tokens(&command)
    } else {
        Vec::new()
    };
    Some(GateTool {
        name: Some(name),
        skill,
        mcp_server,
        skills: Vec::new(),
        paths,
    })
}

/// The server an `mcp__<server>__<tool>` tool name reaches.
fn server_of(tool_name: &str) -> Option<&str> {
    let rest = tool_name.strip_prefix("mcp__")?;
    let (server, tool) = rest.split_once("__")?;
    (!server.is_empty() && !tool.is_empty()).then_some(server)
}

/// The `$name` mentions in a Codex prompt, each once, in the order they first
/// appear. A mention is a `$` at the start of the prompt or after a character
/// that cannot be part of a name, followed by the name; a run of digits alone
/// is an amount, not a name.
pub fn mentions(prompt: &str) -> Vec<String> {
    let is_name = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.');
    let mut found: Vec<String> = Vec::new();
    let mut previous: Option<char> = None;
    for (index, c) in prompt.char_indices() {
        let starts = c == '$' && previous.is_none_or(|before| !is_name(before) && before != '$');
        previous = Some(c);
        if !starts {
            continue;
        }
        let rest = &prompt[index + 1..];
        let length = rest.find(|c: char| !is_name(c)).unwrap_or(rest.len());
        let name = rest[..length].trim_end_matches(['.', ':', '-']);
        if !name.is_empty()
            && !name.chars().all(|c| c.is_ascii_digit())
            && !found.iter().any(|seen| seen == name)
        {
            found.push(name.to_string());
        }
    }
    found
}

/// The tokens of a shell command that may name a path, each once, in order.
///
/// The command is split into words the way a shell would, without expanding
/// anything: quotes are taken off, a backslash escapes the next character and
/// the operators `;`, `|`, `&`, `<`, `>`, `(` and `)` separate words. A word
/// with `=` (`NAME=value`, `--file=value`) contributes what follows the first
/// `=`; any other word that starts with `-` is an option and contributes
/// nothing, and so does a URL. A leading `$HOME/` or `${HOME}/` is written as
/// `~/`. Every other word is kept as written, bare names included: whether a
/// token is a path is decided by the daemon, lexically, against `cwd`
/// (decision 39).
pub fn path_tokens(command: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    for word in shell_words(command) {
        let candidate = match word.split_once('=') {
            Some((_, value)) => value.to_string(),
            None if word.starts_with('-') => continue,
            None => word,
        };
        if candidate.is_empty() || candidate.contains("://") {
            continue;
        }
        let candidate = ["$HOME/", "${HOME}/"]
            .iter()
            .find_map(|prefix| candidate.strip_prefix(prefix))
            .map_or(candidate.clone(), |rest| format!("~/{rest}"));
        if !tokens.contains(&candidate) {
            tokens.push(candidate);
        }
    }
    tokens
}

/// Splits a command into words without expanding anything.
fn shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for quoted in chars.by_ref() {
                    if quoted == '\'' {
                        break;
                    }
                    word.push(quoted);
                }
            }
            '"' => {
                in_word = true;
                while let Some(quoted) = chars.next() {
                    match quoted {
                        '"' => break,
                        '\\' => {
                            if let Some(escaped) = chars.next() {
                                word.push(escaped);
                            }
                        }
                        other => word.push(other),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(escaped) = chars.next() {
                    word.push(escaped);
                }
            }
            c if c.is_whitespace() || matches!(c, ';' | '|' | '&' | '<' | '>' | '(' | ')') => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            other => {
                in_word = true;
                word.push(other);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// The fixed sentence of spec section 7.5 for one reason code.
pub fn sentence(agent: Agent, reason: GateReason, count: usize) -> String {
    match reason {
        GateReason::Project => format!(
            "AgentSweep stopped this turn. {count} items in this project need your decision. \
             Open AgentSweep, decide, then try again."
        ),
        GateReason::UserInstructions => format!(
            "AgentSweep stopped this turn. Your {} instructions file was flagged and needs \
             your decision. Open AgentSweep.",
            agent.display_name()
        ),
        GateReason::Item => "AgentSweep blocked this step: the skill, tool or script it uses is \
                             flagged and waits for the user's decision. Do not retry or work \
                             around it. Tell the user to open AgentSweep."
            .to_string(),
    }
}

/// What the Agent reads for one verdict: on `block` the decision it honours
/// for that event, carrying the fixed sentence; on `clear` and `unknown`
/// nothing at all.
pub fn answer(agent: Agent, event: GateEvent, verdict: GateVerdict) -> String {
    let GateVerdict::Block { count, reason } = verdict else {
        return String::new();
    };
    let reason = sentence(agent, reason, count);
    let decision = match event {
        GateEvent::PreToolUse => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }),
        GateEvent::UserPromptSubmit | GateEvent::UserPromptExpansion => json!({
            "decision": "block",
            "reason": reason,
        }),
    };
    format!("{decision}\n")
}

/// The allow-with-message answer when nothing could be checked.
pub fn fail_open() -> String {
    format!("{}\n", json!({ "systemMessage": FAIL_OPEN }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &[&str]) -> Vec<String> {
        line.iter().map(|word| word.to_string()).collect()
    }

    #[test]
    fn the_command_line_names_the_agent_and_optionally_a_socket() {
        assert_eq!(
            parse(&words(&["--agent", "codex", "--socket", "/tmp/a.sock"])),
            Ok(Invocation {
                agent: Agent::Codex,
                socket: Some(PathBuf::from("/tmp/a.sock")),
            })
        );
        assert_eq!(
            parse(&words(&["--agent", "claude-code"])).map(|one| one.agent),
            Ok(Agent::ClaudeCode)
        );
        assert!(parse(&words(&[])).is_err());
        assert!(parse(&words(&["--agent", "cursor"])).is_err());
        assert!(parse(&words(&["--agent"])).is_err());
        assert!(parse(&words(&["--agent", "codex", "extra"])).is_err());
    }

    /// Codex `$name` mentions: every one in a prompt with several, each once,
    /// and none in a prompt without.
    #[test]
    fn every_dollar_mention_is_found_and_a_prompt_without_has_none() {
        assert_eq!(
            mentions("Use $deploy then $notes:jot, and $lint-all. Again $deploy."),
            vec!["deploy", "notes:jot", "lint-all"]
        );
        assert_eq!(
            mentions("$first at the start\nand ($second) inside"),
            vec!["first", "second"]
        );
        assert!(mentions("Refactor the parser and run the tests.").is_empty());
        assert!(mentions("It costs $20, or 5$ and a lone $ sign, a$b too.").is_empty());
        assert!(mentions("").is_empty());
    }

    /// Path tokens are the words of the command, unquoted, without options
    /// and URLs; bare names stay for the daemon to resolve against `cwd`.
    #[test]
    fn the_path_tokens_of_a_command_are_its_words_without_options_and_urls() {
        assert_eq!(
            path_tokens(
                "cd ~/.claude/skills/setup && bash ./scripts/install.sh --force \
                 'with space/x.sh' | tee ../out.log; curl https://h.example.invalid/x"
            ),
            vec![
                "cd",
                "~/.claude/skills/setup",
                "bash",
                "./scripts/install.sh",
                "with space/x.sh",
                "tee",
                "../out.log",
                "curl"
            ]
        );
        assert_eq!(
            path_tokens("FOO=./a.sh run --config=/etc/x.toml \"$HOME/.codex/x\" ${HOME}/y run"),
            vec!["./a.sh", "run", "/etc/x.toml", "~/.codex/x", "~/y"]
        );
        assert_eq!(
            path_tokens("escaped\\ name.sh>/dev/null"),
            vec!["escaped name.sh", "/dev/null"]
        );
        assert!(path_tokens("").is_empty());
    }

    fn claude(event: Value) -> GateRequest {
        request_of(Agent::ClaudeCode, &event).expect("a request")
    }

    fn codex(event: Value) -> GateRequest {
        request_of(Agent::Codex, &event).expect("a request")
    }

    #[test]
    fn a_claude_code_turn_carries_cwd_and_no_tool() {
        let request = claude(json!({
            "hook_event_name": "UserPromptSubmit",
            "cwd": "/work/one",
            "prompt": "use $deploy please",
        }));
        assert_eq!(request.agent, "claude-code");
        assert_eq!(request.event, GateEvent::UserPromptSubmit);
        assert_eq!(request.cwd, "/work/one");
        assert_eq!(request.tool, None);
    }

    #[test]
    fn a_claude_code_skill_call_carries_the_skill_and_a_server_call_its_source() {
        let skill = claude(json!({
            "hook_event_name": "PreToolUse",
            "cwd": "/work/one",
            "tool_name": "Skill",
            "tool_input": { "skill": "setup", "args": "now" },
        }));
        let tool = skill.tool.expect("a tool");
        assert_eq!(tool.name.as_deref(), Some("Skill"));
        assert_eq!(tool.skill.as_deref(), Some("setup"));
        assert!(tool.paths.is_empty() && tool.mcp_server.is_none());

        let server = claude(json!({
            "hook_event_name": "PreToolUse",
            "cwd": "/work/one",
            "tool_name": "mcp__tracker__list",
            "tool_input": {},
            "mcp_server": { "name": "tracker", "source": "user" },
        }));
        assert_eq!(
            server.tool.expect("a tool").mcp_server,
            Some(McpServerRef {
                name: "tracker".to_string(),
                source: Some("user".to_string()),
            })
        );

        let no_source = claude(json!({
            "hook_event_name": "PreToolUse",
            "cwd": "/work/one",
            "tool_name": "mcp__tracker__list",
            "mcp_server": { "name": "tracker" },
        }));
        assert_eq!(
            no_source.tool.expect("a tool").mcp_server,
            Some(McpServerRef {
                name: "tracker".to_string(),
                source: None,
            })
        );
    }

    #[test]
    fn a_bash_call_carries_its_tokens_and_never_its_command() {
        let command = "bash ~/.claude/skills/setup/scripts/install.sh --quiet";
        let request = claude(json!({
            "hook_event_name": "PreToolUse",
            "cwd": "/work/one",
            "tool_name": "Bash",
            "tool_input": { "command": command, "description": "install" },
        }));
        let tool = request.tool.expect("a tool");
        assert_eq!(
            tool.paths,
            vec!["bash", "~/.claude/skills/setup/scripts/install.sh"]
        );
        assert!(!tool.paths.iter().any(|token| token == command));
    }

    #[test]
    fn a_claude_code_expansion_names_its_command_as_a_skill() {
        let request = claude(json!({
            "hook_event_name": "UserPromptExpansion",
            "cwd": "/work/one",
            "expansion_type": "slash_command",
            "command_name": "notes:jot",
            "command_source": "plugin",
            "command_args": "secret arguments",
            "prompt": "/notes:jot secret arguments",
        }));
        let tool = request.tool.expect("a tool");
        assert_eq!(tool.skill.as_deref(), Some("notes:jot"));
        assert_eq!(tool.name, None);
    }

    #[test]
    fn a_codex_turn_sends_only_the_mentioned_names() {
        let request = codex(json!({
            "hook_event_name": "UserPromptSubmit",
            "cwd": "/work/one",
            "turn_id": "t",
            "prompt": "please run $deploy and then $lint",
        }));
        let tool = request.tool.expect("a tool");
        assert_eq!(tool.skills, vec!["deploy", "lint"]);
        assert_eq!(tool.name, None);

        let plain = codex(json!({
            "hook_event_name": "UserPromptSubmit",
            "cwd": "/work/one",
            "prompt": "nothing mentioned",
        }));
        assert_eq!(plain.tool, None);
    }

    #[test]
    fn a_codex_call_takes_the_server_from_the_tool_name_and_bash_tokens() {
        let server = codex(json!({
            "hook_event_name": "PreToolUse",
            "cwd": "/work/one",
            "tool_name": "mcp__issue_tracker__create",
            "tool_input": { "title": "x" },
        }));
        assert_eq!(
            server.tool.expect("a tool").mcp_server,
            Some(McpServerRef {
                name: "issue_tracker".to_string(),
                source: None,
            })
        );

        let bash = codex(json!({
            "hook_event_name": "PreToolUse",
            "cwd": "/work/one",
            "tool_name": "Bash",
            "tool_input": { "command": ["bash", "-lc", "./bin/run"] },
        }));
        let tool = bash.tool.expect("a tool");
        assert_eq!(tool.paths, vec!["bash", "./bin/run"]);
        assert!(tool.mcp_server.is_none());
    }

    #[test]
    fn an_event_without_cwd_or_one_the_gate_does_not_take_is_no_request() {
        for (agent, event) in [
            (
                Agent::ClaudeCode,
                json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash" }),
            ),
            (
                Agent::ClaudeCode,
                json!({ "hook_event_name": "SessionStart", "cwd": "/w" }),
            ),
            (
                Agent::Codex,
                json!({ "hook_event_name": "UserPromptExpansion", "cwd": "/w" }),
            ),
            (Agent::Codex, json!({ "cwd": "/w" })),
            (Agent::Codex, json!([1, 2])),
        ] {
            assert_eq!(request_of(agent, &event), None, "{event}");
        }
    }

    /// Each reason code yields exactly the section 7.5 sentence, with N
    /// filled in and the Agent's own name in the instruction-file sentence.
    #[test]
    fn each_reason_code_is_the_fixed_sentence() {
        assert_eq!(
            sentence(Agent::ClaudeCode, GateReason::Project, 3),
            "AgentSweep stopped this turn. 3 items in this project need your decision. Open \
             AgentSweep, decide, then try again."
        );
        assert_eq!(
            sentence(Agent::ClaudeCode, GateReason::UserInstructions, 1),
            "AgentSweep stopped this turn. Your Claude Code instructions file was flagged and \
             needs your decision. Open AgentSweep."
        );
        assert_eq!(
            sentence(Agent::Codex, GateReason::UserInstructions, 2),
            "AgentSweep stopped this turn. Your Codex instructions file was flagged and needs \
             your decision. Open AgentSweep."
        );
        for agent in [Agent::ClaudeCode, Agent::Codex] {
            assert_eq!(
                sentence(agent, GateReason::Item, 4),
                "AgentSweep blocked this step: the skill, tool or script it uses is flagged and \
                 waits for the user's decision. Do not retry or work around it. Tell the user \
                 to open AgentSweep."
            );
        }
        assert!(!FAIL_OPEN.contains('\u{2014}'));
    }

    /// A turn is blocked with `decision: "block"`, a call denied through
    /// `hookSpecificOutput`, each carrying the sentence in the field the Agent
    /// reads; `clear` and `unknown` print nothing.
    #[test]
    fn a_block_is_the_decision_the_agent_honours_and_clear_prints_nothing() {
        for agent in [Agent::ClaudeCode, Agent::Codex] {
            for reason in GateReason::ALL {
                let block = GateVerdict::Block { count: 2, reason };
                let expected = sentence(agent, reason, 2);

                let turn: Value =
                    serde_json::from_str(&answer(agent, GateEvent::UserPromptSubmit, block))
                        .expect("JSON");
                assert_eq!(turn, json!({ "decision": "block", "reason": expected }));

                let call: Value =
                    serde_json::from_str(&answer(agent, GateEvent::PreToolUse, block))
                        .expect("JSON");
                assert_eq!(
                    call,
                    json!({ "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": expected,
                    }})
                );
            }
            for event in GateEvent::ALL {
                assert_eq!(answer(agent, event, GateVerdict::Clear), "");
                assert_eq!(answer(agent, event, GateVerdict::Unknown), "");
            }
        }
        let expansion: Value = serde_json::from_str(&answer(
            Agent::ClaudeCode,
            GateEvent::UserPromptExpansion,
            GateVerdict::Block {
                count: 1,
                reason: GateReason::Item,
            },
        ))
        .expect("JSON");
        assert_eq!(expansion["decision"], "block");
    }

    #[test]
    fn the_fail_open_answer_is_one_system_message() {
        let value: Value = serde_json::from_str(&fail_open()).expect("JSON");
        assert_eq!(
            value,
            json!({ "systemMessage": "AgentSweep is not running, nothing was checked." })
        );
        assert_eq!(
            run(Err("bad".to_string()), std::io::empty(), DEADLINE),
            fail_open()
        );
    }
}
