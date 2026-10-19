//! AI Judgement for `agentsweep scan <dir>` (spec section 4.4, "Caps, cache,
//! CLI").
//!
//! After the Tiers, the Folder Scan asks the Judgement Engine the settings
//! file names about each Item it left in the Ambiguous Band, and waits for
//! the Verdicts, since nothing is left behind to receive a late one. There is
//! no consent of its own: the engine was chosen in AgentSweep. `--no-ai` asks
//! nothing.
//!
//! The settings file is read, never written: it is plain JSON and holds no
//! secret. Each answer passes the deterministic checks of the core, the same
//! as the daemon's: the quote check, the reviewer-directed rule and reason
//! containment. At most [`LOCAL_ITEMS_PER_SCAN`] Items are asked of a local
//! engine and the setting's per-Scan cap of the Claude engine; the rest get
//! no Verdict, and the fixed cap line says how many. A malicious Verdict
//! opens the T3 Finding, so the answer turns to "do not open yet"; benign
//! and unsure carry fixed wording, and the engine and its model are named
//! beside every Verdict.
//!
//! Which engines this build can ask:
//!
//! - the in-bundle build asks Ollama and Apple on-device in this process (the
//!   Apple helper sits beside it in the bundle), and hands its requests for
//!   the Claude engine to the daemon, which holds the key and the Claude
//!   client; that is the one reason `scan <dir>` reaches the daemon;
//! - the crates.io build asks only Ollama, and only when the settings file
//!   names its address and model; it never guesses a model.
//!
//! Otherwise the AI check did not run, and one line says so. There is no
//! Verdict cache in this process: the daemon looks its own up for the cloud
//! requests it answers. Nothing here writes anything.

use std::path::Path;

use agentsweep_core::adapter::Enumeration;
#[cfg(feature = "bundle")]
use agentsweep_core::apple_engine::{AppleEngine, AppleHelper};
use agentsweep_core::finding::FiredHeuristic;
use agentsweep_core::item::ItemId;
use agentsweep_core::judged::{self, AppliedVerdict, Judge};
use agentsweep_core::judgement::{self, EngineError, JudgementEngine, Verdict};
use agentsweep_core::judgement_request::{JudgementRequest, Normalisation};
use agentsweep_core::ollama::{OllamaClient, OllamaEngine};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::scan::ScanReport;
use agentsweep_core::settings::{JudgementEngine as EngineChoice, JudgementSettings, SettingsFile};
use agentsweep_core::spend::CapNotice;

/// The most Items one Folder Scan asks a local engine about, the same cap
/// the daemon's queue applies (spec section 4.4).
pub const LOCAL_ITEMS_PER_SCAN: usize = 25;

/// The one line printed when the Folder Scan left Items in the Ambiguous
/// Band and no engine this build can ask is chosen.
pub const DID_NOT_RUN: &str =
    "The AI check did not run: AgentSweep's settings choose no AI engine this build can ask.";

/// What a benign Verdict says.
pub const BENIGN: &str = "nothing in it looks written to cause harm.";

/// What an unsure Verdict says.
pub const UNSURE: &str = "it could not tell whether this was written to cause harm.";

/// What no Verdict says.
pub const NO_VERDICT: &str = "no answer; the Item stays in the Ambiguous Band.";

/// What a malicious Verdict says beside the Finding it opened.
pub const MALICIOUS: &str = "written to cause harm, see the Finding above.";

/// What one ask came to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Asked {
    /// A Verdict that passed every check, and the engine and model behind it
    /// as a person reads them.
    Verdict(Verdict, String),
    /// No Verdict, from the engine as a person reads it.
    NoVerdict(String),
    /// A cloud cap held the request back: nothing more is asked. Only the
    /// daemon answers so, for the Claude engine.
    #[cfg_attr(not(feature = "bundle"), allow(dead_code))]
    Capped,
}

/// One Judgement Engine as the Folder Scan asks it.
pub trait Asker {
    /// The engine and its model as a person reads them.
    fn label(&self) -> String;

    /// Asks about one Item, waiting for the answer.
    fn ask(&mut self, request: &JudgementRequest, fired: &[FiredHeuristic]) -> Asked;
}

/// What came of one Item that was asked about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Judged {
    /// The Item.
    pub item_id: ItemId,
    /// The Verdict, absent for none.
    pub verdict: Option<Verdict>,
    /// The engine and model as a person reads them.
    pub label: String,
}

/// What the AI check came to for one Folder Scan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Judgement {
    /// Nothing was asked and nothing is printed: `--no-ai`, or no Item
    /// awaited judgement.
    #[default]
    NotAsked,
    /// No engine this build can ask is chosen: one line says so.
    DidNotRun,
    /// The engine was asked.
    Ran {
        /// Each Item asked about, in the order they were asked.
        judged: Vec<Judged>,
        /// How many Items a cap held back.
        held_back: usize,
    },
}

impl Judgement {
    /// The Verdict line of one Item, when it was asked about.
    pub fn of(&self, item: &ItemId) -> Option<&Judged> {
        match self {
            Judgement::Ran { judged, .. } => judged.iter().find(|judged| &judged.item_id == item),
            _ => None,
        }
    }

    /// The fixed cap line, when a cap held Items back.
    pub fn cap_line(&self) -> Option<String> {
        match self {
            Judgement::Ran { held_back, .. } if *held_back > 0 => Some(
                CapNotice {
                    cap: agentsweep_core::spend::JudgementCap::Scan,
                    waiting: *held_back,
                }
                .line(),
            ),
            _ => None,
        }
    }
}

/// The engine and model as a person reads them.
pub fn label(engine: &str, model: &str) -> String {
    let name = match engine {
        "apple" => "Apple on-device",
        "ollama" => "Ollama",
        "claude" => "Claude",
        other => other,
    };
    match model.is_empty() {
        true => name.to_string(),
        false => format!("{name} {model}"),
    }
}

/// Asks `asker` about every Item the Folder Scan left awaiting judgement, at
/// most `cap` of them in Item id order (no Baseline tells which changed
/// last), and applies each Verdict to the report: malicious opens the T3
/// Finding, benign moves the Item to Clear, unsure leaves it Ambiguous.
pub fn judge_the_folder(
    enumeration: &Enumeration,
    report: &mut ScanReport,
    judge: &Judge,
    asker: &mut dyn Asker,
    cap: usize,
) -> Judgement {
    let mut awaiting: Vec<usize> = report
        .assessments
        .iter()
        .enumerate()
        .filter(|(_, assessment)| assessment.awaits_judgement())
        .map(|(index, _)| index)
        .collect();
    if awaiting.is_empty() {
        return Judgement::NotAsked;
    }
    awaiting.sort_by(|a, b| {
        report.assessments[*a]
            .item_id
            .as_str()
            .cmp(report.assessments[*b].item_id.as_str())
    });

    let mut judged = Vec::new();
    let mut held_back = awaiting.len().saturating_sub(cap);
    for (asked, index) in awaiting.iter().take(cap).enumerate() {
        let assessment = &report.assessments[*index];
        let item_id = assessment.item_id.clone();
        let Some(item) = enumeration.items.iter().find(|item| item.id == item_id) else {
            continue;
        };
        let answer = match judge.request(item, &assessment.fired) {
            Ok(request) => asker.ask(&request, &assessment.fired),
            Err(_) => Asked::NoVerdict(asker.label()),
        };
        let (verdict, label) = match answer {
            Asked::Verdict(verdict, label) => (Some(verdict), label),
            Asked::NoVerdict(label) => (None, label),
            Asked::Capped => {
                held_back += cap.min(awaiting.len()) - asked;
                break;
            }
        };
        if let Some(verdict) = &verdict {
            let assessment = &mut report.assessments[*index];
            let opened = assessment.findings.len();
            judged::apply(
                item,
                assessment,
                &AppliedVerdict {
                    item_id: item_id.clone(),
                    engine: label.clone(),
                    model: String::new(),
                    verdict: verdict.clone(),
                },
            );
            report
                .findings
                .extend(assessment.findings[opened..].iter().cloned());
        }
        judged.push(Judged {
            item_id,
            verdict,
            label,
        });
    }
    Judgement::Ran { judged, held_back }
}

/// One local Judgement Engine, asked in this process, or the engine error
/// that kept it from opening, which is no Verdict for every Item.
pub struct Local {
    engine: Result<Box<dyn JudgementEngine>, EngineError>,
    label: String,
}

impl Local {
    /// The engine, named for the output.
    pub fn new(engine: Result<Box<dyn JudgementEngine>, EngineError>, label: String) -> Local {
        Local { engine, label }
    }
}

impl Asker for Local {
    fn label(&self) -> String {
        self.label.clone()
    }

    fn ask(&mut self, request: &JudgementRequest, fired: &[FiredHeuristic]) -> Asked {
        let Ok(engine) = &self.engine else {
            return Asked::NoVerdict(self.label.clone());
        };
        match judgement::judge(engine.as_ref(), request, fired) {
            Ok(verdict) => Asked::Verdict(verdict, self.label.clone()),
            Err(_) => Asked::NoVerdict(self.label.clone()),
        }
    }
}

/// The engine the settings choose, as this Folder Scan asks it.
pub struct Chosen {
    /// The engine and the budget its requests are built under.
    pub judge: Judge,
    /// Who to ask.
    pub asker: Box<dyn Asker>,
    /// How many Items one Folder Scan asks about.
    pub cap: usize,
}

/// The AI Judgement choices of the settings file in the user's data
/// directory, read and never written. A missing or unreadable file chooses
/// nothing.
pub fn read_the_settings() -> Option<JudgementSettings> {
    let directory = DataDirectory::for_user()?;
    SettingsFile::in_data_directory(&directory)
        .read()
        .ok()
        .map(|settings| settings.judgement)
}

/// The engine this build can ask among the ones the settings choose, or
/// None when there is none. `socket` is where the in-bundle build reaches the
/// daemon for the Claude engine.
#[cfg_attr(not(feature = "bundle"), allow(unused_variables))]
pub fn choose(
    settings: &JudgementSettings,
    normalisation: Normalisation,
    socket: Option<&Path>,
) -> Option<Chosen> {
    let judge = Judge::of_settings(settings, normalisation)?;
    let local = |asker: Local| Chosen {
        judge: judge.clone(),
        asker: Box::new(asker),
        cap: LOCAL_ITEMS_PER_SCAN,
    };
    match settings.engine {
        EngineChoice::Ollama if !settings.ollama_model.is_empty() => {
            let client = OllamaClient::new(&settings.ollama_address);
            let engine = OllamaEngine::for_model(client, &settings.ollama_model)
                .map(|engine| Box::new(engine) as Box<dyn JudgementEngine>);
            Some(local(Local::new(
                engine,
                label(EngineChoice::Ollama.as_str(), &settings.ollama_model),
            )))
        }
        #[cfg(feature = "bundle")]
        EngineChoice::Apple => {
            let engine = AppleHelper::beside_this_executable()
                .ok_or_else(|| EngineError::Unavailable("helper_missing".into()))
                .and_then(AppleEngine::new)
                .map(|engine| Box::new(engine) as Box<dyn JudgementEngine>);
            Some(local(Local::new(
                engine,
                label(EngineChoice::Apple.as_str(), ""),
            )))
        }
        #[cfg(feature = "bundle")]
        EngineChoice::Claude => Some(Chosen {
            judge: judge.clone(),
            asker: Box::new(daemon::ThroughTheDaemon::at(
                socket,
                label(
                    EngineChoice::Claude.as_str(),
                    settings.claude_model_in_use(),
                ),
            )),
            cap: settings.caps.items_per_scan as usize,
        }),
        _ => None,
    }
}

/// The Claude engine, through the daemon: the in-bundle build only.
#[cfg(feature = "bundle")]
mod daemon {
    use std::path::Path;

    use agentsweep_core::finding::FiredHeuristic;
    use agentsweep_core::judgement_request::JudgementRequest;
    use agentsweep_ipc::judge::{JudgeOutcome, JudgeRequest};
    use agentsweep_ipc::protocol::Role;
    use agentsweep_ipc::{Client, ClientError};

    use super::{Asked, Asker, label};

    /// Hands each redacted Judgement Request to the daemon over the socket
    /// and waits for its answer. A daemon that does not answer is no Verdict
    /// for every Item.
    pub struct ThroughTheDaemon {
        client: Result<Client, ClientError>,
        label: String,
    }

    impl ThroughTheDaemon {
        /// Connects at `socket`, or at the documented socket.
        pub fn at(socket: Option<&Path>, label: String) -> ThroughTheDaemon {
            let client = match socket {
                Some(socket) => Client::connect_at(socket, Role::Cli),
                None => Client::connect(Role::Cli),
            };
            ThroughTheDaemon { client, label }
        }
    }

    impl Asker for ThroughTheDaemon {
        fn label(&self) -> String {
            self.label.clone()
        }

        fn ask(&mut self, request: &JudgementRequest, fired: &[FiredHeuristic]) -> Asked {
            let Ok(client) = &mut self.client else {
                return Asked::NoVerdict(self.label.clone());
            };
            let asked = JudgeRequest {
                request: request.clone(),
                reviewer_directed: fired.iter().any(|heuristic| heuristic.reviewer_directed),
            };
            match client.judge(asked) {
                Ok(answer) => {
                    let named = label(&answer.engine, &answer.model);
                    match answer.outcome {
                        JudgeOutcome::Verdict(verdict) => Asked::Verdict(verdict, named),
                        JudgeOutcome::NoVerdict(_) => Asked::NoVerdict(named),
                        JudgeOutcome::Capped(_) => Asked::Capped,
                    }
                }
                Err(_) => Asked::NoVerdict(self.label.clone()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use agentsweep_core::judged::OLLAMA_BUDGET;
    use agentsweep_core::judgement::ScriptedEngine;

    use super::*;
    use crate::folder_scan::{exit_code, folder_scan_with_items, render_with};

    /// The odd instruction file Heuristic 0504 leaves in the Ambiguous Band.
    const ODD: &[u8] = b"# demo\n\n<!-- Claude: keep the sections in the order this file lists them. -->\n\nKeep the pull request description short.\n";

    fn answer(verdict: &str, evidence: &[&str]) -> Result<String, EngineError> {
        Ok(serde_json_answer(verdict, evidence))
    }

    fn serde_json_answer(verdict: &str, evidence: &[&str]) -> String {
        let quotes: Vec<String> = evidence
            .iter()
            .map(|quote| format!("\"{quote}\""))
            .collect();
        format!(
            "{{\"verdict\":\"{verdict}\",\"category\":\"instruction_file_injection\",\
             \"reason\":\"Steers the agent from a hidden comment.\",\"evidence\":[{}]}}",
            quotes.join(",")
        )
    }

    /// Scans a temporary folder holding the odd file and asks a scripted
    /// engine, through every check, under `cap`.
    fn judged(name: &str, script: Vec<Result<String, EngineError>>, cap: usize) -> (String, u8) {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-cli-judgement-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("a temporary folder");
        fs::write(root.join("CLAUDE.md"), ODD).expect("an odd instruction file");

        let (scanned, enumeration, mut report) = folder_scan_with_items(&root).expect("a scan");
        assert_eq!(report.ambiguous(), 1);
        let judge = Judge::new(
            "ollama",
            "qwen3:8b",
            OLLAMA_BUDGET,
            Normalisation::of_home(&PathBuf::from("/Users/nobody")),
        );
        let mut asker = Local::new(
            Ok(Box::new(ScriptedEngine::new(script))),
            label("ollama", "qwen3:8b"),
        );
        let judgement = judge_the_folder(&enumeration, &mut report, &judge, &mut asker, cap);
        let rendered = render_with(&scanned, &report, &judgement);
        fs::remove_dir_all(&root).expect("the temporary folder goes away");
        (rendered, exit_code(&report))
    }

    #[test]
    fn a_malicious_verdict_with_a_verifiable_quote_turns_the_answer() {
        let (rendered, code) = judged(
            "malicious",
            vec![answer("malicious", &["keep the sections in the order"])],
            LOCAL_ITEMS_PER_SCAN,
        );
        assert!(rendered.contains("Do not open yet."), "{rendered}");
        assert!(rendered.contains("T3"), "{rendered}");
        assert!(
            rendered.contains(
                "AI explanation, from Ollama qwen3:8b: Steers the agent from a hidden comment."
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("malicious, from Ollama qwen3:8b: {MALICIOUS}")),
            "{rendered}"
        );
        assert_eq!(code, 1);
    }

    #[test]
    fn a_malicious_verdict_without_a_verifiable_quote_does_not() {
        let (rendered, code) = judged(
            "unquoted",
            vec![answer("malicious", &["not in the file"])],
            LOCAL_ITEMS_PER_SCAN,
        );
        assert!(rendered.contains("Safe to open."), "{rendered}");
        assert!(
            rendered.contains(&format!("no Verdict, from Ollama qwen3:8b: {NO_VERDICT}")),
            "{rendered}"
        );
        assert!(!rendered.contains("AI explanation"), "{rendered}");
        assert_eq!(code, 0);
    }

    /// An asker that answers the same for every Item, past the checks, so a
    /// benign Verdict can be shown on an Item where a reviewer-directed
    /// Heuristic fired.
    struct Answers(Asked);

    impl Asker for Answers {
        fn label(&self) -> String {
            label("claude", "claude-sonnet-5")
        }

        fn ask(&mut self, _request: &JudgementRequest, _fired: &[FiredHeuristic]) -> Asked {
            self.0.clone()
        }
    }

    #[test]
    fn benign_and_unsure_carry_fixed_wording_and_never_the_reason() {
        // 0504 is reviewer directed, so a benign answer is recorded as unsure.
        let (lured, _) = judged("lured", vec![answer("benign", &[])], 25);
        assert!(
            lured.contains(&format!("unsure, from Ollama qwen3:8b: {UNSURE}")),
            "{lured}"
        );

        let root = std::env::temp_dir().join(format!(
            "agentsweep-cli-judgement-benign-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("a temporary folder");
        fs::write(root.join("CLAUDE.md"), ODD).expect("an odd instruction file");
        let (scanned, enumeration, mut report) = folder_scan_with_items(&root).expect("a scan");
        let judge = Judge::new(
            "claude",
            "claude-sonnet-5",
            32_000,
            Normalisation::default(),
        );
        let mut asker = Answers(Asked::Verdict(
            Verdict::Benign,
            label("claude", "claude-sonnet-5"),
        ));
        let judgement = judge_the_folder(&enumeration, &mut report, &judge, &mut asker, 25);
        let benign = render_with(&scanned, &report, &judgement);
        fs::remove_dir_all(&root).expect("the temporary folder goes away");
        assert!(
            benign.contains(&format!("benign, from Claude claude-sonnet-5: {BENIGN}")),
            "{benign}"
        );
        assert!(
            !benign.contains("Ambiguous Band, nothing to do"),
            "{benign}"
        );
        assert!(benign.contains("Safe to open."), "{benign}");

        let (unsure, _) = judged("unsure", vec![answer("unsure", &[])], 25);
        assert!(
            unsure.contains(&format!("unsure, from Ollama qwen3:8b: {UNSURE}")),
            "{unsure}"
        );
        assert!(!unsure.contains("hidden comment"), "{unsure}");
        assert!(unsure.contains("Ambiguous Band, nothing to do"), "{unsure}");
    }

    #[test]
    fn items_past_the_cap_get_no_verdict_and_the_cap_line() {
        let (rendered, code) = judged("cap", vec![answer("malicious", &["keep"])], 0);
        assert!(
            rendered.contains("The AI check, no Items asked:"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "The AI check reached its limit for this scan. 1 item will be looked at next time."
            ),
            "{rendered}"
        );
        assert_eq!(code, 0);
    }

    /// Without the bundle only Ollama is asked, and only when the settings
    /// name a model: it never guesses one.
    #[test]
    fn only_a_named_ollama_model_is_asked_without_the_bundle() {
        let none = |settings: &JudgementSettings| {
            choose(settings, Normalisation::default(), None).is_none()
        };
        let mut settings = JudgementSettings::default();
        assert!(none(&settings), "off asks nothing");
        settings.engine = EngineChoice::Ollama;
        assert!(none(&settings), "no model, nothing guessed");
        #[cfg(not(feature = "bundle"))]
        for engine in [EngineChoice::Apple, EngineChoice::Claude] {
            settings.engine = engine;
            assert!(none(&settings), "{engine}");
        }
    }
}
