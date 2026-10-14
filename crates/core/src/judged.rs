//! Cached Verdicts applied inside a Scan (spec sections 4.4 and 6.4).
//!
//! An Item that awaits judgement, Ambiguous with no other Finding, is looked
//! up in the Verdict cache under the active Judgement Engine before anything
//! is asked. A hit is applied at once, without the engine:
//!
//! - malicious opens one T3 Threat Finding with source `score`, the fired
//!   Heuristics beneath it as its evidence, manual Quarantine only, and the
//!   engine, the model and the contained reason beside it;
//! - benign moves the Item to Clear, with a "checked by <engine>" note that
//!   only the Developer Posture shows;
//! - unsure leaves it Ambiguous.
//!
//! A miss changes nothing here; it is what the AI Judgement queue is fed
//! with. The cache key is the hash of the redacted Judgement Request together
//! with the engine, the model and the prompt version, so a change to the
//! content, to a fired Heuristic or to a fact misses, and so does another
//! engine. Severity is the highest of the fired Heuristics, never the
//! engine's. Nothing here sends anything and nothing here writes the cache.

use std::fmt;

use crate::finding::{Category, Finding, FiredHeuristic, RuleStatus, Severity, Source, Tier};
use crate::heuristics::{Assessment, Band};
use crate::item::{Item, ItemId};
use crate::judgement::{Verdict, judgement_severity};
use crate::judgement_request::{
    ByteEstimate, JudgementRequest, NoRequest, Normalisation, RequestBuilder,
};
use crate::settings::{JudgementEngine, JudgementSettings};
use crate::verdicts::{InstalledModel, VerdictCacheView};

/// The developer-facing one line of a Finding a malicious Verdict opened.
pub const JUDGEMENT_TITLE: &str = "AI Judgement found the Item malicious";

/// The one sentence the Simple Posture shows above the fired Heuristics'
/// `plain` lines. The AI check advises; it never decides by itself.
pub const JUDGEMENT_PLAIN: &str = "The AI check looked at the signs below and believes this item was \
     written to cause harm. It only advises: what happens next is your decision.";

/// The token budget a Judgement Request is built under for Apple on-device:
/// its 4,096-token context (spec section 4.4).
pub const APPLE_BUDGET: usize = 4_096;

/// The budget for Ollama: the 8,192 `num_ctx` stated with every request.
pub const OLLAMA_BUDGET: usize = 8_192;

/// The budget for the Claude API: about 32K tokens.
pub const CLAUDE_BUDGET: usize = 32_000;

/// The active Judgement Engine as a Scan names it: which engine, which model
/// it reports, and the budget its Judgement Requests are built under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Judge {
    /// The engine, as the settings file spells it.
    pub engine: String,
    /// The model id the engine reports, empty where it reports none.
    pub model: String,
    /// The token budget a request has to fit.
    pub budget: usize,
    normalisation: Normalisation,
}

impl Judge {
    /// One engine and model, under one budget, normalising one home.
    pub fn new(engine: &str, model: &str, budget: usize, normalisation: Normalisation) -> Judge {
        Judge {
            engine: engine.to_string(),
            model: model.to_string(),
            budget,
            normalisation,
        }
    }

    /// The active engine the settings name, or none while AI Judgement is
    /// off. The model is the one the settings name for it; an engine that
    /// reports a finer id (an Ollama digest, the OS model version) hands that
    /// over through [`Judge::new`] instead.
    pub fn of_settings(
        settings: &JudgementSettings,
        normalisation: Normalisation,
    ) -> Option<Judge> {
        let budget = budget_of(settings.engine)?;
        Some(Judge::new(
            settings.engine.as_str(),
            settings.model_of(settings.engine),
            budget,
            normalisation,
        ))
    }

    /// What the evaluation cache key and the Scan summary name: the engine
    /// and the model.
    pub fn label(&self) -> String {
        match self.model.is_empty() {
            true => self.engine.clone(),
            false => format!("{} {}", self.engine, self.model),
        }
    }

    /// The Judgement Request for one Item and the Heuristics that fired on
    /// it, built under this engine's budget.
    pub fn request(
        &self,
        item: &Item,
        fired: &[FiredHeuristic],
    ) -> Result<JudgementRequest, NoRequest> {
        RequestBuilder::new(self.normalisation.clone(), self.budget, &ByteEstimate)
            .build(item, fired)
    }
}

/// The budget of an engine, none for off.
fn budget_of(engine: JudgementEngine) -> Option<usize> {
    match engine {
        JudgementEngine::Off => None,
        JudgementEngine::Apple => Some(APPLE_BUDGET),
        JudgementEngine::Ollama => Some(OLLAMA_BUDGET),
        JudgementEngine::Claude => Some(CLAUDE_BUDGET),
    }
}

/// Every engine and model the settings name as installed, which is what a
/// cached Verdict has to name to survive a compaction: Apple on-device, the
/// Ollama model once one is named, and the Claude model in use.
pub fn installed_models(settings: &JudgementSettings) -> Vec<InstalledModel> {
    let mut installed = vec![InstalledModel::new(
        JudgementEngine::Apple.as_str(),
        settings.model_of(JudgementEngine::Apple),
    )];
    if !settings.ollama_model.is_empty() {
        installed.push(InstalledModel::new(
            JudgementEngine::Ollama.as_str(),
            &settings.ollama_model,
        ));
    }
    installed.push(InstalledModel::new(
        JudgementEngine::Claude.as_str(),
        settings.claude_model_in_use(),
    ));
    installed
}

/// One cached Verdict a Scan applied to one Item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedVerdict {
    /// The Item it was applied to.
    pub item_id: ItemId,
    /// The engine that gave it.
    pub engine: String,
    /// The model that engine ran.
    pub model: String,
    /// The Verdict.
    pub verdict: Verdict,
}

impl AppliedVerdict {
    /// The contained reason of a malicious Verdict, empty for any other.
    pub fn reason(&self) -> &str {
        match &self.verdict {
            Verdict::Malicious { reason, .. } => reason,
            _ => "",
        }
    }
}

/// Where a Scan looks for a Verdict on an Item that awaits judgement.
///
/// A trait, as the evaluation cache is, because a Folder Scan and the
/// in-process command line interface have no Verdict cache and say so by
/// handing over [`NoVerdicts`].
pub trait Verdicts: Sync {
    /// The Verdict cached for this Item and these fired Heuristics under the
    /// active engine, if there is one.
    fn cached(&self, item: &Item, fired: &[FiredHeuristic]) -> Option<AppliedVerdict>;
}

/// No Verdict cache at all: every Item that awaits judgement stays Ambiguous.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoVerdicts;

impl Verdicts for NoVerdicts {
    fn cached(&self, _item: &Item, _fired: &[FiredHeuristic]) -> Option<AppliedVerdict> {
        None
    }
}

/// The Verdict cache as one read left it, looked up under one engine.
pub struct CachedVerdicts<'a> {
    view: &'a VerdictCacheView,
    judge: &'a Judge,
}

impl fmt::Debug for CachedVerdicts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedVerdicts")
            .field("held", &self.view.len())
            .field("judge", &self.judge.label())
            .finish()
    }
}

impl<'a> CachedVerdicts<'a> {
    /// Looks up in this view under this engine.
    pub fn new(view: &'a VerdictCacheView, judge: &'a Judge) -> CachedVerdicts<'a> {
        CachedVerdicts { view, judge }
    }
}

impl Verdicts for CachedVerdicts<'_> {
    fn cached(&self, item: &Item, fired: &[FiredHeuristic]) -> Option<AppliedVerdict> {
        // A request that cannot be built is no Verdict, and so is a miss.
        let request = self.judge.request(item, fired).ok()?;
        let verdict = self
            .view
            .lookup(request.hash(), &self.judge.engine, &self.judge.model)?;
        Some(AppliedVerdict {
            item_id: item.id.clone(),
            engine: self.judge.engine.clone(),
            model: self.judge.model.clone(),
            verdict,
        })
    }
}

/// Applies one Verdict to the Assessment of the Item it is about: malicious
/// opens the T3 Finding and puts the Item in the Suspicious Band, benign puts
/// it in the Clear Band, unsure leaves it where it is.
pub fn apply(item: &Item, assessment: &mut Assessment, applied: &AppliedVerdict) {
    match applied.verdict {
        Verdict::Malicious { .. } => {
            assessment
                .findings
                .push(judgement_finding(item, assessment.score, &assessment.fired));
            assessment.band = Band::Suspicious;
        }
        Verdict::Benign => assessment.band = Band::Clear,
        Verdict::Unsure => {}
    }
}

/// The one Threat Finding a malicious Verdict opens: about the Item, with
/// the fired Heuristics as its evidence and their highest Severity as its
/// own. Its source is `score`, as every Finding a Score stands behind.
pub fn judgement_finding(item: &Item, score: i64, fired: &[FiredHeuristic]) -> Finding {
    Finding {
        item_id: item.id.clone(),
        source: Source::Score(score),
        content_hash: item.content_hash.clone(),
        category: Category::Threat,
        severity: judgement_severity(fired).unwrap_or(Severity::Low),
        tier: Tier::AiJudgement,
        status: RuleStatus::Stable,
        title: JUDGEMENT_TITLE.to_string(),
        plain: JUDGEMENT_PLAIN.to_string(),
        sensitive: fired.iter().any(|heuristic| heuristic.sensitive),
        file: String::new(),
        matches: Vec::new(),
        heuristics: fired.to_vec(),
        drift: None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::item::{Activation, Kind, Provenance, Scope};

    fn skill(content: &str) -> Item {
        Item::file(
            "claude-code",
            Scope::User,
            Kind::Skill,
            "skills/helper/SKILL.md",
            PathBuf::from("/nowhere/skills/helper/SKILL.md"),
            Provenance::Manual,
            Activation::Active,
            content.as_bytes().to_vec(),
        )
    }

    fn fired(id: i64, severity: Severity) -> FiredHeuristic {
        FiredHeuristic {
            id,
            weight: 1,
            title: format!("Heuristic {id}"),
            plain: format!("Heuristic {id} fired."),
            severity,
            sensitive: false,
            reviewer_directed: false,
            file: String::new(),
            matches: Vec::new(),
        }
    }

    fn ambiguous(item: &Item) -> Assessment {
        Assessment {
            item_id: item.id.clone(),
            score: 3,
            band: Band::Ambiguous,
            fired: vec![fired(520, Severity::Medium), fired(522, Severity::High)],
            findings: Vec::new(),
        }
    }

    fn applied(item: &Item, verdict: Verdict) -> AppliedVerdict {
        AppliedVerdict {
            item_id: item.id.clone(),
            engine: "ollama".to_string(),
            model: "a-model".to_string(),
            verdict,
        }
    }

    #[test]
    fn a_malicious_verdict_opens_one_t3_score_finding_with_the_heuristics_beneath() {
        let item = skill("text");
        let mut assessment = ambiguous(&item);
        let verdict = Verdict::Malicious {
            category: crate::judgement::Category::MaliciousInstalledContent,
            reason: "It hides an instruction.".to_string(),
            evidence: vec!["text".to_string()],
        };
        apply(&item, &mut assessment, &applied(&item, verdict));
        assert_eq!(assessment.band, Band::Suspicious);
        assert_eq!(assessment.findings.len(), 1);
        let finding = &assessment.findings[0];
        assert_eq!(finding.source, Source::Score(3));
        assert_eq!(finding.tier, Tier::AiJudgement);
        assert_eq!(finding.category, Category::Threat);
        assert_eq!(finding.severity, Severity::High, "the Heuristics' highest");
        let ids: Vec<i64> = finding.heuristics.iter().map(|h| h.id).collect();
        assert_eq!(ids, vec![520, 522]);
    }

    #[test]
    fn benign_clears_and_unsure_leaves_the_item_ambiguous() {
        let item = skill("text");
        let mut cleared = ambiguous(&item);
        apply(&item, &mut cleared, &applied(&item, Verdict::Benign));
        assert_eq!(cleared.band, Band::Clear);
        assert!(cleared.findings.is_empty());

        let mut unsure = ambiguous(&item);
        apply(&item, &mut unsure, &applied(&item, Verdict::Unsure));
        assert!(unsure.awaits_judgement());
    }

    #[test]
    fn off_is_no_judge_and_every_engine_names_its_model() {
        let mut settings = JudgementSettings::default();
        assert_eq!(
            Judge::of_settings(&settings, Normalisation::default()),
            None
        );
        settings.engine = JudgementEngine::Ollama;
        settings.ollama_model = "qwen3:8b".to_string();
        let ollama = Judge::of_settings(&settings, Normalisation::default()).expect("a judge");
        assert_eq!(ollama.budget, OLLAMA_BUDGET);
        assert_eq!(ollama.label(), "ollama qwen3:8b");
        settings.engine = JudgementEngine::Apple;
        let apple = Judge::of_settings(&settings, Normalisation::default()).expect("a judge");
        assert_eq!(apple.label(), "apple");
    }

    #[test]
    fn the_installed_models_are_the_ones_the_settings_name() {
        let mut settings = JudgementSettings::default();
        let names = |settings: &JudgementSettings| -> Vec<(String, String)> {
            installed_models(settings)
                .into_iter()
                .map(|model| (model.engine, model.model))
                .collect()
        };
        assert!(
            !names(&settings)
                .iter()
                .any(|(engine, _)| engine == "ollama"),
            "no Ollama model named, none installed"
        );
        settings.ollama_model = "qwen3:8b".to_string();
        assert!(names(&settings).contains(&("ollama".to_string(), "qwen3:8b".to_string())));
    }
}
