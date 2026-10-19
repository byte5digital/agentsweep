//! The Claude engine's answers for `agentsweep scan <dir>` (spec section 4.4).
//!
//! The in-bundle command line interface runs its Folder Scan in its own
//! process and asks a local Judgement Engine itself, but it never holds the
//! Claude key and never links the Claude client: it hands each redacted
//! Judgement Request to the daemon over the `judge` request and waits. The
//! daemon answers it the way its own AI Judgement queue answers a request:
//!
//! - only while the Claude engine is the active Judgement Engine;
//! - from the Verdict cache first, under the engine, the model and the
//!   prompt version (the owner's decision of 2026-10-14: the cache is used
//!   for the cloud requests the daemon answers, never in the command line
//!   process);
//! - under the cloud caps: a request that would start past the day's Items
//!   or the month's money is not sent and is answered with the cap;
//! - through every deterministic check, the reviewer-directed rule read from
//!   the mark the request carries;
//! - with its spend recorded beside the events in the Event Log and its
//!   Verdict cached; no Verdict is never cached.
//!
//! Nothing else is recorded: a Folder Scan opens no Finding.

use agentsweep_core::envelope::Timestamp;
use agentsweep_core::judgement::{self, Verdict};
use agentsweep_core::judgement_request::JudgementRequest;
use agentsweep_core::settings::JudgementEngine as EngineChoice;
use agentsweep_core::verdicts::{CachedVerdict, VerdictCache, VerdictCacheWriter};
use agentsweep_ipc::judge::{JudgeAnswer, JudgeOutcome, JudgeRequest};

use crate::full_scan::read_the_verdicts;
use crate::service::Daemon;

impl Daemon {
    /// Answers one `judge` request of the in-bundle command line interface.
    pub fn judge_for_the_command_line(&self, asked: &JudgeRequest) -> JudgeAnswer {
        let judgement = self.judgement();
        let no = |engine: &str, model: &str, why: &str| JudgeAnswer {
            engine: engine.to_string(),
            model: model.to_string(),
            outcome: JudgeOutcome::NoVerdict(why.to_string()),
        };
        if judgement.engine != EngineChoice::Claude {
            return no(
                judgement.engine.as_str(),
                "",
                "the Claude engine is not the active Judgement Engine",
            );
        }
        let Some(in_force) = self.engine_in_force() else {
            return no(EngineChoice::Claude.as_str(), "", "the engine is not open");
        };
        let engine = in_force.judge.engine.clone();
        let model = in_force.judge.model.clone();
        let answer = |outcome| JudgeAnswer {
            engine: engine.clone(),
            model: model.clone(),
            outcome,
        };
        let request = &asked.request;

        if let Some(verdict) =
            read_the_verdicts(&self.directory, &*self.keys).lookup(request.hash(), &engine, &model)
        {
            return answer(JudgeOutcome::Verdict(verdict));
        }
        let Some(asking) = in_force.asking else {
            return answer(JudgeOutcome::NoVerdict(
                "this daemon asks no engine".to_string(),
            ));
        };
        if let Err(cap) = self.admit_a_cloud_request() {
            return answer(JudgeOutcome::Capped(cap));
        }

        let (outcome, usage) = match judgement::Prompt::for_request(request) {
            Ok(prompt) => {
                let (raw, usage) = asking.asker.judge_metered(&prompt);
                (
                    judgement::check_flagged(raw, request, asked.reviewer_directed),
                    usage,
                )
            }
            Err(no) => (Err(no), None),
        };
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        self.settle_a_cloud_request(&model, usage);
        match outcome {
            Ok(verdict) => {
                self.cache_the_verdict(request, &engine, &model, &verdict);
                answer(JudgeOutcome::Verdict(verdict))
            }
            Err(no) => {
                say!("no Verdict from {engine} for a Folder Scan of the command line: {no}");
                answer(JudgeOutcome::NoVerdict(no.to_string()))
            }
        }
    }

    /// Caches one Verdict under the request, the engine and the model. The
    /// caller holds the write lock.
    fn cache_the_verdict(
        &self,
        request: &JudgementRequest,
        engine: &str,
        model: &str,
        verdict: &Verdict,
    ) {
        let record = CachedVerdict::of(request.hash(), engine, model, Timestamp::now(), verdict);
        let written = VerdictCacheWriter::open(
            &VerdictCache::in_data_directory(&self.directory),
            &*self.keys,
        )
        .and_then(|mut writer| writer.append(&record));
        if let Err(error) = written {
            say!("a Verdict for the command line could not be cached: {error}");
        }
    }
}
