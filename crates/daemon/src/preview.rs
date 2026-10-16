//! "Preview a request" in the daemon (spec sections 4.4 and 8.10).
//!
//! Given an Item id and an engine, the daemon builds exactly what it would
//! send that engine: the fixed system prompt and the user turn with the
//! redacted Judgement Request inside its nonce block, under that engine's
//! budget, or the answer that the Item is too large for it. Without an Item
//! id it previews the fixed sample Item shipped in the binary, which needs no
//! engine configured and no Item present.
//!
//! An Item that awaits judgement is previewed from what the latest Scan left
//! for the AI Judgement queue, the very Item and Heuristics the queue builds
//! its request from. Any other Item is read as it stands now and run through
//! the Tiers of the Rule Pack in force, as a Folder Scan would, for the
//! Heuristics that fire on it.
//!
//! Nothing is sent, nothing is cached and nothing is recorded: no engine is
//! opened, the Verdict cache is not read, and neither the Event Log nor the
//! state file is touched. The request is answered beside any running Scan.

use agentsweep_core::finding::FiredHeuristic;
use agentsweep_core::item::{Item, ItemId};
use agentsweep_core::judgement_request::Normalisation;
use agentsweep_core::preview::{self, Preview, judge_for, sample_item};
use agentsweep_core::scan::Scanners;
use agentsweep_core::settings::JudgementEngine;
use agentsweep_ipc::preview::{PreviewOutcome, RequestPreview};
use agentsweep_ipc::protocol::RequestError;

use crate::actions::Acting;
use crate::service::Daemon;

impl Daemon {
    /// The preview of what `engine` would be handed about the Item `item`
    /// names, or about the sample Item when it names none.
    pub(crate) fn preview_request(
        &self,
        item: Option<&str>,
        engine: JudgementEngine,
    ) -> Result<RequestPreview, RequestError> {
        let machine = self.machine_in_force();
        let judge = judge_for(engine, Normalisation::of_home(machine.home())).ok_or_else(|| {
            RequestError::new(
                "no-engine",
                "AI Judgement off sends nothing, so there is no request to preview; choose an \
                 engine",
            )
        })?;
        let (item, fired, sample) = match item {
            None => {
                let item = sample_item();
                let fired = self.fired_now(&item)?;
                (item, fired, true)
            }
            Some(id) => {
                let (item, fired) = self.item_to_preview(&ItemId::from_recorded(id))?;
                (item, fired, false)
            }
        };
        let outcome = match preview::preview(&judge, &item, &fired)
            .map_err(|reason| RequestError::new("failed", reason))?
        {
            Preview::Request {
                request,
                prompt,
                tokens,
                budget,
            } => PreviewOutcome::Request {
                system: prompt.system().to_string(),
                user: prompt.user().to_string(),
                nonce: prompt.nonce().to_string(),
                prompt_version: prompt.version().to_string(),
                tokens,
                budget,
                windowed: request.is_windowed(),
            },
            Preview::TooLarge { tokens, budget } => PreviewOutcome::TooLarge { tokens, budget },
        };
        Ok(RequestPreview {
            engine,
            item: item.id.as_str().to_string(),
            sample,
            outcome,
        })
    }

    /// The Item and the Heuristics that fired on it: what the latest Scan
    /// left awaiting judgement, or else the Item as it stands now with what
    /// the Tiers make of it.
    fn item_to_preview(&self, id: &ItemId) -> Result<(Item, Vec<FiredHeuristic>), RequestError> {
        let held = self
            .awaiting
            .lock()
            .expect("the awaiting Items are not poisoned")
            .iter()
            .find(|awaiting| &awaiting.item.id == id)
            .map(|awaiting| (awaiting.item.clone(), awaiting.fired.clone()));
        if let Some(held) = held {
            return Ok(held);
        }
        let roots = self.roots_for(id);
        let machine = self.machine_in_force();
        let acting = Acting {
            machine: &machine,
            roots: &roots,
        };
        let item = acting
            .enumerate()
            .items
            .into_iter()
            .find(|item| &item.id == id)
            .ok_or_else(|| {
                RequestError::new(
                    "unknown-target",
                    format!("`{}` names no Item AgentSweep knows", id.as_str()),
                )
            })?;
        let fired = self.fired_now(&item)?;
        Ok((item, fired))
    }

    /// The Threat Heuristics that fire on one Item under the Rule Pack in
    /// force.
    fn fired_now(&self, item: &Item) -> Result<Vec<FiredHeuristic>, RequestError> {
        let pack = self.pack_in_force();
        Scanners::with_bands(&pack.rules, pack.manifest.bands)
            .assess(item)
            .map(|assessment| assessment.fired)
            .map_err(|error| {
                RequestError::new("failed", format!("the Tiers could not run: {error}"))
            })
    }
}
