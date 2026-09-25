//! Acting on what a Scan found: by itself during a Scan, and when a client
//! asks.
//!
//! **During a Scan.** Once the Tiers have decided and before the Baseline
//! advances, every Item is taken in the per-Item order of spec section 6.4. An
//! Item that is back on its Surface with exactly the content AgentSweep took
//! out by itself is taken out again (the re-enforce of spec section 5.3), and
//! the third reappearance within an hour is answered with the "keeps coming
//! back" Finding instead. Any other Item with a Finding a stable Rule raised on
//! a kind the eligibility table lets go by itself is quarantined
//! automatically. A Rule on Probation, a Heuristic, an Exposure, a Drift
//! question and a Managed Item never act alone: [`may_quarantine`] says so, and
//! a chain that was tampered with freezes all of it (ADR 0003).
//!
//! **On request.** The closed vocabulary of [`Request`]: a manual Quarantine of
//! any Threat Finding, Restore, Trust, Acknowledge, the one-click fix of
//! Exposures 0018 and 0019, Re-enable for a plugin whose newer version this
//! daemon found clean, and revealing where a Receipt's Item came from. Every
//! request names a Finding, an Item or a Receipt by id and the daemon resolves
//! it against what it knows; an id it does not know is refused and nothing is
//! read. Revealing a Receipt is the one request with a path, and the path is
//! compared with what the Event Log says, never opened.
//!
//! Every action states whether Agent sessions appear to be running
//! ([`crate::sessions`]), and every write that moved another Item besides the
//! one it was about names that Item and the hash it left there, so the next
//! Scan reads it as a known action and never as Drift (ADR 0007).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;

use agentsweep_core::adapter::{Enumeration, SurfaceAdapter};
use agentsweep_core::derived::{QuarantineEntry, QuarantineManifest};
use agentsweep_core::drift::{AcknowledgeError, Acknowledgement};
use agentsweep_core::enforcement::{Cause, Enforcement, FIXABLE_EXPOSURES, may_quarantine};
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::eventlog::{Actor, EventLog, Outcome, Primitive, ReceiptStep};
use agentsweep_core::finding::{Category, Finding, FindingState, RuleStatus, Severity, Source};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Item, ItemId, Kind, Scope, Shape};
use agentsweep_core::keychain::KeySource;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::quarantine::{Conflict, EnforcementError, Receipt, ReceiptId};
use agentsweep_core::state::{RecordedFinding, StateFile, StateWriter};
use agentsweep_ipc::protocol::{
    ActionReport, Request, RequestError, RevealedReceipt, Sessions, StateEvent, receipts_to_value,
};

use crate::full_scan::{Covering, survey};
use crate::machine::{Machine, adapters};
use crate::service::Daemon;
use crate::sessions;

/// Where the daemon acts: the machine, and the project roots an action or a
/// Scan enumerated.
#[derive(Clone, Copy, Debug)]
pub struct Acting<'a> {
    /// The machine.
    pub machine: &'a Machine,
    /// The pooled project roots in play.
    pub roots: &'a [PathBuf],
}

impl Acting<'_> {
    /// The Host an adapter enforces through.
    pub fn host(&self) -> Host {
        self.machine.host(self.roots.to_vec())
    }

    /// Whether Agent sessions appear to be running on this machine.
    pub fn sessions(&self) -> Sessions {
        sessions::detect(self.machine.home())
    }

    /// Everything the adapters yield at these roots right now. Nothing is
    /// judged and nothing is written: an action reads the Item it is about as
    /// it stands, never as a Scan remembered it.
    pub fn enumerate(&self) -> Enumeration {
        survey(self.machine, &adapters(), self.roots, Covering::Roots(&[])).enumeration
    }

    /// Every entry Item as it stands now, by id, with its hash. What a write
    /// that edits shared files is compared against afterwards.
    pub fn entries_now(&self) -> BTreeMap<ItemId, String> {
        self.enumerate()
            .items
            .into_iter()
            .filter(|item| item.shape == Shape::Entry)
            .map(|item| (item.id, item.content_hash))
            .collect()
    }

    /// The entries of the files this Receipt edited that stand at a hash they
    /// did not have before: the settings entry a native disable flipped, the
    /// record a composite took out of its registry.
    pub fn collateral(
        &self,
        before: &BTreeMap<ItemId, String>,
        receipt: &Receipt,
    ) -> Vec<(ItemId, String)> {
        let edited: BTreeSet<PathBuf> = receipt
            .steps
            .iter()
            .filter(|step| {
                matches!(
                    step.primitive,
                    Primitive::NativeDisable | Primitive::RemoveEntry
                )
            })
            .map(|step| PathBuf::from(&step.path))
            .collect();
        if edited.is_empty() {
            return Vec::new();
        }
        self.enumerate()
            .items
            .into_iter()
            .filter(|item| item.shape == Shape::Entry && edited.contains(&item.path))
            .filter(|item| before.get(&item.id) != Some(&item.content_hash))
            .map(|item| (item.id, item.content_hash))
            .collect()
    }
}

/// True for the kinds whose Quarantine edits a file other Items live in
/// besides moving the Item itself: the plugin composite flips the Agent's own
/// switch, the marketplace composite takes the registry record out. Only
/// those are compared before and after, because only those move another Item.
pub fn moves_other_items(kind: Option<Kind>) -> bool {
    matches!(kind, Some(Kind::Plugin | Kind::Marketplace))
}

/// The adapter that yields Items of this agent id.
pub fn adapter_for(agent: &str) -> Option<Box<dyn SurfaceAdapter>> {
    adapters()
        .into_iter()
        .find(|adapter| adapter.descriptor().agent == agent)
}

/// What a Scan did by itself.
#[derive(Clone, Debug, Default)]
pub struct ScanActions {
    /// The Items quarantined automatically, with the Receipt each one got.
    pub quarantined: Vec<(ItemId, String)>,
    /// The Items that came back and were taken out again, with the Receipt
    /// the count went on.
    pub re_enforced: Vec<(ItemId, String)>,
    /// The Items that are back on their Surface with the content a Receipt
    /// took out, and stay there: their Findings are open, not stopped.
    pub returned: BTreeSet<ItemId>,
    /// The "keeps coming back" Findings this Scan raised.
    pub keeps_coming_back: Vec<Finding>,
    /// Whether Agent sessions appeared to be running, when anything was done.
    pub sessions: Option<Sessions>,
}

impl ScanActions {
    /// True when anything was written to the Event Log.
    pub fn wrote(&self) -> bool {
        !self.quarantined.is_empty() || !self.re_enforced.is_empty()
    }
}

/// The write side, opened the first time a Scan needs it and not before, so a
/// Scan with nothing to do opens nothing.
fn writer<'e, 'k>(
    slot: &'e mut Option<Enforcement<'k>>,
    directory: &DataDirectory,
    keys: &'k dyn KeySource,
) -> Option<&'e mut Enforcement<'k>> {
    if slot.is_none() {
        match Enforcement::open(directory, keys) {
            Ok((enforcement, _)) => *slot = Some(enforcement),
            Err(error) => {
                say!("the quarantine store could not be opened: {error}");
                return None;
            }
        }
    }
    slot.as_mut()
}

/// Everything one Scan does by itself, in the per-Item order.
///
/// `findings` are what the Tiers raised on this enumeration and `manifest` is
/// what the store held before the Scan began. A frozen chain acts on nothing:
/// every reappearance stays where it is and nothing is quarantined until the
/// user has looked at the records.
#[allow(clippy::too_many_arguments)]
pub fn act_in_scan(
    acting: &Acting<'_>,
    directory: &DataDirectory,
    keys: &dyn KeySource,
    enumeration: &Enumeration,
    findings: &[Finding],
    manifest: &QuarantineManifest,
    frozen: bool,
    at: Timestamp,
) -> ScanActions {
    let mut acted = ScanActions::default();
    let mut enforcement: Option<Enforcement<'_>> = None;
    let host = acting.host();

    for item in &enumeration.items {
        // The Receipt that took exactly this content out, the latest one where
        // the user quarantined it again after it kept coming back.
        let held = manifest
            .entries()
            .filter(|entry| entry.item_id == item.id && entry.content_hash == item.content_hash)
            .max_by_key(|entry| entry.quarantined_at);
        if let Some(entry) = held {
            reappeared(
                acting,
                directory,
                keys,
                &host,
                item,
                entry,
                findings,
                frozen,
                at,
                &mut enforcement,
                &mut acted,
            );
            continue;
        }
        if frozen {
            continue;
        }
        for finding in findings.iter().filter(|finding| finding.item_id == item.id) {
            let cause = Cause::of(finding, Actor::Auto);
            if may_quarantine(item, &cause).is_err() {
                continue;
            }
            let Some(adapter) = adapter_for(&item.agent) else {
                break;
            };
            let Some(writing) = writer(&mut enforcement, directory, keys) else {
                break;
            };
            let running = acted
                .sessions
                .get_or_insert_with(|| acting.sessions())
                .running;
            let before = match moves_other_items(Some(item.kind)) {
                true => acting.entries_now(),
                false => BTreeMap::new(),
            };
            match writing.quarantine_with(
                &*adapter,
                &host,
                item,
                &cause.with_sessions(running),
                &mut |receipt| acting.collateral(&before, receipt),
            ) {
                Ok(receipt) => {
                    say!(
                        "quarantined {} by itself: {} ({})",
                        item.id,
                        finding.source,
                        receipt.id
                    );
                    acted
                        .quarantined
                        .push((item.id.clone(), receipt.id.to_string()));
                }
                Err(error) => say!("{} could not be quarantined: {error}", item.id),
            }
            // One Quarantine per Item: the first Finding that may act is the
            // one that did, or that tried to.
            break;
        }
    }
    acted
}

/// One Item back on its Surface with the content a Receipt took out.
#[allow(clippy::too_many_arguments)]
fn reappeared<'k>(
    acting: &Acting<'_>,
    directory: &DataDirectory,
    keys: &'k dyn KeySource,
    host: &Host,
    item: &Item,
    entry: &QuarantineEntry,
    findings: &[Finding],
    frozen: bool,
    at: Timestamp,
    enforcement: &mut Option<Enforcement<'k>>,
    acted: &mut ScanActions,
) {
    // What the user quarantined by hand is theirs to take out again, and a
    // frozen chain takes nothing out at all. Either way the Item is back.
    if entry.actor != Actor::Auto || frozen {
        acted.returned.insert(item.id.clone());
        return;
    }
    if entry.keeps_coming_back(at) {
        acted.returned.insert(item.id.clone());
        let (severity, status) = findings
            .iter()
            .find(|finding| {
                finding.item_id == item.id && finding.source == Source::Rule(entry.rule_id)
            })
            .map(|finding| (finding.severity, finding.status))
            .unwrap_or((Severity::Critical, RuleStatus::Stable));
        say!(
            "{} keeps coming back: {} reappearances within the hour, no longer taken out",
            item.id,
            entry.re_enforced_within_the_hour(at) + 1
        );
        acted.keeps_coming_back.push(Finding::keeps_coming_back(
            &item.id,
            item.kind,
            &item.content_hash,
            severity,
            status,
        ));
        return;
    }
    let (Some(adapter), Some(writing)) = (
        adapter_for(&item.agent),
        writer(enforcement, directory, keys),
    ) else {
        acted.returned.insert(item.id.clone());
        return;
    };
    let running = acted
        .sessions
        .get_or_insert_with(|| acting.sessions())
        .running;
    let before = match moves_other_items(Some(item.kind)) {
        true => acting.entries_now(),
        false => BTreeMap::new(),
    };
    match writing.re_enforce_with(&*adapter, host, item, entry, running, &mut |receipt| {
        acting.collateral(&before, receipt)
    }) {
        Ok(done) => {
            say!(
                "{} came back and was taken out again ({} times, {})",
                item.id,
                done.times,
                done.receipt_id
            );
            acted.re_enforced.push((item.id.clone(), done.receipt_id));
        }
        Err(error) => {
            say!(
                "{} came back and could not be taken out again: {error}",
                item.id
            );
            acted.returned.insert(item.id.clone());
        }
    }
}

/// Why a request was refused, in the words the client prints.
fn refused(code: &str, message: impl Into<String>) -> RequestError {
    RequestError::new(code, message)
}

/// The refusal for an id the daemon does not know.
fn unknown(target: &str) -> RequestError {
    refused(
        "unknown-target",
        format!("AgentSweep knows no Finding, Item or Receipt `{target}`"),
    )
}

/// The refusal an enforcement error becomes.
fn failed(error: EnforcementError) -> RequestError {
    let code = match error {
        EnforcementError::NotEligible { .. } | EnforcementError::Unsupported { .. } => {
            "not-allowed"
        }
        EnforcementError::FileIsChanging { .. } => "changed",
        EnforcementError::Missing { .. } => "gone",
        _ => "failed",
    };
    refused(code, error.to_string())
}

/// Which Finding on an Item a request means when it names the Item: a Rule's
/// first, then the Score, then the Finding that the Item keeps coming back,
/// then the Drift question.
fn priority(finding: &RecordedFinding) -> u8 {
    match finding.source.as_str() {
        source if source.starts_with("rule") => 0,
        source if source.starts_with("score") => 1,
        "keeps coming back" => 2,
        "drift" => 3,
        _ => 4,
    }
}

/// The name a person knows an Item by: the last part of its locator.
fn name_of(item_id: &str) -> &str {
    let locator = item_id.rsplit(['/', '#']).next().unwrap_or(item_id);
    if locator.is_empty() { item_id } else { locator }
}

/// An Item as a sentence names it: its kind in words, then its name.
fn named(kind: Option<Kind>, item_id: &str) -> String {
    match kind {
        Some(kind) => format!(
            "{} '{}'",
            kind.id_segment().replace('-', " "),
            name_of(item_id)
        ),
        None => format!("'{}'", name_of(item_id)),
    }
}

/// The line a manual Quarantine of a project's Item adds (spec section 8.4).
const PROJECT_LINE: &str =
    "This file belongs to a project, so git will show the change. Restore undoes it.";

impl Daemon {
    /// Carries out one action request.
    pub(crate) fn act(self: &Arc<Daemon>, request: &Request) -> Result<Value, RequestError> {
        match request {
            Request::Quarantine { target } => self.quarantine(target),
            Request::Restore { target, conflict } => self.restore(target, *conflict),
            Request::Trust { target } => self.trust(target),
            Request::Acknowledge { target } => self.acknowledge(target),
            Request::Fix { target } => self.fix(target),
            Request::ReEnable { target } => self.re_enable(target),
            Request::RevealReceipt { path } => self.reveal(path.as_deref()),
            Request::Status
            | Request::ScanNow
            | Request::Subscribe
            | Request::RuleFeed { .. }
            | Request::Sessions
            | Request::Folder { .. } => Err(RequestError::unknown(request.as_str())),
        }
    }

    /// The one Finding a target names that the action may be taken on.
    ///
    /// A Finding id names itself. An Item id names the Findings on that Item,
    /// and the one the action fits best is taken. Anything else is not
    /// something this daemon knows.
    fn finding_for(
        &self,
        target: &str,
        fits: impl Fn(&RecordedFinding) -> bool,
        refusal: &str,
    ) -> Result<RecordedFinding, RequestError> {
        let state = self.state.lock().expect("the state is not poisoned");
        if target.contains('|') {
            let found = state
                .findings
                .iter()
                .find(|finding| finding.id.as_str() == target)
                .ok_or_else(|| unknown(target))?;
            return match fits(found) {
                true => Ok(found.clone()),
                false => Err(refused("not-allowed", refusal)),
            };
        }
        let on_item: Vec<&RecordedFinding> = state
            .findings
            .iter()
            .filter(|finding| finding.item_id.as_str() == target)
            .collect();
        if on_item.is_empty() {
            return Err(unknown(target));
        }
        on_item
            .into_iter()
            .filter(|finding| fits(finding))
            .min_by_key(|finding| priority(finding))
            .cloned()
            .ok_or_else(|| refused("not-allowed", refusal))
    }

    /// The Receipt a target names: a Receipt id, or a Finding or an Item one
    /// Receipt stopped.
    fn receipt_for(&self, target: &str) -> Result<QuarantineEntry, RequestError> {
        let manifest = self.manifest()?;
        if ReceiptId::parse(target).is_some() {
            return manifest
                .for_receipt(target)
                .cloned()
                .ok_or_else(|| unknown(target));
        }
        let by_finding = {
            let state = self.state.lock().expect("the state is not poisoned");
            state
                .findings
                .iter()
                .find(|finding| finding.id.as_str() == target && !finding.receipt_id.is_empty())
                .map(|finding| finding.receipt_id.clone())
        };
        if let Some(receipt_id) = by_finding {
            return manifest
                .for_receipt(&receipt_id)
                .cloned()
                .ok_or_else(|| unknown(target));
        }
        if target.contains('|') {
            let known = self
                .state
                .lock()
                .expect("the state is not poisoned")
                .findings
                .iter()
                .any(|finding| finding.id.as_str() == target);
            return Err(match known {
                true => refused("not-allowed", "that Finding was not quarantined"),
                false => unknown(target),
            });
        }
        let mut held: Vec<&QuarantineEntry> = manifest
            .entries()
            .filter(|entry| entry.item_id.as_str() == target)
            .collect();
        match held.len() {
            0 => Err(unknown(target)),
            1 => Ok(held.remove(0).clone()),
            _ => Err(refused(
                "ambiguous",
                format!(
                    "more than one Receipt holds that Item; name one of {}",
                    held.iter()
                        .map(|entry| entry.receipt_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
        }
    }

    /// What the store holds, as the Event Log says.
    fn manifest(&self) -> Result<QuarantineManifest, RequestError> {
        EventLog::in_data_directory(&self.directory)
            .read(&*self.keys)
            .map(|view| view.quarantine_manifest())
            .map_err(|error| refused("failed", format!("the Event Log: {error}")))
    }

    /// The pooled roots an Item of this id may need: its own project root,
    /// or none for the user's own Scope.
    fn roots_for(&self, item_id: &ItemId) -> Vec<PathBuf> {
        self.pooled_roots()
            .into_iter()
            .filter(|root| item_id.in_scope(&Scope::Project(root.clone()).id_segment()))
            .collect()
    }

    /// The Item as it stands on its Surface now, which has to be the content
    /// the Finding was raised on.
    fn locate(
        &self,
        roots: &[PathBuf],
        item_id: &ItemId,
        content_hash: &str,
    ) -> Result<Item, RequestError> {
        let acting = Acting {
            machine: &self.machine,
            roots,
        };
        let item = acting
            .enumerate()
            .items
            .into_iter()
            .find(|item| &item.id == item_id)
            .ok_or_else(|| {
                refused(
                    "gone",
                    "the Item is no longer where the Scan found it, so nothing was done",
                )
            })?;
        if item.content_hash != content_hash {
            return Err(refused(
                "changed",
                "the Item changed since the Finding was raised, so nothing was done; the next \
                 Scan looks at it again",
            ));
        }
        Ok(item)
    }

    /// Manual Quarantine: any open Threat Finding at any Tier, by the same
    /// primitive table an automatic one uses (spec section 5.2).
    fn quarantine(self: &Arc<Daemon>, target: &str) -> Result<Value, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let finding = self.finding_for(
            target,
            |finding| finding.is_open() && finding.category == Category::Threat,
            "only an open Threat Finding is quarantined; an Exposure is fixed or kept, never \
             moved",
        )?;
        let roots = self.roots_for(&finding.item_id);
        let item = self.locate(&roots, &finding.item_id, &finding.content_hash)?;
        let adapter = adapter_for(&item.agent).ok_or_else(|| unknown(target))?;
        let acting = Acting {
            machine: &self.machine,
            roots: &roots,
        };
        let sessions = acting.sessions();
        let cause = Cause {
            actor: Actor::User,
            category: finding.category,
            tier: finding.tier,
            status: finding.status,
            rule_id: finding.rule_id,
            finding_id: finding.id.clone(),
            drift: finding.source == "drift",
            sessions_running: sessions.running,
        };
        let before = match moves_other_items(Some(item.kind)) {
            true => acting.entries_now(),
            false => BTreeMap::new(),
        };
        let (mut enforcement, _) =
            Enforcement::open(&self.directory, &*self.keys).map_err(failed)?;
        let receipt = enforcement
            .quarantine_with(&*adapter, &acting.host(), &item, &cause, &mut |receipt| {
                acting.collateral(&before, receipt)
            })
            .map_err(failed)?;
        drop(enforcement);

        let receipt_id = receipt.id.to_string();
        self.settle(|recorded| stop(recorded, &item.id, &item.content_hash, &receipt_id));
        let mut message = format!(
            "Quarantined the {}. `agentsweep restore {receipt_id}` puts it back.",
            named(Some(item.kind), item.id.as_str())
        );
        if item.id.is_project() {
            message = format!("{message} {PROJECT_LINE}");
        }
        say!("quarantined {} on request ({receipt_id})", item.id);
        Ok(self.report(
            "quarantine",
            &finding,
            &receipt_id,
            receipt.result(),
            receipt.steps,
            false,
            sessions,
            message,
        ))
    }

    /// The one-click fix of Exposures 0018 and 0019: the entry taken out of
    /// its settings file, as a Quarantine a Restore undoes.
    fn fix(self: &Arc<Daemon>, target: &str) -> Result<Value, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let finding = self.finding_for(
            target,
            |finding| {
                finding.is_open()
                    && finding.category == Category::Exposure
                    && FIXABLE_EXPOSURES.contains(&finding.rule_id)
            },
            "only the open Exposures of Rules 0018 and 0019 have the one-click fix",
        )?;
        let roots = self.roots_for(&finding.item_id);
        let item = self.locate(&roots, &finding.item_id, &finding.content_hash)?;
        let adapter = adapter_for(&item.agent).ok_or_else(|| unknown(target))?;
        let acting = Acting {
            machine: &self.machine,
            roots: &roots,
        };
        let sessions = acting.sessions();
        let cause = Cause {
            actor: Actor::User,
            category: finding.category,
            tier: finding.tier,
            status: finding.status,
            rule_id: finding.rule_id,
            finding_id: finding.id.clone(),
            drift: false,
            sessions_running: sessions.running,
        };
        let (mut enforcement, _) =
            Enforcement::open(&self.directory, &*self.keys).map_err(failed)?;
        let receipt = enforcement
            .fix_with(&*adapter, &acting.host(), &item, &cause, &mut |_| {
                Vec::new()
            })
            .map_err(failed)?;
        drop(enforcement);

        let receipt_id = receipt.id.to_string();
        self.settle(|recorded| stop(recorded, &item.id, &item.content_hash, &receipt_id));
        say!("fixed {} on request ({receipt_id})", item.id);
        Ok(self.report(
            "fix",
            &finding,
            &receipt_id,
            receipt.result(),
            receipt.steps,
            false,
            sessions,
            format!(
                "Took the setting '{}' out of its file. `agentsweep restore {receipt_id}` puts \
                 it back.",
                name_of(item.id.as_str())
            ),
        ))
    }

    /// Restore: the Receipt replayed in reverse, with Trust for what
    /// AgentSweep took out by itself (spec section 5.4).
    fn restore(
        self: &Arc<Daemon>,
        target: &str,
        conflict: Conflict,
    ) -> Result<Value, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let entry = self.receipt_for(target)?;
        let agent = entry.item_id.as_str().split('/').next().unwrap_or_default();
        let adapter = adapter_for(agent).ok_or_else(|| unknown(target))?;
        let roots = self.roots_for(&entry.item_id);
        let acting = Acting {
            machine: &self.machine,
            roots: &roots,
        };
        let sessions = acting.sessions();
        let before = match moves_other_items(entry.kind) {
            true => acting.entries_now(),
            false => BTreeMap::new(),
        };
        let (mut enforcement, _) =
            Enforcement::open(&self.directory, &*self.keys).map_err(failed)?;
        let report = enforcement
            .restore_with(
                &*adapter,
                &acting.host(),
                &entry,
                conflict,
                &mut |receipt| acting.collateral(&before, receipt),
            )
            .map_err(failed)?;
        drop(enforcement);

        let done = report.result == Outcome::Ok;
        let trusted = done && entry.actor == Actor::Auto;
        if done {
            let now = match trusted {
                true => FindingState::Trusted,
                false => FindingState::Open,
            };
            self.settle(|recorded| {
                if recorded.receipt_id != entry.receipt_id {
                    return false;
                }
                recorded.state = now;
                recorded.receipt_id.clear();
                recorded.fixed_version.clear();
                true
            });
        }
        let message = match (done, trusted, report.conflicted) {
            (true, true, _) => format!(
                "Restored the {} and trusted this exact version, so it is not stopped again.",
                named(entry.kind, entry.item_id.as_str())
            ),
            (true, false, _) => {
                format!(
                    "Restored the {}.",
                    named(entry.kind, entry.item_id.as_str())
                )
            }
            (false, _, true) => "Something else is at the original place now, so nothing was \
                                 put back. Ask again with --replace to replace it or --beside to \
                                 restore beside it."
                .to_string(),
            (false, _, false) => "The Restore did not finish; each step below says what \
                                  happened."
                .to_string(),
        };
        say!(
            "restored {} on request ({})",
            entry.item_id,
            entry.receipt_id
        );
        let finding = self.recorded_for_receipt(&entry);
        Ok(ActionReport {
            action: "restore".to_string(),
            finding_id: entry.finding_id.clone(),
            item_id: entry.item_id.to_string(),
            receipt_id: entry.receipt_id.clone(),
            state: finding
                .map(|finding| finding.state.to_string())
                .unwrap_or_else(|| {
                    match (done, trusted) {
                        (true, true) => FindingState::Trusted,
                        (true, false) => FindingState::Open,
                        (false, _) => FindingState::Stopped,
                    }
                    .to_string()
                }),
            result: report.result,
            steps: report.steps,
            trusted,
            sessions,
            message,
        }
        .to_value())
    }

    /// Re-enable: the plugin switched back on for the newer version this
    /// daemon's last Scan found clean, and nothing else (spec section 5.4).
    fn re_enable(self: &Arc<Daemon>, target: &str) -> Result<Value, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let entry = self.receipt_for(target)?;
        if entry.kind != Some(Kind::Plugin) || !entry.natively_disabled {
            return Err(refused(
                "not-allowed",
                "only a plugin AgentSweep switched off is re-enabled",
            ));
        }
        let finding = self.recorded_for_receipt(&entry).ok_or_else(|| {
            refused(
                "not-allowed",
                "no Scan has found a newer version of this plugin yet",
            )
        })?;
        if finding.fixed_version.is_empty() {
            return Err(refused(
                "not-allowed",
                "no Scan has found a newer version of this plugin without a Threat Finding",
            ));
        }
        let roots = self.roots_for(&entry.item_id);
        let fixed = self.locate(&roots, &entry.item_id, &finding.fixed_version)?;
        let acting = Acting {
            machine: &self.machine,
            roots: &roots,
        };
        let sessions = acting.sessions();
        let before = acting.entries_now();
        let (mut enforcement, _) =
            Enforcement::open(&self.directory, &*self.keys).map_err(failed)?;
        let report = enforcement
            .re_enable_with(&acting.host(), &entry, &fixed, &mut |receipt| {
                acting.collateral(&before, receipt)
            })
            .map_err(failed)?;
        drop(enforcement);

        self.settle(|recorded| {
            if recorded.receipt_id != entry.receipt_id || recorded.fixed_version.is_empty() {
                return false;
            }
            recorded.fixed_version.clear();
            true
        });
        say!(
            "re-enabled {} on request ({})",
            entry.item_id,
            entry.receipt_id
        );
        Ok(self.report(
            "re-enable",
            &finding,
            &entry.receipt_id,
            report.result,
            report.steps,
            false,
            sessions,
            "Switched the plugin back on for its newer version. The version that was stopped \
             stays in quarantine."
                .to_string(),
        ))
    }

    /// Trust: this exact content of this kind is safe, wherever it appears.
    fn trust(self: &Arc<Daemon>, target: &str) -> Result<Value, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let finding = self.finding_for(
            target,
            |finding| {
                finding.is_open()
                    && !finding.content_hash.is_empty()
                    && !finding.source.starts_with("problem")
            },
            "only an open Finding about content can be trusted",
        )?;
        let sessions = sessions::detect(self.machine.home());
        let (mut enforcement, _) =
            Enforcement::open(&self.directory, &*self.keys).map_err(failed)?;
        enforcement
            .trust(
                &finding.item_id,
                finding.kind,
                &finding.content_hash,
                Actor::User,
            )
            .map_err(failed)?;
        drop(enforcement);

        // Trust is bound to the kind and the hash, so every open Finding on
        // that content is settled by it, wherever it stands.
        self.settle(|recorded| {
            if !recorded.is_open()
                || recorded.kind != finding.kind
                || recorded.content_hash != finding.content_hash
            {
                return false;
            }
            recorded.state = FindingState::Trusted;
            true
        });
        say!("trusted {} on request", finding.item_id);
        let message = match finding.category {
            Category::Threat => "Trusted this exact version. Any change to it is checked afresh.",
            Category::Exposure => "Kept it as it is. Any change to it is checked afresh.",
        };
        Ok(self.report(
            "trust",
            &finding,
            "",
            Outcome::Ok,
            Vec::new(),
            true,
            sessions,
            message.to_string(),
        ))
    }

    /// Acknowledge: the Drift was the user's own doing. The accepted hash
    /// moves to the content on screen and nothing else (spec section 4.6.5).
    fn acknowledge(self: &Arc<Daemon>, target: &str) -> Result<Value, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let finding = self.finding_for(
            target,
            |finding| finding.is_open() && finding.source == "drift",
            "only an open Drift question is acknowledged; a Finding that carries a change as \
             context is settled with that Finding",
        )?;
        let sessions = sessions::detect(self.machine.home());
        let (mut acknowledgement, _, _) = Acknowledgement::open(&self.directory, &*self.keys)
            .map_err(|error| refused("failed", error.to_string()))?;
        acknowledgement
            .acknowledge(&finding.item_id, &finding.content_hash, finding.id.as_str())
            .map_err(|error| match error {
                AcknowledgeError::Stale { .. } => refused("changed", error.to_string()),
                AcknowledgeError::Unknown(_) => refused("not-allowed", error.to_string()),
                AcknowledgeError::Chain(_) => refused("failed", error.to_string()),
            })?;
        drop(acknowledgement);

        self.settle(|recorded| {
            if recorded.id != finding.id {
                return false;
            }
            recorded.state = FindingState::Acknowledged;
            true
        });
        say!("acknowledged {} on request", finding.item_id);
        Ok(self.report(
            "acknowledge",
            &finding,
            "",
            Outcome::Ok,
            Vec::new(),
            false,
            sessions,
            "Noted that the change was yours. Every check still runs on it.".to_string(),
        ))
    }

    /// Every Receipt with the place its Item was taken from, or only those
    /// taken from at or below one path. The path is compared with what the
    /// Event Log says and never opened.
    fn reveal(&self, path: Option<&str>) -> Result<Value, RequestError> {
        let manifest = self.manifest()?;
        let wanted = path.map(Path::new);
        let receipts: Vec<RevealedReceipt> = manifest
            .entries()
            .filter_map(|entry| {
                let original = entry.original_path().unwrap_or_default();
                if let Some(wanted) = wanted
                    && !Path::new(original).starts_with(wanted)
                {
                    return None;
                }
                Some(RevealedReceipt {
                    receipt_id: entry.receipt_id.clone(),
                    item_id: entry.item_id.clone(),
                    kind: entry.kind,
                    original_path: original.to_string(),
                    payload_path: match entry.has_payload() {
                        true => self
                            .directory
                            .quarantine_payload(&entry.receipt_id)
                            .display()
                            .to_string(),
                        false => String::new(),
                    },
                    actor: entry.actor,
                    quarantined_at: entry.quarantined_at,
                    finding_id: entry.finding_id.clone(),
                    rule_id: entry.rule_id,
                    re_enforced: entry.re_enforced,
                })
            })
            .collect();
        Ok(receipts_to_value(&receipts))
    }

    /// The Finding a Receipt stopped, as the state holds it.
    fn recorded_for_receipt(&self, entry: &QuarantineEntry) -> Option<RecordedFinding> {
        let state = self.state.lock().expect("the state is not poisoned");
        state
            .findings
            .iter()
            .find(|finding| {
                finding.receipt_id == entry.receipt_id || finding.id.as_str() == entry.finding_id
            })
            .cloned()
    }

    /// Changes where the Findings an action settled stand, writes the state
    /// file and tells every subscriber, so `status` and the Findings window
    /// show the action at once rather than after the next Scan.
    fn settle(self: &Arc<Daemon>, mut change: impl FnMut(&mut RecordedFinding) -> bool) {
        let mut changed = Vec::new();
        {
            let mut state = self.state.lock().expect("the state is not poisoned");
            for recorded in state.findings.iter_mut() {
                if change(recorded) {
                    changed.push((recorded.id.clone(), recorded.state.to_string()));
                }
            }
            let file = StateFile::in_data_directory(&self.directory);
            if let Err(error) = StateWriter::write(&file, &*self.keys, &state) {
                say!("the cached state could not be written: {error}");
            }
            self.health
                .lock()
                .expect("the health is not poisoned")
                .open_findings = state.open_count();
        }
        for (id, state) in changed {
            self.publish(StateEvent::FindingChanged { id, state });
        }
        self.tell_health();
    }

    /// The answer to an action that acted on one Finding.
    #[allow(clippy::too_many_arguments)]
    fn report(
        &self,
        action: &str,
        finding: &RecordedFinding,
        receipt_id: &str,
        result: Outcome,
        steps: Vec<ReceiptStep>,
        trusted: bool,
        sessions: Sessions,
        message: String,
    ) -> Value {
        let state = self
            .state
            .lock()
            .expect("the state is not poisoned")
            .findings
            .iter()
            .find(|recorded| recorded.id == finding.id)
            .map(|recorded| recorded.state.to_string())
            .unwrap_or_else(|| finding.state.to_string());
        ActionReport {
            action: action.to_string(),
            finding_id: finding.id.to_string(),
            item_id: finding.item_id.to_string(),
            receipt_id: receipt_id.to_string(),
            state,
            result,
            steps,
            trusted,
            sessions,
            message,
        }
        .to_value()
    }
}

/// Marks a Finding on this content of this Item as stopped by this Receipt.
fn stop(
    recorded: &mut RecordedFinding,
    item_id: &ItemId,
    content_hash: &str,
    receipt_id: &str,
) -> bool {
    if &recorded.item_id != item_id
        || recorded.content_hash != content_hash
        || recorded.state == FindingState::Stopped
    {
        return false;
    }
    recorded.state = FindingState::Stopped;
    recorded.receipt_id = receipt_id.to_string();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_person_knows_an_item_by_the_last_part_of_its_locator() {
        assert_eq!(
            name_of("claude-code/user/skill/~/.claude/skills/setup"),
            "setup"
        );
        assert_eq!(
            name_of("claude-code/user/mcp-server/~/.claude.json#tracker"),
            "tracker"
        );
    }

    #[test]
    fn a_sentence_names_the_kind_in_words_and_then_the_item() {
        assert_eq!(
            named(
                Some(Kind::McpServer),
                "claude-code/user/mcp-server/~/.claude.json#tracker"
            ),
            "mcp server 'tracker'"
        );
        assert_eq!(named(None, "claude-code/user/skill/x"), "'x'");
    }

    #[test]
    fn only_the_composites_move_another_item() {
        assert!(moves_other_items(Some(Kind::Plugin)));
        assert!(moves_other_items(Some(Kind::Marketplace)));
        assert!(!moves_other_items(Some(Kind::McpServer)));
        assert!(!moves_other_items(None));
    }

    #[test]
    fn an_item_named_by_id_means_its_rule_finding_first() {
        let rule = RecordedFinding {
            source: "rule 0001".to_string(),
            ..sample()
        };
        let drift = RecordedFinding {
            source: "drift".to_string(),
            ..sample()
        };
        assert!(priority(&rule) < priority(&drift));
    }

    fn sample() -> RecordedFinding {
        RecordedFinding {
            id: agentsweep_core::finding::FindingId::from_recorded("x|rule/0001|a"),
            item_id: ItemId::from_recorded("claude-code/user/skill/x"),
            kind: Kind::Skill,
            source: String::new(),
            rule_id: 1,
            category: Category::Threat,
            severity: Severity::Critical,
            tier: agentsweep_core::finding::Tier::Rules,
            status: RuleStatus::Probation,
            state: FindingState::Open,
            content_hash: "a".to_string(),
            title: String::new(),
            plain: String::new(),
            file: String::new(),
            drift: String::new(),
            receipt_id: String::new(),
            fixed_version: String::new(),
            first_seen: Timestamp::now(),
            notified_at: None,
        }
    }
}
