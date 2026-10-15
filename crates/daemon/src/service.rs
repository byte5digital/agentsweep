//! The daemon itself: what it holds, what it answers and when it scans.
//!
//! One Full Scan at start, one socket, one Scan at a time. The accept loop, the
//! watcher, the due check and the Scan each run on a thread of their own, and a
//! connection gets one more, so a client asking for status while a Full Scan is
//! running is answered at once out of what the last Scan left.
//!
//! What asks for a Scan and what runs one are kept apart by [`Queue`], which is
//! where the merge rules of spec section 6.4 live: one Scan at a time, pending
//! Change batches merge by path, a pending Full Scan absorbs them, and "Scan
//! now" during a Full Scan joins it rather than starting another.
//!
//! Nothing here is asynchronous. A Scan is processor-bound and a YARA-X
//! scanner cannot move between threads, so the daemon is a handful of threads
//! and a few locks rather than a runtime (ADR 0011).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, RwLock};

use agentsweep_core::adapter::WatchRoots;
use agentsweep_core::baseline::{self, Retention};
use agentsweep_core::chain::ChainState;
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::evaluation::EvaluationCache;
use agentsweep_core::eventlog::{Action, EventLog, PackChange, PackRules, RulePackRecord};
use agentsweep_core::finding::{Category, Finding, FindingId, FindingState};
use agentsweep_core::gate_facts::GateRecord;
use agentsweep_core::gate_registration::GateCommand;
use agentsweep_core::health::{Health, Protection, StateFileHealth};
use agentsweep_core::integrity::ResetUnanswered;
use agentsweep_core::item::Scope;
use agentsweep_core::judged::installed_models;
use agentsweep_core::keychain::{ClaudeKeyStore, KeySource, MemoryKeySource};
use agentsweep_core::packs::{LoadedPack, PackOrigin, PackStore, Verdict, judge};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::rules::RulePack;
use agentsweep_core::scan_pass::{BACKGROUND_WORKERS, ScanKind, on_demand_workers};
use agentsweep_core::settings::{Settings, SettingsError, SettingsFile, SettingsWriter};
use agentsweep_core::state::{RecordedFinding, State, StateFile, StateWriter, Trigger};
use agentsweep_core::verdicts;
use agentsweep_ipc::gate::{GateRequest, GateVerdict};
use agentsweep_ipc::peer::PeerCheck;
use agentsweep_ipc::protocol::{
    ActivityLine, Hello, Message, Refusal, Request, RequestError, StateEvent, Status,
    check_version, welcome,
};
use agentsweep_ipc::socket::{Connection, SocketListener};

use crate::bundle_watch::{self, BundleWatch, Change, Own};
use crate::change_scan::ChangeScan;
use crate::due::{self, Occasion, PowerState, Schedule, SystemPower};
use crate::full_scan::{FullScan, Progress, ScanRun};
use crate::machine::Machine;
use crate::options::{KeySourceChoice, Options};
use crate::permission::{Access, Disk, Folders, proven_readable_classes};
use crate::rule_feed::{self, Endpoints, FeedClient, FeedTuning, Fetched, Validators};
use crate::stores::{open_both_chains, open_the_event_log};
use crate::watcher::{self, Batch, Decision, Timings, Watch};

/// How the daemon is timed, so a test runs a day of Protection in a second.
///
/// Every field has the value the shipped daemon takes; a test names the ones
/// it wants to move and nothing else. Nothing here reaches the command line:
/// these are not the developer's flags but the suite's seams.
pub struct Tuning {
    /// The watcher's debounce: two seconds quiet, fifteen seconds maximum
    /// hold.
    pub watch: Timings,
    /// How often the due check asks.
    pub due: Schedule,
    /// Where Low Power Mode is read.
    pub power: Arc<dyn PowerState>,
    /// How many worker threads a Scan nobody is waiting for runs the Tiers
    /// with.
    pub workers: usize,
    /// The Rules the binary ships, the bundled ones unless a test names
    /// others. The seam a test flips one Rule to stable through, since every
    /// bundled Rule is on Probation and none may be flipped in place. A pack
    /// from the Rule Feed still replaces it, as it replaces the bundled one.
    pub pack: Option<Arc<RulePack>>,
    /// Where the Rule Feed is and how the fetch is timed.
    pub feed: FeedTuning,
    /// The handle every read into a protected location class goes through:
    /// the disk itself, unless a test hands in one that records, denies or
    /// blocks (spec section 9.7).
    pub folders: Arc<dyn Folders>,
    /// Whether the answer to an `engine` request asks Ollama at the address
    /// the settings name. Absent means yes for the installed daemon and no
    /// for a developer run, so a test or a hand run never reaches an Ollama
    /// on this Mac unless it says so.
    pub detect_ollama: Option<bool>,
    /// The command the Gate runs, which every Full Scan verifies with every
    /// detected Agent: the command line interface beside this daemon in the
    /// bundle. Absent when there is no such path, and then nothing is
    /// registered.
    pub gate: Option<GateCommand>,
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning {
            watch: Timings::default(),
            due: Schedule::default(),
            power: Arc::new(SystemPower),
            workers: BACKGROUND_WORKERS,
            pack: None,
            feed: FeedTuning::default(),
            folders: Arc::new(Disk),
            detect_ollama: None,
            gate: crate::gate::bundled_command(),
        }
    }
}

impl std::fmt::Debug for Tuning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuning")
            .field("watch", &self.watch)
            .field("due", &self.due)
            .field("workers", &self.workers)
            .field("pack", &self.pack)
            .field("feed", &self.feed)
            .field("detect_ollama", &self.detect_ollama)
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}

/// What has been asked for and what is running, with the rules of spec section
/// 6.4 about two Scans meeting each other in one place.
#[derive(Debug, Default)]
struct Queue {
    /// Which Scan kind is running, absent when none is.
    running: Option<ScanKind>,
    /// A Full Scan has been asked for, by whatever asked first.
    full: Option<Trigger>,
    /// The changed paths waiting for a Change Scan, gathered by path.
    batch: Batch,
    /// The Scan thread is alive and will take whatever is put here. Two
    /// requests arriving before it has taken the first would otherwise start
    /// two threads, and two Scans would run at once.
    draining: bool,
}

impl Queue {
    /// True when a Scan is running or one is waiting to, which is what Health
    /// reports as "scanning": a Scan that has been asked for has not happened
    /// yet, whether or not its thread has got going.
    fn busy(&self) -> bool {
        self.running.is_some() || self.full.is_some() || !self.batch.is_empty()
    }

    /// The next piece of work, marking it as the one running.
    fn next(&mut self) -> Option<Work> {
        if let Some(trigger) = self.full.take() {
            // A pending Full Scan absorbs every Change batch waiting with it.
            self.batch = Batch::default();
            self.running = Some(ScanKind::Full);
            return Some(Work::Full(trigger));
        }
        if !self.batch.is_empty() {
            self.running = Some(ScanKind::Change);
            return Some(Work::Change(std::mem::take(&mut self.batch)));
        }
        self.running = None;
        self.draining = false;
        None
    }

    /// Whoever put work here starts the Scan thread when none is draining the
    /// queue, and only then. Answers with true when the caller must start it.
    fn claim_the_thread(&mut self) -> bool {
        !std::mem::replace(&mut self.draining, true)
    }
}

/// One piece of work the Scan thread takes off the queue.
#[derive(Clone, Debug)]
enum Work {
    /// A Full Scan, and what asked for it.
    Full(Trigger),
    /// A Change Scan of these paths.
    Change(Batch),
}

/// Everything the daemon holds while it runs.
pub struct Daemon {
    pub(crate) directory: DataDirectory,
    pub(crate) keys: Box<dyn KeySource + Send + Sync>,
    pub(crate) machine: Machine,
    check: Arc<dyn PeerCheck>,
    pub(crate) tuning: Tuning,
    /// The cached derivation, which is what a client is answered out of.
    pub(crate) state: Mutex<State>,
    /// The user's choices, as the settings file holds them, or every default
    /// while that file cannot be read.
    pub(crate) settings: Mutex<Settings>,
    /// Where the Claude API key is kept: the second item of the login
    /// Keychain for the shipped daemon, memory for a test or a hand run.
    pub(crate) claude_key: Box<dyn ClaudeKeyStore + Send + Sync>,
    /// Every state a client is shown, by the precedence of spec section 6.6.
    pub(crate) health: Mutex<Health>,
    /// Which chains started again under a new key without the user having
    /// answered "Start a fresh record" since. Read off the chains at start,
    /// set by a Scan that finds a key missing, cleared by the answer.
    pub(crate) reset: Mutex<ResetUnanswered>,
    /// Held by whatever writes the Event Log or the Baseline: a Scan from
    /// start to end, and one action at a time. Each opens its own writer, and
    /// a chain has one head, so two writers at once would fork it.
    pub(crate) writing: Mutex<()>,
    /// The Findings the last Scan raised, which the next one compares against
    /// to know what is gone. Never stored: a restart derives them again.
    raised: Mutex<Vec<Finding>>,
    /// What has been asked for, and what is running.
    queue: Mutex<Queue>,
    /// The Rule Pack in force, compiled once. Compiling it costs far more than
    /// a Change Scan is allowed to take, so no Scan compiles its own. A Scan
    /// takes the pack in force when it starts and keeps it to the end; an
    /// accepted pack is in force for the Scan after.
    pack: RwLock<Arc<LoadedPack>>,
    /// The pack this binary ships, which is in force whenever no fetched pack
    /// is, and always while the Rule Feed is off.
    bundled: Arc<LoadedPack>,
    /// Where the Rule Feed is asked, absent when it is never asked: a
    /// developer run that named no feed.
    feed: Option<Endpoints>,
    /// Whether the answer to an `engine` request asks Ollama.
    pub(crate) detect_ollama: bool,
    /// Held while a fetch runs, so two never run at once.
    fetching: Mutex<()>,
    /// A change of the Rule Pack in force that is still to be recorded. It is
    /// written to the Event Log as a `rule-pack` record under the write lock,
    /// just before the Full Scan the change brings, when the Findings it takes
    /// with it are the ones the last Scan left.
    pack_change: Mutex<Option<PendingPackChange>>,
    /// The Activity lines the Event Log keeps, read once at start and
    /// extended by every `rule-pack` and `purge` record this daemon writes.
    activity: Mutex<Vec<ActivityLine>>,
    /// True while a fetch is waiting out its jitter or running.
    fetch_pending: AtomicBool,
    /// Held by whatever decides which pack is in force from the toggle: the
    /// toggle itself, and a fetch putting what it accepted in force. Without
    /// it a fetch that read the toggle on could put its pack in force just
    /// after the user switched the feed off.
    switching: Mutex<()>,
    /// The Tier outcomes this daemon has already produced. In memory only,
    /// empty at start, thrown away when a Rule Pack is accepted.
    cache: Arc<EvaluationCache>,
    /// The project roots the last Scan pooled, which is what tells a newly
    /// registered project from one AgentSweep already knows.
    roots: Mutex<Vec<PathBuf>>,
    /// The watcher, started again after every Full Scan on the roots that Scan
    /// declared.
    watch: Mutex<Option<Watch>>,
    /// The due check, started once.
    due: Mutex<Option<due::DueCheck>>,
    /// Everyone listening to the state events.
    subscribers: Mutex<Vec<Sender<StateEvent>>>,
    /// The Health the subscribers were last told about, so a change is sent
    /// once and a Health that did not move is not sent at all.
    told: Mutex<Option<Health>>,
    /// Set when the daemon's own bundle was replaced: no further piece of
    /// work is taken off the queue, and the daemon exits once the write in
    /// hand has finished, so `KeepAlive` starts the new binary (spec section
    /// 9.5).
    leaving: AtomicBool,
    /// True while a "Check now" makes its reads into the protected location
    /// classes, so two clicks never make them twice at once.
    pub(crate) checking: AtomicBool,
}

impl Daemon {
    /// Opens the stores, reads the cached state and works out the health,
    /// without binding anything or scanning anything.
    pub fn open(options: &Options) -> Result<Arc<Daemon>, Box<dyn Error>> {
        Daemon::open_answering(options, crate::peer_check::for_this_build())
    }

    /// The same, answering a peer check of the caller's choosing. It is how a
    /// test exercises the refusal a release build makes without a signed
    /// binary to make it about.
    pub fn open_answering(
        options: &Options,
        check: Arc<dyn PeerCheck>,
    ) -> Result<Arc<Daemon>, Box<dyn Error>> {
        let keys: Box<dyn KeySource + Send + Sync> = match options.key_source {
            KeySourceChoice::Keychain => Box::new(keychain()),
            KeySourceChoice::Memory => Box::new(MemoryKeySource::empty()),
        };
        Daemon::open_with(options, check, keys)
    }

    /// The same, holding the chain key the caller handed over.
    ///
    /// The shipped daemon reads the login Keychain and nothing else. This is
    /// the seam a test restarts a daemon through: a key that lives in the
    /// process would otherwise be a different key on every start, and the
    /// second daemon would read the chains it wrote itself as belonging to a
    /// generation it cannot verify.
    pub fn open_with(
        options: &Options,
        check: Arc<dyn PeerCheck>,
        keys: Box<dyn KeySource + Send + Sync>,
    ) -> Result<Arc<Daemon>, Box<dyn Error>> {
        Daemon::open_tuned(options, check, keys, Tuning::default())
    }

    /// The same, timed the caller's way.
    ///
    /// The debounce is two seconds and the due check fifteen minutes on a real
    /// machine, and a test that waited either out would be a test nobody runs.
    pub fn open_tuned(
        options: &Options,
        check: Arc<dyn PeerCheck>,
        keys: Box<dyn KeySource + Send + Sync>,
        tuning: Tuning,
    ) -> Result<Arc<Daemon>, Box<dyn Error>> {
        let directory = options.data_dir.clone();
        directory.create()?;

        // Opening both chains is what turns a key that went missing into one
        // chain restart rather than into a restart per write, and it is what
        // says whether the records were tampered with.
        let (events, baseline) = open_both_chains(&directory, &*keys)?;
        // A chain that started again under a new key stays "protection state
        // was reset" until the user answers, across restarts of the daemon.
        let reset = ResetUnanswered::of(
            &EventLog::in_data_directory(&directory)
                .chain()
                .verify(&*keys)?,
            &agentsweep_core::baseline::Baseline::in_data_directory(&directory)
                .chain()
                .verify(&*keys)?,
        );

        let file = StateFile::in_data_directory(&directory);
        let (mut state, state_file) = match file.read(&*keys) {
            Ok(state) => (state, StateFileHealth::Loaded),
            Err(error) if error.rebuilds() => {
                say!("the cached state is being rebuilt: {error}");
                (
                    State::empty(),
                    match error {
                        agentsweep_core::state::StateError::Missing => StateFileHealth::Missing,
                        _ => StateFileHealth::Rebuilt,
                    },
                )
            }
            Err(error) => return Err(Box::new(error)),
        };

        let machine = match &options.home {
            Some(home) => Machine::named(home.clone()),
            None => Machine::real(options.home_directory()?),
        };
        // A rebuilt state file remembers the protected classes the Baseline
        // proves AgentSweep read before, and no other: the grant was given
        // once, and losing the cache must not ask for it again.
        if state_file != StateFileHealth::Loaded {
            state.readable_classes = proven_readable_classes(&directory, &*keys, machine.home());
        }

        // The bundled pack is compiled once, here. A daemon that cannot
        // compile its own pack has nothing to protect with and says so rather
        // than starting.
        let bundled = Arc::new(match &tuning.pack {
            Some(pack) => LoadedPack::bundled_as(Arc::clone(pack)),
            None => LoadedPack::bundled()?,
        });
        // The installed daemon asks the project's own feed; a developer run
        // asks only a feed it was pointed at, so a hand run or a test never
        // reaches GitHub by accident.
        let feed = tuning
            .feed
            .endpoints
            .clone()
            .or_else(|| (!options.is_developer_run()).then(Endpoints::github));
        let detect_ollama = tuning.detect_ollama.unwrap_or(!options.is_developer_run());
        let (settings, settings_unreadable) = settings_at_start(&directory, &*keys, &mut state);
        let (pack, discarded) = pack_at_start(&directory, &bundled, &mut state, settings.rule_feed);
        // A stored pack discarded at start is recorded like an accepted one,
        // before the first Full Scan: what it withdrew is measured against
        // the discarded pack, which is the one the last Scans ran with.
        let pack_change = discarded.map(|(version, before)| {
            let mut record = RulePackRecord::new(
                PackChange::Discarded,
                pack.manifest.pack_version,
                &pack.manifest.released_at,
                pack.origin,
            );
            record.discarded_version = version;
            PendingPackChange {
                record,
                before,
                from: (version, PackOrigin::Fetched),
            }
        });
        let activity = activity_in_the_event_log(&directory, &*keys);
        let now = (tuning.due.now)();

        let mut health = Health {
            protection: Protection::On,
            events: crate::integrity::shown(&events, reset.events),
            baseline: crate::integrity::shown(&baseline, reset.baseline),
            projects_need_permission: crate::permission::needing_permission(&state.overview),
            gate_lines: Vec::new(),
            projects_gate_off: state.overview.projects_gate_off(),
            state_file,
            settings_unreadable,
            scanning: false,
            last_full_scan: state.last_full_scan,
            items: state.last_scan().map(|scan| scan.items).unwrap_or_default(),
            open_threats: 0,
            open_exposures: 0,
            rule_pack: pack.manifest.pack_version,
            rule_pack_origin: pack.origin,
            rules_released_at: pack.manifest.released_at.clone(),
            rule_feed: settings.rule_feed,
            ignored_pack: state.feed.ignored.clone(),
            feed_unreachable: match settings.rule_feed {
                true => Health::feed_unreachable_at(state.feed.unreachable_since, now),
                false => None,
            },
        };
        health.count_open(&state);

        Ok(Arc::new(Daemon {
            directory,
            keys,
            machine,
            check,
            tuning,
            state: Mutex::new(state),
            settings: Mutex::new(settings),
            claude_key: crate::engine::claude_key_store(options.key_source),
            health: Mutex::new(health),
            reset: Mutex::new(reset),
            writing: Mutex::new(()),
            raised: Mutex::new(Vec::new()),
            queue: Mutex::new(Queue::default()),
            pack: RwLock::new(pack),
            bundled,
            feed,
            detect_ollama,
            fetching: Mutex::new(()),
            pack_change: Mutex::new(pack_change),
            activity: Mutex::new(activity),
            fetch_pending: AtomicBool::new(false),
            switching: Mutex::new(()),
            cache: Arc::new(EvaluationCache::new()),
            roots: Mutex::new(Vec::new()),
            watch: Mutex::new(None),
            due: Mutex::new(None),
            subscribers: Mutex::new(Vec::new()),
            told: Mutex::new(None),
            leaving: AtomicBool::new(false),
            checking: AtomicBool::new(false),
        }))
    }

    /// The evaluation cache this daemon reads and fills.
    ///
    /// It is handed out so that the milestone that accepts a Rule Pack can
    /// empty it, which is the one thing that has to happen before the Full
    /// Scan a new pack triggers (spec section 6.4).
    pub fn evaluation_cache(&self) -> &Arc<EvaluationCache> {
        &self.cache
    }

    /// Throws every cached Tier outcome away. What an accepted Rule Pack does
    /// before the Full Scan it triggers.
    pub fn forget_evaluations(&self) {
        self.cache.clear();
    }

    /// The Rule Pack in force right now.
    pub fn pack_in_force(&self) -> Arc<LoadedPack> {
        Arc::clone(&self.pack.read().expect("the pack is not poisoned"))
    }

    /// What the state holds for the Gate: the pooled project roots and the
    /// facts of every open Threat Finding, absent until a Full Scan of this
    /// version has written them.
    pub fn gate_record(&self) -> Option<GateRecord> {
        self.state
            .lock()
            .expect("the state is not poisoned")
            .gate
            .clone()
    }

    /// The Gate's verdict on one request, from the pooled roots and the Gate
    /// facts the state holds (spec section 7.3). It holds the state only long
    /// enough to read them: it never scans, never reads a Surface and never
    /// waits for a running Scan, which writes the state only at its end. A
    /// block is neither logged nor counted (spec section 7.6), and nothing of
    /// the request is ever written to the log.
    pub fn gate(&self, request: &GateRequest) -> GateVerdict {
        let state = self.state.lock().expect("the state is not poisoned");
        let open_threats: BTreeSet<FindingId> = state
            .open()
            .filter(|finding| finding.category == Category::Threat)
            .map(|finding| finding.id.clone())
            .collect();
        crate::gate_answer::verdict(
            state.gate.as_ref(),
            &open_threats,
            request,
            self.machine.home(),
        )
    }

    /// The project roots the last Scan pooled.
    pub fn pooled_roots(&self) -> Vec<PathBuf> {
        self.roots
            .lock()
            .expect("the roots are not poisoned")
            .clone()
    }

    /// The directories the watcher is following, empty before the first Full
    /// Scan has declared any.
    pub fn watching(&self) -> WatchRoots {
        self.watch
            .lock()
            .expect("the watcher is not poisoned")
            .as_ref()
            .map(|watch| watch.roots().clone())
            .unwrap_or_default()
    }

    /// Every state the machine is in right now.
    pub fn health(&self) -> Health {
        let mut health = self
            .health
            .lock()
            .expect("the health is not poisoned")
            .clone();
        health.scanning = self.queue.lock().expect("the queue is not poisoned").busy();
        health
    }

    /// What a `status` request answers with.
    pub fn status(&self) -> Status {
        let state = self.state.lock().expect("the state is not poisoned");
        Status {
            health: self.health(),
            scan: state.last_scan().cloned(),
            findings: state.findings.clone(),
            overview: state.overview.clone(),
            activity: self
                .activity
                .lock()
                .expect("the Activity is not poisoned")
                .clone(),
        }
    }

    /// Asks for a Full Scan.
    ///
    /// One that is already running or already waiting is joined rather than
    /// started again, which is what "Scan now" during a Full Scan does (spec
    /// section 6.4). Answers with true when this call put one on the queue.
    pub fn scan(self: &Arc<Daemon>, trigger: Trigger) -> bool {
        let mut queue = self.queue.lock().expect("the queue is not poisoned");
        if queue.running == Some(ScanKind::Full) || queue.full.is_some() {
            return false;
        }
        queue.full = Some(trigger);
        let start = queue.claim_the_thread();
        drop(queue);
        if start {
            self.work();
        }
        true
    }

    /// Asks for a Change Scan of one debounced batch of changed paths.
    ///
    /// A batch that arrives while a Full Scan is waiting is absorbed by it;
    /// two batches that arrive while a Scan is running are one batch by the
    /// time it is over.
    pub fn change(self: &Arc<Daemon>, batch: Batch) {
        let mut queue = self.queue.lock().expect("the queue is not poisoned");
        if queue.full.is_some() {
            return;
        }
        for path in batch.paths() {
            queue.batch.also(path.to_path_buf());
        }
        let start = queue.claim_the_thread();
        drop(queue);
        if start {
            self.work();
        }
    }

    /// Starts the thread that empties the queue, one Scan at a time.
    fn work(self: &Arc<Daemon>) {
        let daemon = Arc::clone(self);
        std::thread::Builder::new()
            .name("agentsweep-scan".to_string())
            .spawn(move || {
                loop {
                    let work = {
                        let mut queue = daemon.queue.lock().expect("the queue is not poisoned");
                        // A daemon whose bundle was replaced takes nothing
                        // more: the Scan it was running is finished, and the
                        // new binary runs the next one.
                        let next = match daemon.is_leaving() {
                            true => {
                                queue.running = None;
                                queue.draining = false;
                                None
                            }
                            false => queue.next(),
                        };
                        match next {
                            Some(work) => work,
                            None => {
                                drop(queue);
                                daemon.tell_health();
                                return;
                            }
                        }
                    };
                    daemon.tell_health();
                    daemon.carry_out(work);
                }
            })
            .expect("the Scan thread starts");
    }

    /// Runs one piece of work and takes what it decided.
    fn carry_out(self: &Arc<Daemon>, work: Work) {
        // A Scan writes the Baseline and may write the Event Log, so no action
        // runs while it does, and it waits for one that is running.
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let previous = self
            .raised
            .lock()
            .expect("the last Scan is not poisoned")
            .clone();
        let watching = Watching(Arc::clone(self));
        // The pack in force when the Scan starts is the one it runs to the
        // end; a pack accepted meanwhile asks for the Full Scan after it.
        let pack = self.pack_in_force();
        // So is the Judgement Engine: its Verdicts are looked up, and its name
        // and model key the evaluation cache, under what was active at the
        // start.
        let judge = self.judge_in_force();
        match work {
            Work::Full(trigger) => {
                self.record_the_pack_change(&pack);
                self.publish(StateEvent::ScanStarted {
                    trigger,
                    at: Timestamp::now(),
                });
                // A Scan the user asked for may use more of the machine than
                // one nobody is waiting for (spec section 6.4).
                let workers = match trigger {
                    Trigger::ScanNow | Trigger::Folder => on_demand_workers(),
                    _ => self.tuning.workers,
                };
                let readable = self.readable_classes();
                let run = FullScan {
                    machine: &self.machine_in_force(),
                    access: Access {
                        readable: &readable,
                        folders: &*self.tuning.folders,
                    },
                    directory: &self.directory,
                    keys: &*self.keys,
                    pack: &pack.rules,
                    manifest: &pack.manifest,
                    previous: &previous,
                    cache: &*self.cache,
                    judge: judge.as_ref(),
                    workers,
                    progress: &watching,
                    acts: true,
                    // The Gate is always on until its switch arrives.
                    gate: self.tuning.gate.as_ref(),
                }
                .run(trigger);
                match run {
                    Ok(run) => self.took(run),
                    Err(error) => say!("the Full Scan failed: {error}"),
                }
            }
            Work::Change(batch) => {
                let at = Timestamp::now();
                let pooled = self.pooled_roots();
                let readable = self.readable_classes();
                let run = ChangeScan {
                    machine: &self.machine_in_force(),
                    access: Access {
                        readable: &readable,
                        folders: &*self.tuning.folders,
                    },
                    directory: &self.directory,
                    keys: &*self.keys,
                    pack: &pack.rules,
                    manifest: &pack.manifest,
                    previous: &previous,
                    pooled: &pooled,
                    cache: &*self.cache,
                    judge: judge.as_ref(),
                    workers: self.tuning.workers,
                    acts: true,
                }
                .run(&batch);
                match run {
                    // A batch about no Item is not a Scan, so nobody is told
                    // one started: the start is published here rather than
                    // before the batch is mapped, because only the mapping can
                    // say whether there was anything to scan.
                    Ok(None) => {}
                    Ok(Some(run)) => {
                        self.publish(StateEvent::ScanStarted {
                            trigger: Trigger::Watcher,
                            at,
                        });
                        self.took(run);
                    }
                    Err(error) => say!("the Change Scan failed: {error}"),
                }
            }
        }
    }

    /// Takes what one Scan decided: the cached state, the health and the
    /// events every subscriber is sent.
    ///
    /// A Full Scan speaks for everything and replaces the lot. A Change Scan
    /// speaks only for the Items it looked at, so what it says is put in among
    /// what stands about the rest.
    fn took(self: &Arc<Daemon>, run: ScanRun) {
        let whole = run.summary.kind == ScanKind::Full;
        // A key that went missing while the daemon ran restarted the chain
        // this Scan opened, and that restart waits for an answer too.
        let reset = {
            let mut reset = self.reset.lock().expect("the reset is not poisoned");
            reset.events |= run.events == ChainState::KeyMissing;
            reset.baseline |= run.baseline == ChainState::KeyMissing;
            *reset
        };
        let mut changed: Vec<(FindingId, String, Option<Box<RecordedFinding>>)> = Vec::new();
        let mut overview_changed = None;
        {
            let mut state = self.state.lock().expect("the state is not poisoned");
            let before: BTreeMap<FindingId, String> = state
                .findings
                .iter()
                .map(|finding| (finding.id.clone(), finding.state.to_string()))
                .collect();

            let at = run.summary.started_at;
            let mut findings: Vec<RecordedFinding> = match whole {
                true => Vec::new(),
                false => state
                    .findings
                    .iter()
                    .filter(|finding| !run.looked_at.contains(&finding.item_id))
                    .cloned()
                    .collect(),
            };
            findings.extend(run.standing.iter().map(|found| {
                let first_seen = state.first_seen(&found.id).unwrap_or(at);
                let notified = state.notified_at(&found.id);
                let mut recorded = RecordedFinding::of(found, first_seen).notified(notified);
                if let Some(fixed) = run.fixed_versions.get(&recorded.receipt_id) {
                    recorded.fixed_version = fixed.clone();
                }
                recorded.switched = run.switched.contains(&recorded.id);
                if let Some(facts) = run.facts.get(&recorded.id) {
                    recorded.facts = facts.clone();
                }
                recorded
            }));

            for finding in &findings {
                let now = finding.state.to_string();
                if before.get(&finding.id) != Some(&now) {
                    changed.push((finding.id.clone(), now, Some(Box::new(finding.clone()))));
                }
            }
            // A Finding the last Scan knew and this one did not derive at all
            // is gone, and the Activity keeps it.
            for id in before.keys() {
                if !findings.iter().any(|finding| &finding.id == id) {
                    changed.push((id.clone(), "gone".to_string(), None));
                }
            }

            state.findings = findings;
            // The Gate answers from what is written here (spec section 7.3).
            // A Full Scan writes all of it. A Change Scan moves the pooled
            // roots and the facts of the Items it looked at, and only once a
            // Full Scan has written the rest: an older state file read at
            // start has none, and stays "state unavailable" until then.
            match (whole, state.gate.as_mut()) {
                (true, _) => {
                    state.gate = Some(GateRecord {
                        roots: run.roots.clone(),
                        facts: run.gate_facts.clone(),
                    });
                }
                (false, Some(gate)) => {
                    gate.roots = run.roots.clone();
                    gate.facts.extend(run.gate_facts.clone());
                }
                (false, None) => {}
            }
            state.prune_gate_facts();
            // A Full Scan speaks for every Agent, root and Item; a Change Scan
            // only for the Ambiguous Items among the ones it looked at.
            let overview_before = state.overview.clone();
            match whole {
                true => state.overview = run.overview.clone(),
                false => {
                    state
                        .overview
                        .take_change(&run.looked_at, &run.overview.ambiguous);
                    state
                        .overview
                        .take_checked(&run.looked_at, &run.overview.checked);
                    state.overview.take_project_hooks(&run.project_hooks);
                }
            }
            if state.overview != overview_before {
                overview_changed = Some(Box::new(state.overview.clone()));
            }
            state.record_scan(run.summary.clone());
            let file = StateFile::in_data_directory(&self.directory);
            if let Err(error) = StateWriter::write(&file, &*self.keys, &state) {
                say!("the cached state could not be written: {error}");
            }

            let mut health = self.health.lock().expect("the health is not poisoned");
            health.events = crate::integrity::shown(&run.events, reset.events);
            health.baseline = crate::integrity::shown(&run.baseline, reset.baseline);
            health.last_full_scan = state.last_full_scan;
            // Only a Full Scan knows how many Items there are; a Change Scan
            // counted the handful it was told about.
            if whole {
                health.items = run.summary.items;
                health.projects_need_permission =
                    crate::permission::needing_permission(&state.overview);
            }
            // A project leaves the count on the first Scan that looks at it
            // once its switch is cleared.
            health.projects_gate_off = state.overview.projects_gate_off();
            // A line clears on the first Full Scan whose check passes.
            if let Some(lines) = &run.gate_lines {
                health.gate_lines = lines.clone();
            }
            health.count_open(&state);
        }

        {
            let mut raised = self.raised.lock().expect("the last Scan is not poisoned");
            let mut kept: Vec<Finding> = match whole {
                true => Vec::new(),
                false => raised
                    .iter()
                    .filter(|finding| !run.looked_at.contains(&finding.item_id))
                    .cloned()
                    .collect(),
            };
            kept.extend(run.raised.iter().cloned());
            *raised = kept;
        }

        *self.roots.lock().expect("the roots are not poisoned") = run.roots.clone();

        say!(
            "{} Scan ({}): {} Items, {} Findings, {} ms, {} project roots",
            run.summary.kind,
            run.summary.trigger,
            run.summary.items,
            run.summary.findings(),
            run.summary.duration_ms,
            run.roots.len()
        );
        if run.events != ChainState::Intact || run.baseline != ChainState::Intact {
            say!(
                "the chains say: events {:?}, baseline {:?}",
                run.events,
                run.baseline
            );
        }
        for (id, state, finding) in changed {
            self.publish(StateEvent::FindingChanged { id, state, finding });
        }
        if let Some(overview) = overview_changed {
            self.publish(StateEvent::OverviewChanged { overview });
        }
        // Only a Full Scan recomputes the watch roots, and housekeeping runs
        // behind one and behind nothing else.
        if whole {
            // A Full Scan saw every Item there is, so an outcome it did not
            // ask about is one for content that is no longer anywhere.
            self.cache.sweep();
            self.follow(&run.watch_roots);
            self.compact(&run);
            self.compact_the_verdicts(&run);
        }

        self.publish(StateEvent::ScanFinished {
            summary: Box::new(run.summary),
        });
        self.tell_health();
    }

    /// Points the watcher at the roots this Full Scan declared.
    ///
    /// The old watcher is dropped first, because a root may have gone away
    /// with the Scan that stopped declaring it and FSEvents keeps following a
    /// stream nobody asked about any more.
    fn follow(self: &Arc<Daemon>, roots: &WatchRoots) {
        let mut held = self.watch.lock().expect("the watcher is not poisoned");
        // The old one goes before the new one starts, so no batch is ever
        // reported twice and no stream is left following a root this Scan
        // stopped declaring.
        *held = None;
        let weak = Arc::downgrade(self);
        let started = watcher::watch(roots, self.tuning.watch, move |decision| {
            if let Some(daemon) = weak.upgrade() {
                daemon.noticed(decision);
            }
        });
        match started {
            Ok(watch) => {
                say!(
                    "watching {} of {} declared roots",
                    watch.following(),
                    roots.all().count()
                );
                *held = Some(watch);
            }
            // A watcher that will not start is not a reason to stop
            // protecting: the daily Full Scan still runs.
            Err(error) => say!("{error}"),
        }
    }

    /// What one debounced batch is worth, decided by the watcher and acted on
    /// here.
    ///
    /// The seam between the two: the watcher works out what a batch means and
    /// this carries it out, so a test can hand over a decision no real file
    /// system would make it wait for.
    pub fn noticed(self: &Arc<Daemon>, decision: Decision) {
        match decision {
            Decision::Nothing => {}
            Decision::Change(batch) => {
                say!("{} paths changed", batch.len());
                self.change(batch);
            }
            Decision::Full(why) => {
                say!("a Full Scan because {why}");
                self.scan(Trigger::Watcher);
            }
        }
    }

    /// Compacts the Baseline behind a completed Full Scan, at most once a day
    /// (spec section 4.6.6).
    fn compact(self: &Arc<Daemon>, run: &ScanRun) {
        let at = Timestamp::now();
        if !baseline::compaction_due(run.last_compaction, at) {
            return;
        }
        if run.baseline != ChainState::Intact {
            return;
        }
        // A compaction writes the Baseline afresh, restart records and all,
        // so it waits until a reset of the protection state is answered.
        if self.reset.lock().expect("the reset is not poisoned").any() {
            return;
        }
        let live: BTreeSet<String> = run
            .roots
            .iter()
            .map(|root| Scope::Project(root.clone()).id_segment())
            .collect();
        // Only an open Threat Finding keeps a record compaction would drop
        // otherwise, because only a Threat Finding holds the accepted hash.
        let retention = Retention::of(live)
            .held_by(self.state.lock().expect("the state is not poisoned").open());

        let baseline = agentsweep_core::baseline::Baseline::in_data_directory(&self.directory);
        let Ok(view) = baseline.read(&*self.keys) else {
            return;
        };
        let plan = agentsweep_core::baseline::CompactionPlan::of(&view, &retention, at);
        if plan.changes_nothing() {
            return;
        }
        match baseline::compact(&self.directory, &*self.keys, &retention, at) {
            Ok(done) => say!(
                "the Baseline was compacted: {} records dropped, {} stretches of coverage dropped",
                done.plan.dropped.len(),
                done.plan.uncovered.len()
            ),
            Err(error) => say!("the Baseline could not be compacted: {error}"),
        }
    }

    /// Compacts the Verdict cache behind a completed Full Scan, at most once
    /// a day: a Verdict whose model id or prompt version no longer matches an
    /// installed engine is dropped, and one `verdicts-compacted` event anchors
    /// the compacted file in the Event Log (spec sections 4.6.6 and 6.9).
    fn compact_the_verdicts(self: &Arc<Daemon>, run: &ScanRun) {
        if run.events != ChainState::Intact {
            return;
        }
        if self.reset.lock().expect("the reset is not poisoned").any() {
            return;
        }
        let at = Timestamp::now();
        let last = match EventLog::in_data_directory(&self.directory).read(&*self.keys) {
            Ok(view) => view
                .events
                .iter()
                .filter(|recorded| recorded.event.action == Action::VerdictsCompacted)
                .map(|recorded| recorded.recorded_at)
                .next_back(),
            Err(error) => {
                say!("the Event Log could not be read for the Verdict cache: {error}");
                return;
            }
        };
        if !baseline::compaction_due(last, at) {
            return;
        }
        let installed = installed_models(&self.judgement());
        match verdicts::compact(&self.directory, &*self.keys, &installed) {
            Ok(Some(done)) => say!(
                "the Verdict cache was compacted: {} records before, {} after",
                done.before,
                done.after
            ),
            Ok(None) => {}
            Err(error) => say!("the Verdict cache could not be compacted: {error}"),
        }
    }

    /// Starts the due check, which asks every fifteen minutes and when the
    /// machine wakes whether the daily Full Scan is due.
    fn check_when_due(self: &Arc<Daemon>) {
        let weak = Arc::downgrade(self);
        let check = due::every(self.tuning.due.clone(), move |occasion| {
            if let Some(daemon) = weak.upgrade() {
                daemon.asked_whether_due(occasion);
            }
        });
        *self.due.lock().expect("the due check is not poisoned") = Some(check);
    }

    /// Answers the due check: a Full Scan when the last completed one is a day
    /// old, deferred at most three days by Low Power Mode.
    fn asked_whether_due(self: &Arc<Daemon>, occasion: Occasion) {
        let last = self
            .health
            .lock()
            .expect("the health is not poisoned")
            .last_full_scan;
        let saving = self.tuning.power.low_power_mode();
        // The due check's own clock, which is the machine's in the shipped
        // daemon and a test's moment of choosing in the suite.
        let now = (self.tuning.due.now)();
        // The Rule Feed fetch rides along with the due check (spec section
        // 6.4), on its own daily cadence.
        self.fetch_when_due(now);
        if !due::is_due(last, now, saving) {
            return;
        }
        say!("a Full Scan is due ({occasion})");
        self.scan(Trigger::Due);
    }

    /// Sends one event to everyone listening, dropping whoever has gone away.
    pub(crate) fn publish(&self, event: StateEvent) {
        let mut listening = self
            .subscribers
            .lock()
            .expect("the subscribers are not poisoned");
        listening.retain(|subscriber| subscriber.send(event.clone()).is_ok());
    }

    /// Tells every subscriber the Health as it stands now, when it differs
    /// from what they were last told.
    pub(crate) fn tell_health(&self) {
        let health = self.health();
        {
            let mut told = self.told.lock().expect("the told Health is not poisoned");
            if told.as_ref() == Some(&health) {
                return;
            }
            *told = Some(health.clone());
        }
        self.publish(StateEvent::HealthChanged {
            health: Box::new(health),
        });
    }

    /// True once the daemon's own bundle was replaced and it is on its way
    /// out.
    pub fn is_leaving(&self) -> bool {
        self.leaving.load(Ordering::SeqCst)
    }

    /// Stops taking work and waits for the write in hand to finish: a Scan
    /// from start to end, or one action. What the daemon does before it exits
    /// because its bundle was replaced, so no store is left half written and
    /// the new binary starts from records that verify.
    ///
    /// A Scan writes the Baseline and the Event Log for all of its Items at
    /// its end, not Item by Item, so the Scan in hand is the smallest unit
    /// that can be finished without tearing a write.
    pub fn finish_the_work_in_hand(&self) {
        self.leaving.store(true, Ordering::SeqCst);
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
    }

    /// Adds one listener and answers with the end it reads from.
    fn subscribe(&self) -> Receiver<StateEvent> {
        let (sender, receiver) = channel();
        self.subscribers
            .lock()
            .expect("the subscribers are not poisoned")
            .push(sender);
        receiver
    }

    /// Serves one connection until the peer goes away: the handshake, then
    /// requests, or the subscribe stream.
    pub fn serve(self: &Arc<Daemon>, mut connection: Connection) {
        let peer = connection.peer();
        match self.shake_hands(&mut connection) {
            Ok(hello) => say!("a {} of version {} connected", hello.role, hello.version),
            Err(refusal) => {
                say!("refused {peer}: {}", refusal.detail());
                let _ = connection.send(&Message::Refused(refusal));
                return;
            }
        }

        loop {
            let message = match connection.receive() {
                Ok(Some(message)) => message,
                Ok(None) => return,
                Err(error) => {
                    say!("a connection ended: {error}");
                    return;
                }
            };
            let Message::Request { id, request } = message else {
                let _ = connection.send(&Message::Response {
                    id: String::new(),
                    result: Err(RequestError::new(
                        "not-a-request",
                        "only a request may follow the handshake",
                    )),
                });
                return;
            };
            if request == Request::Subscribe {
                let receiver = self.subscribe();
                let _ = connection.send(&Message::Response {
                    id,
                    result: Ok(serde_json::Value::Bool(true)),
                });
                // The stream opens with the Health as it stands, so a
                // subscriber has something to show before anything changes.
                let _ = connection.send(&Message::Event(StateEvent::HealthChanged {
                    health: Box::new(self.health()),
                }));
                // A subscribed connection carries no more requests: the daemon
                // writes events on it until the client goes away.
                for event in receiver {
                    if connection.send(&Message::Event(event)).is_err() {
                        return;
                    }
                }
                return;
            }
            let result = self.answer(&request);
            if connection.send(&Message::Response { id, result }).is_err() {
                return;
            }
        }
    }

    /// The handshake: a version this daemon shares, and a peer it may answer.
    fn shake_hands(self: &Arc<Daemon>, connection: &mut Connection) -> Result<Hello, Refusal> {
        let peer = connection.peer();
        let hello = match connection.receive() {
            Ok(Some(Message::Hello(hello))) => hello,
            Ok(Some(other)) => {
                return Err(Refusal::NotAHandshake {
                    detail: format!("the peer said {} first", name_of(&other)),
                });
            }
            Ok(None) => {
                return Err(Refusal::NotAHandshake {
                    detail: "the peer said nothing".to_string(),
                });
            }
            Err(error) => {
                return Err(Refusal::NotAHandshake {
                    detail: error.to_string(),
                });
            }
        };
        // The version first: a peer of another version is a half-finished
        // update, and saying so is more use than saying it is unsigned.
        check_version(&hello)?;
        self.check.admits(&peer)?;
        connection
            .send(&welcome())
            .map_err(|error| Refusal::NotAHandshake {
                detail: error.to_string(),
            })?;
        Ok(hello)
    }

    /// Carries out one request.
    fn answer(self: &Arc<Daemon>, request: &Request) -> Result<serde_json::Value, RequestError> {
        match request {
            Request::Status => Ok(self.status().to_value()),
            Request::ScanNow => {
                let started = self.scan(Trigger::ScanNow);
                Ok(serde_json::json!({ "started": started }))
            }
            // The reads are made on a thread of their own, never this one:
            // the call may block while the system alert is on screen.
            Request::CheckNow => {
                let started = self.check_now();
                Ok(serde_json::json!({ "started": started }))
            }
            // Handled by the caller, which turns the connection into a stream.
            Request::Subscribe => Ok(serde_json::Value::Bool(true)),
            Request::RuleFeed { enabled } => {
                let enabled = match enabled {
                    Some(enabled) => self.set_rule_feed(*enabled),
                    None => self.rule_feed_enabled(),
                };
                Ok(serde_json::json!({ "enabled": enabled }))
            }
            Request::Sessions => Ok(crate::sessions::detect(self.machine.home()).to_value()),
            // Runs here, on this connection's thread, beside any other Scan,
            // and records nothing.
            Request::Folder { path } => {
                let pack = self.pack_in_force();
                crate::folder_scan::folder_scan(&pack, path).map(|result| result.to_value())
            }
            Request::Engine { change } => self.change_engine(change).map(|state| state.to_value()),
            Request::Settings { change } => {
                self.change_settings(change).map(|state| state.to_value())
            }
            Request::SetClaudeKey { key } => self.set_claude_key(key).map(|state| state.to_value()),
            Request::RemoveClaudeKey => self.remove_claude_key().map(|state| state.to_value()),
            Request::Records { chain, from } => self.records(*chain, *from),
            Request::AcknowledgeKeyMissing => self.acknowledge_key_missing(),
            Request::AcknowledgeChainBroken => self.acknowledge_chain_broken(),
            // Answered here, from what the state holds, beside any Scan.
            Request::Gate(gate) => Ok(self.gate(gate).to_value()),
            // Everything else acts, and is carried out where acting lives.
            _ => self.act(request),
        }
    }
}

/// What one fetch of the Rule Feed came to, as a test and a log line read it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeedOutcome {
    /// There is no feed to ask: a developer run that named none.
    NoFeed,
    /// The toggle is off, so nothing was asked.
    Off,
    /// The index has not changed since the last answer that was acted on.
    Unchanged,
    /// Nothing newer than the pack in use.
    NothingNewer {
        /// The version compared: the index's, or the signed manifest's when
        /// one was downloaded.
        offered: u64,
        /// The version in use.
        in_use: u64,
    },
    /// A newer pack that needs a newer AgentSweep, ignored with the notice.
    NeedsNewerEngine {
        /// Its version.
        offered: u64,
        /// The AgentSweep version it asks for.
        minimum: String,
    },
    /// A newer pack, verified and now in force.
    Accepted {
        /// Its version.
        pack_version: u64,
    },
    /// A pack that was refused, and why.
    Refused(String),
    /// The feed answered and part of the release was missing.
    Incomplete(String),
    /// Nothing answered.
    Unreachable(String),
}

/// The user's choices at start, and whether the settings file could not be
/// read.
///
/// A missing settings file means every default, unless the state file is one
/// written before the settings file existed and still carries the Rule Feed
/// toggle: that toggle is taken over into a new settings file, once, and the
/// state file is written again without it. A settings file that cannot be read
/// back is left as it is and every default is in force, which Health reports.
fn settings_at_start(
    directory: &DataDirectory,
    keys: &dyn KeySource,
    state: &mut State,
) -> (Settings, bool) {
    let file = SettingsFile::in_data_directory(directory);
    match file.read() {
        Ok(settings) => (settings, false),
        Err(SettingsError::Missing) => {
            let Some(rule_feed) = state.legacy_rule_feed.take() else {
                return (Settings::default(), false);
            };
            let settings = Settings {
                rule_feed,
                ..Settings::default()
            };
            match SettingsWriter::write(&file, &settings) {
                Ok(()) => {
                    say!("the Rule Feed toggle moved from the state file to the settings file");
                    let state_file = StateFile::in_data_directory(directory);
                    if let Err(error) = StateWriter::write(&state_file, keys, state) {
                        say!("the cached state could not be written: {error}");
                    }
                }
                Err(error) => say!("the settings file could not be written: {error}"),
            }
            (settings, false)
        }
        Err(error) => {
            say!("every setting is at its default and the settings file is left as it is: {error}");
            (Settings::default(), true)
        }
    }
}

/// A change of the Rule Pack in force that the Event Log is still to hear of.
#[derive(Debug)]
struct PendingPackChange {
    /// The record, with the pack now in force named and nothing yet said
    /// about what it withdrew.
    record: RulePackRecord,
    /// The Rules of the pack in force before, which what it withdrew and what
    /// left Probation are measured against.
    before: PackRules,
    /// The version and origin of that pack: a change that puts it back in
    /// force before any Scan ran without it changed nothing.
    from: (u64, PackOrigin),
}

/// The Rules of one pack by id, with where each stands.
fn rules_of(pack: &RulePack) -> PackRules {
    pack.metas().map(|meta| (meta.id, meta.status)).collect()
}

/// The Activity lines the Event Log keeps: every `rule-pack` record and
/// every `purge`, each with its sequence, in the order written. A log that
/// cannot be read has none to show; its state is the Health's to report.
fn activity_in_the_event_log(directory: &DataDirectory, keys: &dyn KeySource) -> Vec<ActivityLine> {
    match EventLog::in_data_directory(directory).read(keys) {
        Ok(view) => {
            let mut lines: Vec<ActivityLine> = view
                .pack_activity()
                .into_iter()
                .map(|(sequence, recorded_at, line)| ActivityLine {
                    sequence,
                    recorded_at,
                    line,
                })
                .collect();
            lines.extend(crate::actions::purge_activity(&view));
            lines.sort_by_key(|line| (line.recorded_at, line.sequence));
            lines
        }
        Err(error) => {
            say!("the Activity could not be read from the Event Log: {error}");
            Vec::new()
        }
    }
}

/// The Rule Pack in force at start: the stored one when the feed is on and
/// the stored pack verifies and beats the bundled one, the bundled one
/// otherwise. A stored pack that fails verification is discarded, never
/// trusted; one the bundled pack caught up with is thrown away as well.
///
/// A discarded pack is answered with its version and its Rules, both empty
/// when it did not verify, so the change can be recorded.
fn pack_at_start(
    directory: &DataDirectory,
    bundled: &Arc<LoadedPack>,
    state: &mut State,
    feed_on: bool,
) -> (Arc<LoadedPack>, Option<(u64, PackRules)>) {
    // A pack that was ignored for needing a newer AgentSweep is asked for
    // again once this binary is new enough: the validators go, so the next
    // fetch is not answered "unchanged".
    if let Some(ignored) = &state.feed.ignored
        && agentsweep_core::pack::engine_satisfies(
            &ignored.minimum_engine_version,
            agentsweep_core::VERSION,
        )
    {
        state.feed.ignored = None;
        state.feed.etag.clear();
        state.feed.last_modified.clear();
    }
    if !feed_on {
        return (Arc::clone(bundled), None);
    }
    let store = PackStore::in_data_directory(directory);
    match store.read() {
        Ok(None) => (Arc::clone(bundled), None),
        Ok(Some(fetched)) => match judge(
            &fetched.manifest,
            bundled.manifest.pack_version,
            agentsweep_core::VERSION,
        ) {
            Verdict::Accept => {
                say!(
                    "Rule Pack {} from the Rule Feed is in force, released {}",
                    fetched.manifest.pack_version,
                    fetched.manifest.released_at
                );
                (Arc::new(fetched), None)
            }
            verdict => {
                say!("the stored Rule Pack is not used and is discarded: {verdict:?}");
                if let Err(error) = store.discard() {
                    say!("the stored Rule Pack could not be discarded: {error}");
                }
                let discarded = (fetched.manifest.pack_version, rules_of(&fetched.rules));
                (Arc::clone(bundled), Some(discarded))
            }
        },
        Err(error) => {
            say!("the stored Rule Pack does not verify and is discarded: {error}");
            if let Err(error) = store.discard() {
                say!("the stored Rule Pack could not be discarded: {error}");
            }
            (Arc::clone(bundled), Some((0, PackRules::new())))
        }
    }
}

impl Daemon {
    /// Whether the Rule Feed toggle is on.
    pub fn rule_feed_enabled(&self) -> bool {
        self.settings
            .lock()
            .expect("the settings are not poisoned")
            .rule_feed
    }

    /// Moves the Rule Feed toggle and answers with where it stands.
    ///
    /// Off means no request at all and the bundled pack only (spec section
    /// 9.4): a fetched pack in force gives way to the bundled one, with the
    /// Full Scan any change of pack brings. The stored pack stays on disk, so
    /// switching the feed on again puts it back in force without a request.
    /// On asks the feed at once, after the jitter.
    ///
    /// The toggle is written to the settings file, which a rebuilt state file
    /// leaves alone. A settings file that could not be read is written over
    /// here, as by any choice the user makes: the user has just made the
    /// choice it holds. Every subscriber is told the choices as they stand.
    pub fn set_rule_feed(self: &Arc<Daemon>, enabled: bool) -> bool {
        let enabled = self.switch_rule_feed(enabled);
        self.tell_settings();
        enabled
    }

    /// Moves the Rule Feed toggle, as [`Daemon::set_rule_feed`] describes,
    /// without telling subscribers about the choices: the caller does, once.
    pub(crate) fn switch_rule_feed(self: &Arc<Daemon>, enabled: bool) -> bool {
        let _switching = self.switching.lock().expect("the switch is not poisoned");
        let written = {
            let mut settings = self.settings.lock().expect("the settings are not poisoned");
            settings.rule_feed = enabled;
            let file = SettingsFile::in_data_directory(&self.directory);
            match SettingsWriter::write(&file, &settings) {
                Ok(()) => true,
                Err(error) => {
                    say!("the settings file could not be written: {error}");
                    false
                }
            }
        };
        {
            let mut state = self.state.lock().expect("the state is not poisoned");
            if !enabled {
                state.feed.ignored = None;
                state.feed.unreachable_since = None;
            }
            self.write_state(&state);
            let mut health = self.health.lock().expect("the health is not poisoned");
            health.rule_feed = enabled;
            if written {
                health.settings_unreadable = false;
            }
            if !enabled {
                health.ignored_pack = None;
                health.feed_unreachable = None;
            }
        }
        say!(
            "the Rule Feed was switched {}",
            if enabled { "on" } else { "off" }
        );
        self.tell_health();
        let in_force = self.pack_in_force();
        match enabled {
            false => {
                if in_force.origin == PackOrigin::Fetched {
                    self.adopt(Arc::clone(&self.bundled));
                }
            }
            true => {
                let store = PackStore::in_data_directory(&self.directory);
                if let Ok(Some(stored)) = store.read()
                    && judge(
                        &stored.manifest,
                        in_force.manifest.pack_version,
                        agentsweep_core::VERSION,
                    ) == Verdict::Accept
                {
                    self.adopt(Arc::new(stored));
                }
                self.fetch_later();
            }
        }
        enabled
    }

    /// Asks the Rule Feed once, after the jitter, on a thread of its own.
    /// Nothing happens when there is no feed, when the toggle is off, or when
    /// a fetch is already waiting or running.
    pub fn fetch_later(self: &Arc<Daemon>) {
        if self.feed.is_none() || !self.rule_feed_enabled() {
            return;
        }
        if self.fetch_pending.swap(true, Ordering::SeqCst) {
            return;
        }
        let wait = rule_feed::jitter(self.tuning.feed.jitter);
        let weak = Arc::downgrade(self);
        let started = std::thread::Builder::new()
            .name("agentsweep-rule-feed".to_string())
            .spawn(move || {
                std::thread::sleep(wait);
                if let Some(daemon) = weak.upgrade() {
                    daemon.fetch_rule_feed();
                    daemon.fetch_pending.store(false, Ordering::SeqCst);
                }
            });
        if started.is_err() {
            self.fetch_pending.store(false, Ordering::SeqCst);
        }
    }

    /// Asks for a fetch when the last one is a day old, which is how the fetch
    /// rides along with the due check.
    fn fetch_when_due(self: &Arc<Daemon>, now: Timestamp) {
        let last = self
            .state
            .lock()
            .expect("the state is not poisoned")
            .feed
            .last_attempt;
        let every = self.tuning.feed.every.as_millis() as i64;
        let due = last.is_none_or(|last| now.as_unix_ms() - last.as_unix_ms() >= every);
        if due {
            self.fetch_later();
        }
    }

    /// Asks the Rule Feed now and takes what it offers. The one outbound
    /// request the daemon makes, and none at all when the toggle is off.
    pub fn fetch_rule_feed(self: &Arc<Daemon>) -> FeedOutcome {
        let Some(endpoints) = self.feed.clone() else {
            return FeedOutcome::NoFeed;
        };
        let _one = self
            .fetching
            .lock()
            .expect("the fetch lock is not poisoned");
        if !self.rule_feed_enabled() {
            return FeedOutcome::Off;
        }
        let validators = {
            let state = self.state.lock().expect("the state is not poisoned");
            Validators {
                etag: state.feed.etag.clone(),
                last_modified: state.feed.last_modified.clone(),
            }
        };
        let host = endpoints.host();
        let client = FeedClient::new(endpoints);
        let store = PackStore::in_data_directory(&self.directory);
        let in_use = self.pack_in_force().manifest.pack_version;
        let (fetched, keep) = rule_feed::fetch(
            &client,
            &store,
            in_use,
            agentsweep_core::VERSION,
            &validators,
        );
        let now = (self.tuning.due.now)();

        let (outcome, accepted) = match fetched {
            Fetched::Unchanged => (FeedOutcome::Unchanged, None),
            Fetched::NothingNewer { offered, in_use } => {
                (FeedOutcome::NothingNewer { offered, in_use }, None)
            }
            Fetched::NeedsNewerEngine(ignored) => (
                FeedOutcome::NeedsNewerEngine {
                    offered: ignored.pack_version,
                    minimum: ignored.minimum_engine_version.clone(),
                },
                None,
            ),
            Fetched::Accepted(pack) => (
                FeedOutcome::Accepted {
                    pack_version: pack.manifest.pack_version,
                },
                Some(pack),
            ),
            Fetched::Refused(why) => (FeedOutcome::Refused(why), None),
            Fetched::Incomplete(why) => (FeedOutcome::Incomplete(why), None),
            Fetched::Unreachable(why) => (FeedOutcome::Unreachable(why), None),
        };

        {
            let mut state = self.state.lock().expect("the state is not poisoned");
            let feed = &mut state.feed;
            feed.last_attempt = Some(now);
            match &outcome {
                FeedOutcome::Unreachable(_) => {
                    feed.unreachable_since.get_or_insert(now);
                }
                _ => {
                    feed.last_contact = Some(now);
                    feed.unreachable_since = None;
                }
            }
            if let Some(kept) = keep {
                feed.etag = kept.etag;
                feed.last_modified = kept.last_modified;
            }
            match &outcome {
                FeedOutcome::NeedsNewerEngine { offered, minimum } => {
                    feed.ignored = Some(agentsweep_core::state::IgnoredPack {
                        pack_version: *offered,
                        minimum_engine_version: minimum.clone(),
                    });
                }
                // An accepted pack at least as new as the one that was ignored
                // settles the notice.
                FeedOutcome::Accepted { pack_version }
                    if feed
                        .ignored
                        .as_ref()
                        .is_some_and(|ignored| ignored.pack_version <= *pack_version) =>
                {
                    feed.ignored = None;
                }
                _ => {}
            }
            let ignored = feed.ignored.clone();
            let unreachable = Health::feed_unreachable_at(feed.unreachable_since, now);
            self.write_state(&state);
            let mut health = self.health.lock().expect("the health is not poisoned");
            health.ignored_pack = ignored;
            health.feed_unreachable = unreachable;
        }

        say!("the Rule Feed at {host}: {outcome:?}");
        self.tell_health();
        // The toggle may have gone off while the request was on the wire. The
        // pack stays stored for the day it goes on again; off means the
        // bundled pack only.
        let _switching = self.switching.lock().expect("the switch is not poisoned");
        if let Some(pack) = accepted
            && self.rule_feed_enabled()
        {
            self.adopt(Arc::new(*pack));
        }
        outcome
    }

    /// Puts a pack in force: the evaluation cache is emptied, then a Full
    /// Scan runs with the new pack, in that order (spec section 6.4). What the
    /// new pack says about each Finding is decided in that Scan, not here: a
    /// withdrawn Rule's open Findings go, a quarantined Item whose Rule was
    /// withdrawn stays and says so, a Rule that left Probation acts through
    /// the automatic Quarantine every Scan applies.
    ///
    /// Every pack put in force is a change the Event Log records, with what
    /// it withdrew and what left Probation, just before that Full Scan: a
    /// fetched pack as accepted, the bundled pack put back by switching the
    /// Rule Feed off as the stored pack set aside. Its Activity lines are
    /// built from the record. Changes made before the Scan are one change,
    /// measured against the pack the last Scan ran with, and none at all when
    /// they put that pack back in force.
    fn adopt(self: &Arc<Daemon>, pack: Arc<LoadedPack>) {
        {
            let mut pending = self
                .pack_change
                .lock()
                .expect("the pack change is not poisoned");
            let (before, from) = match pending.take() {
                Some(earlier) => (earlier.before, earlier.from),
                None => {
                    let in_force = self.pack_in_force();
                    (
                        rules_of(&in_force.rules),
                        (in_force.manifest.pack_version, in_force.origin),
                    )
                }
            };
            let change = match pack.origin {
                PackOrigin::Fetched => PackChange::Accepted,
                PackOrigin::Bundled => PackChange::SetAside,
            };
            if from != (pack.manifest.pack_version, pack.origin) {
                let record = RulePackRecord::new(
                    change,
                    pack.manifest.pack_version,
                    &pack.manifest.released_at,
                    pack.origin,
                );
                *pending = Some(PendingPackChange {
                    record,
                    before,
                    from,
                });
            }
        }
        {
            let mut health = self.health.lock().expect("the health is not poisoned");
            health.rule_pack = pack.manifest.pack_version;
            health.rule_pack_origin = pack.origin;
            health.rules_released_at = pack.manifest.released_at.clone();
        }
        *self.pack.write().expect("the pack is not poisoned") = pack;
        self.forget_evaluations();
        self.tell_health();
        self.scan_with_the_new_pack();
    }

    /// Writes the change of the Rule Pack that is still to be recorded, when
    /// the pack about to be scanned with is the one it names.
    ///
    /// Runs under the write lock, before the Full Scan the change brings: the
    /// Findings the withdrawn Rules take with them are the ones the last Scan
    /// left, which is what that Scan turns gone. The Activity lines are built
    /// from the record and sent with its sequence.
    fn record_the_pack_change(&self, pack: &LoadedPack) {
        let pending = self
            .pack_change
            .lock()
            .expect("the pack change is not poisoned")
            .take();
        let Some(pending) = pending else {
            return;
        };
        if pending.record.pack_version != pack.manifest.pack_version
            || pending.record.origin != pack.origin
        {
            return;
        }
        let mut record = pending
            .record
            .comparing(&pending.before, &rules_of(&pack.rules));
        record.gone = self
            .state
            .lock()
            .expect("the state is not poisoned")
            .findings
            .iter()
            .filter(|finding| finding.rule_id != 0 && record.withdrawn.contains(&finding.rule_id))
            .filter(|finding| !matches!(finding.state, FindingState::Stopped | FindingState::Gone))
            .map(|finding| finding.id.clone())
            .collect();
        let written = open_the_event_log(&self.directory, &*self.keys)
            .and_then(|(mut writer, _)| writer.record_rule_pack(&record));
        let envelope = match written {
            Ok(envelope) => envelope,
            Err(error) => {
                say!("the change of the Rule Pack could not be recorded: {error}");
                return;
            }
        };
        let lines: Vec<ActivityLine> = record
            .activity()
            .into_iter()
            .map(|line| ActivityLine {
                sequence: envelope.sequence,
                recorded_at: envelope.recorded_at,
                line,
            })
            .collect();
        self.activity
            .lock()
            .expect("the Activity is not poisoned")
            .extend(lines.iter().cloned());
        for line in lines {
            say!("{}", line.line);
            self.publish(StateEvent::Activity {
                line: line.line,
                sequence: Some(line.sequence),
            });
        }
    }

    /// Keeps one Activity line an action's record stands for and sends it to
    /// every subscriber with that record's sequence.
    pub(crate) fn note_activity(&self, line: ActivityLine) {
        say!("{}", line.line);
        self.activity
            .lock()
            .expect("the Activity is not poisoned")
            .push(line.clone());
        self.publish(StateEvent::Activity {
            line: line.line,
            sequence: Some(line.sequence),
        });
    }

    /// Asks for the Full Scan a new pack brings. One that is waiting will run
    /// with the new pack anyway and is joined; one that is running started
    /// with the old pack, so another is put behind it.
    fn scan_with_the_new_pack(self: &Arc<Daemon>) {
        self.scan_behind(Trigger::RulePack);
    }

    /// Asks for a Full Scan that starts after anything that is running now:
    /// one that is waiting is joined, one that is running started before
    /// whatever asks for this one, so another is put behind it.
    pub(crate) fn scan_behind(self: &Arc<Daemon>, trigger: Trigger) {
        let mut queue = self.queue.lock().expect("the queue is not poisoned");
        if queue.full.is_none() {
            queue.full = Some(trigger);
        }
        let start = queue.claim_the_thread();
        drop(queue);
        if start {
            self.work();
        }
    }

    /// Writes the state file, saying so when it could not be written.
    pub(crate) fn write_state(&self, state: &State) {
        let file = StateFile::in_data_directory(&self.directory);
        if let Err(error) = StateWriter::write(&file, &*self.keys, state) {
            say!("the cached state could not be written: {error}");
        }
    }
}

/// What a message is called in a log line, which is its kind and nothing else.
fn name_of(message: &Message) -> &'static str {
    match message {
        Message::Hello(_) => "a handshake",
        Message::Welcome { .. } => "a welcome",
        Message::Refused(_) => "a refusal",
        Message::Request { .. } => "a request",
        Message::Response { .. } => "a response",
        Message::Event(_) => "an event",
    }
}

/// The progress of a Scan, as its subscribers see it.
struct Watching(Arc<Daemon>);

impl Progress for Watching {
    fn at(&self, done: usize, total: usize) {
        self.0.publish(StateEvent::ScanProgress { done, total });
    }
}

/// The key source the shipped daemon uses: the item in the login Keychain.
#[cfg(target_os = "macos")]
fn keychain() -> agentsweep_core::keychain::LoginKeychain {
    agentsweep_core::keychain::LoginKeychain::for_the_daemon()
}

/// The key source a build without a login Keychain uses.
///
/// There is no Keychain off macOS, and the integration layer for the other
/// platforms is a later effort (spec section 6.1). A key that lives only as
/// long as the process is the honest stand-in: nothing is written that a later
/// run would fail to verify, because nothing is kept.
#[cfg(not(target_os = "macos"))]
fn keychain() -> MemoryKeySource {
    MemoryKeySource::empty()
}

/// A daemon that is listening, with the socket it is listening on.
pub struct Running {
    daemon: Arc<Daemon>,
    listener: Arc<SocketListener>,
    /// The watch on the daemon's own bundle, absent when it runs out of none.
    _bundle: Option<BundleWatch>,
}

impl Running {
    /// The daemon itself.
    pub fn daemon(&self) -> &Arc<Daemon> {
        &self.daemon
    }

    /// Where it is listening.
    pub fn socket(&self) -> &std::path::Path {
        self.listener.path()
    }

    /// Answers connections until the process is stopped.
    pub fn serve_forever(&self) {
        loop {
            match self.listener.accept() {
                Ok(connection) => {
                    let daemon = Arc::clone(&self.daemon);
                    std::thread::spawn(move || daemon.serve(connection));
                }
                Err(error) => {
                    say!("the socket could not be read: {error}");
                    return;
                }
            }
        }
    }

    /// Answers connections on a thread of its own, for a caller that has
    /// something else to do. Dropping the handle stops the daemon answering.
    pub fn serve_in_the_background(self) -> Background {
        let stopping = Arc::new(AtomicBool::new(false));
        let listener = Arc::clone(&self.listener);
        let daemon = Arc::clone(&self.daemon);
        let flag = Arc::clone(&stopping);
        let handle = std::thread::spawn(move || {
            while let Ok(connection) = listener.accept() {
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                let daemon = Arc::clone(&daemon);
                std::thread::spawn(move || daemon.serve(connection));
            }
        });
        Background {
            daemon: self.daemon,
            listener: self.listener,
            _bundle: self._bundle,
            stopping,
            handle: Some(handle),
        }
    }
}

/// A daemon answering on a thread of its own.
pub struct Background {
    daemon: Arc<Daemon>,
    listener: Arc<SocketListener>,
    _bundle: Option<BundleWatch>,
    stopping: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Background {
    /// The daemon itself.
    pub fn daemon(&self) -> &Arc<Daemon> {
        &self.daemon
    }

    /// Where it is listening.
    pub fn socket(&self) -> std::path::PathBuf {
        self.listener.path().to_path_buf()
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        // The accept loop is asleep in the operating system, so it is told to
        // stop and then woken by one connection of this thread's own. A
        // subscriber that is still reading keeps its own thread and ends with
        // the process.
        self.stopping.store(true, Ordering::SeqCst);
        let _ = agentsweep_ipc::socket::connect(self.listener.path());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Opens the stores, binds the socket and runs the Full Scan every start runs.
pub fn start(options: &Options) -> Result<Running, Box<dyn Error>> {
    start_with(options, Daemon::open(options)?)
}

/// The same for a daemon the caller opened, which is how a test starts one
/// with a peer check and a key source of its own.
pub fn start_with(options: &Options, daemon: Arc<Daemon>) -> Result<Running, Box<dyn Error>> {
    let listener = SocketListener::bind(&options.socket)?;
    say!(
        "{} listening on {}",
        agentsweep_core::VERSION,
        listener.path().display()
    );
    if options.is_developer_run() {
        say!(
            "a developer run: home {}, data {}, key source {}",
            daemon.machine.home().display(),
            options.data_dir.root().display(),
            options.key_source.as_str()
        );
    }
    say!("the peer check is {}", daemon.check.describe());
    // The Full Scan every start runs is asked for first, so a due check that
    // asks before it has finished joins it rather than taking its place. The
    // watcher starts behind that Scan, because nothing has declared a watch
    // root yet.
    daemon.scan(Trigger::DaemonStart);
    daemon.check_when_due();
    match &daemon.feed {
        Some(feed) => say!("the Rule Feed is asked at {}", feed.host()),
        None => say!("the Rule Feed is not asked in a developer run that names none"),
    }
    daemon.fetch_later();
    let bundle = watch_the_bundle(&daemon, &options.socket);
    Ok(Running {
        daemon,
        listener: Arc::new(listener),
        _bundle: bundle,
    })
}

/// Starts watching the daemon's own executable and bundle, when it runs out
/// of one (spec section 9.5).
fn watch_the_bundle(daemon: &Arc<Daemon>, socket: &std::path::Path) -> Option<BundleWatch> {
    let Some(own) = Own::this_process() else {
        say!("not running out of an app bundle, so no bundle is watched");
        return None;
    };
    say!("watching its own bundle at {}", own.bundle.display());
    let daemon = Arc::clone(daemon);
    let socket = socket.to_path_buf();
    let bundle = own.bundle.clone();
    Some(bundle_watch::watch(
        own,
        bundle_watch::GRACE,
        bundle_watch::BACKSTOP,
        move |change| leave(&daemon, change, &bundle, &socket),
    ))
}

/// Exits because the bundle changed, once the work in hand is finished.
///
/// Replaced exits with [`bundle_watch::EXIT_REPLACED`], which `KeepAlive`
/// answers by starting the binary that is there now; gone exits with zero,
/// which it answers by leaving the daemon down. A bundle judged gone is
/// looked at once more after the work in hand: one back at its path by then
/// was replaced (a rebuild in place outlasts the grace).
fn leave(daemon: &Daemon, change: Change, bundle: &std::path::Path, socket: &std::path::Path) {
    match change {
        Change::Same => return,
        Change::Replaced => say!(
            "the bundle at {} was replaced: finishing the work in hand, then exiting so the new binary starts",
            bundle.display()
        ),
        Change::Gone => say!(
            "the bundle at {} is gone: finishing the work in hand, then exiting for good",
            bundle.display()
        ),
    }
    daemon.finish_the_work_in_hand();
    let last = bundle_watch::at_exit(change, bundle);
    if last != change {
        say!(
            "a bundle is back at {}: it was replaced, so exiting for the new binary to start",
            bundle.display()
        );
    }
    let Some(code) = last.exit_status() else {
        return;
    };
    let _ = std::fs::remove_file(socket);
    say!("exiting with status {code}");
    std::process::exit(code);
}

/// Runs the daemon until the process is stopped.
///
/// It never answers with success: the only successful exit is the one a
/// daemon whose bundle is gone makes, because success is what keeps the
/// launch agent down. A socket that stopped answering is a failure, and
/// `KeepAlive` starts the daemon again.
pub fn run(options: &Options) -> Result<(), Box<dyn Error>> {
    start(options)?.serve_forever();
    Err("the socket stopped answering".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two requests that arrive before the Scan thread has taken the first
    /// start one thread between them, so two Scans never run at once.
    #[test]
    fn only_the_first_request_starts_the_scan_thread() {
        let mut queue = Queue {
            full: Some(Trigger::DaemonStart),
            ..Queue::default()
        };
        assert!(queue.claim_the_thread());
        queue.batch.also(PathBuf::from("/x/a"));
        assert!(!queue.claim_the_thread());

        assert!(matches!(
            queue.next(),
            Some(Work::Full(Trigger::DaemonStart))
        ));
        assert!(!queue.claim_the_thread(), "the thread is still draining");
        assert!(queue.next().is_none());
        assert!(!queue.busy());
        assert!(
            queue.claim_the_thread(),
            "a drained queue needs a new thread"
        );
    }

    /// A pending Full Scan absorbs the Change batches waiting with it, and
    /// batches waiting together merge by path.
    #[test]
    fn a_pending_full_scan_absorbs_the_change_batches() {
        let mut queue = Queue::default();
        queue.batch.also(PathBuf::from("/x/a"));
        queue.batch.also(PathBuf::from("/x/a"));
        queue.batch.also(PathBuf::from("/x/b"));
        assert_eq!(queue.batch.len(), 2);
        queue.full = Some(Trigger::Watcher);
        assert!(matches!(queue.next(), Some(Work::Full(Trigger::Watcher))));
        assert!(queue.batch.is_empty());
        assert!(queue.next().is_none());
    }

    /// An older state file's toggle is taken over into the settings file
    /// once: the state file is written again without it, and a settings file
    /// that exists already is never overwritten by what a state file says.
    #[test]
    fn an_older_state_files_toggle_moves_to_the_settings_file_once() {
        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let directory = DataDirectory::at(temporary.path());
        let keys = MemoryKeySource::empty();
        let older = State {
            legacy_rule_feed: Some(false),
            ..State::empty()
        };

        let mut state = older.clone();
        let (settings, unreadable) = settings_at_start(&directory, &keys, &mut state);
        assert_eq!(
            settings,
            Settings {
                rule_feed: false,
                ..Settings::default()
            }
        );
        assert!(!unreadable);
        assert_eq!(state.legacy_rule_feed, None);
        let settings_file = SettingsFile::in_data_directory(&directory);
        assert_eq!(settings_file.read().expect("a settings file"), settings);
        let rewritten = StateFile::in_data_directory(&directory)
            .read(&keys)
            .expect("the state file written again");
        assert_eq!(rewritten.legacy_rule_feed, None);

        // The user switches the feed on; a stale state file that still says
        // off does not win.
        SettingsWriter::write(&settings_file, &Settings::default()).expect("on");
        let mut stale = older;
        let (settings, _) = settings_at_start(&directory, &keys, &mut stale);
        assert!(settings.rule_feed);
        assert!(settings_file.read().expect("a settings file").rule_feed);
    }

    /// A state file with no toggle and no settings file means every default,
    /// and nothing is written.
    #[test]
    fn no_settings_file_and_no_older_toggle_means_every_default() {
        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let directory = DataDirectory::at(temporary.path());
        let keys = MemoryKeySource::empty();
        let (settings, unreadable) = settings_at_start(&directory, &keys, &mut State::empty());
        assert_eq!(settings, Settings::default());
        assert!(!unreadable);
        assert!(!directory.settings_file().exists());
    }
}
