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
//! and a few locks rather than a runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use agentsweep_core::adapter::WatchRoots;
use agentsweep_core::baseline::{self, Retention};
use agentsweep_core::chain::ChainState;
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::evaluation::EvaluationCache;
use agentsweep_core::finding::{Finding, FindingId};
use agentsweep_core::health::{Health, Protection, StateFileHealth};
use agentsweep_core::item::{ItemId, Scope};
use agentsweep_core::keychain::{KeySource, MemoryKeySource};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::scan_pass::{BACKGROUND_WORKERS, ScanKind, on_demand_workers};
use agentsweep_core::state::{RecordedFinding, State, StateFile, StateWriter, Trigger};
use agentsweep_ipc::peer::PeerCheck;
use agentsweep_ipc::protocol::{
    Hello, Message, Refusal, Request, RequestError, StateEvent, Status, check_version, welcome,
};
use agentsweep_ipc::socket::{Connection, SocketListener};

use crate::change_scan::ChangeScan;
use crate::due::{self, Occasion, PowerState, Schedule, SystemPower};
use crate::full_scan::{FullScan, Progress, ScanRun};
use crate::machine::Machine;
use crate::options::{KeySourceChoice, Options};
use crate::stores::{open_the_baseline, open_the_event_log};
use crate::watcher::{self, Batch, Decision, Timings, Watch};

/// Writes one line to the standard error stream.
///
/// The daemon's real log is `tracing` to a rotated file, which arrives with
/// the application milestone. Until then a hand run reads its own output. A
/// line names paths and ids and never content or a sensitive field (spec
/// section 6.9).
macro_rules! say {
    ($($argument:tt)*) => {
        eprintln!("{} agentsweepd {}", agentsweep_core::envelope::Timestamp::now(), format_args!($($argument)*))
    };
}

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
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning {
            watch: Timings::default(),
            due: Schedule::default(),
            power: Arc::new(SystemPower),
            workers: BACKGROUND_WORKERS,
        }
    }
}

impl std::fmt::Debug for Tuning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuning")
            .field("watch", &self.watch)
            .field("due", &self.due)
            .field("workers", &self.workers)
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
        None
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
    directory: DataDirectory,
    keys: Box<dyn KeySource + Send + Sync>,
    machine: Machine,
    check: Arc<dyn PeerCheck>,
    tuning: Tuning,
    /// The cached derivation, which is what a client is answered out of.
    state: Mutex<State>,
    /// Every state a client is shown, by the precedence of spec section 6.6.
    health: Mutex<Health>,
    /// The Findings the last Scan raised, which the next one compares against
    /// to know what is gone. Never stored: a restart derives them again.
    raised: Mutex<Vec<Finding>>,
    /// What has been asked for, and what is running.
    queue: Mutex<Queue>,
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
        let (_, events) = open_the_event_log(&directory, &*keys)?;
        let (_, baseline) = open_the_baseline(&directory, &*keys)?;

        let file = StateFile::in_data_directory(&directory);
        let (state, state_file) = match file.read(&*keys) {
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

        let health = Health {
            protection: Protection::On,
            events,
            baseline,
            projects_need_permission: 0,
            state_file,
            scanning: false,
            last_full_scan: state.last_full_scan,
            items: state.last_scan().map(|scan| scan.items).unwrap_or_default(),
            open_findings: state.open_count(),
        };

        Ok(Arc::new(Daemon {
            directory,
            keys,
            machine,
            check,
            tuning,
            state: Mutex::new(state),
            health: Mutex::new(health),
            raised: Mutex::new(Vec::new()),
            queue: Mutex::new(Queue::default()),
            cache: Arc::new(EvaluationCache::new()),
            roots: Mutex::new(Vec::new()),
            watch: Mutex::new(None),
            due: Mutex::new(None),
            subscribers: Mutex::new(Vec::new()),
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
        let idle = queue.running.is_none();
        drop(queue);
        if idle {
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
        let idle = queue.running.is_none();
        drop(queue);
        if idle {
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
                        match queue.next() {
                            Some(work) => work,
                            None => return,
                        }
                    };
                    daemon.carry_out(work);
                }
            })
            .expect("the Scan thread starts");
    }

    /// Runs one piece of work and takes what it decided.
    fn carry_out(self: &Arc<Daemon>, work: Work) {
        let previous = self
            .raised
            .lock()
            .expect("the last Scan is not poisoned")
            .clone();
        let watching = Watching(Arc::clone(self));
        match work {
            Work::Full(trigger) => {
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
                let run = FullScan {
                    machine: &self.machine,
                    directory: &self.directory,
                    keys: &*self.keys,
                    previous: &previous,
                    cache: &*self.cache,
                    workers,
                    progress: &watching,
                }
                .run(trigger);
                match run {
                    Ok(run) => self.took(run),
                    Err(error) => say!("the Full Scan failed: {error}"),
                }
            }
            Work::Change(batch) => {
                self.publish(StateEvent::ScanStarted {
                    trigger: Trigger::Watcher,
                    at: Timestamp::now(),
                });
                let pooled = self.pooled_roots();
                let run = ChangeScan {
                    machine: &self.machine,
                    directory: &self.directory,
                    keys: &*self.keys,
                    previous: &previous,
                    pooled: &pooled,
                    cache: &*self.cache,
                    workers: self.tuning.workers,
                }
                .run(&batch);
                match run {
                    Ok(run) => self.took(run),
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
        let mut changed: Vec<(FindingId, String)> = Vec::new();
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
                RecordedFinding::of(found, first_seen).notified(notified)
            }));

            for finding in &findings {
                let now = finding.state.to_string();
                if before.get(&finding.id) != Some(&now) {
                    changed.push((finding.id.clone(), now));
                }
            }
            // A Finding the last Scan knew and this one did not derive at all
            // is gone, and the Activity keeps it.
            for id in before.keys() {
                if !findings.iter().any(|finding| &finding.id == id) {
                    changed.push((id.clone(), "gone".to_string()));
                }
            }

            state.findings = findings;
            state.record_scan(run.summary.clone());
            let file = StateFile::in_data_directory(&self.directory);
            if let Err(error) = StateWriter::write(&file, &*self.keys, &state) {
                say!("the cached state could not be written: {error}");
            }

            let mut health = self.health.lock().expect("the health is not poisoned");
            health.events = run.events.clone();
            health.baseline = run.baseline.clone();
            health.last_full_scan = state.last_full_scan;
            // Only a Full Scan knows how many Items there are; a Change Scan
            // counted the handful it was told about.
            if whole {
                health.items = run.summary.items;
            }
            health.open_findings = state.open_count();
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
        for (id, state) in changed {
            self.publish(StateEvent::FindingChanged { id, state });
        }

        // Only a Full Scan recomputes the watch roots, and housekeeping runs
        // behind one and behind nothing else.
        if whole {
            self.follow(&run.watch_roots);
            self.compact(&run);
        }

        self.publish(StateEvent::ScanFinished {
            summary: Box::new(run.summary),
        });
    }

    /// Points the watcher at the roots this Full Scan declared.
    ///
    /// The old watcher is dropped first, because a root may have gone away
    /// with the Scan that stopped declaring it and FSEvents keeps following a
    /// stream nobody asked about any more.
    fn follow(self: &Arc<Daemon>, roots: &WatchRoots) {
        let weak = Arc::downgrade(self);
        let started = watcher::watch(roots, self.tuning.watch, move |decision| {
            if let Some(daemon) = weak.upgrade() {
                daemon.noticed(decision);
            }
        });
        let mut held = self.watch.lock().expect("the watcher is not poisoned");
        *held = None;
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
    fn noticed(self: &Arc<Daemon>, decision: Decision) {
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
        let live: BTreeSet<String> = run
            .roots
            .iter()
            .map(|root| Scope::Project(root.clone()).id_segment())
            .collect();
        let referenced: BTreeSet<ItemId> = self
            .state
            .lock()
            .expect("the state is not poisoned")
            .open()
            .map(|finding| finding.item_id.clone())
            .collect();
        let retention = Retention::of(live).referring_to(referenced);

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
        if !due::is_due(last, Timestamp::now(), saving) {
            return;
        }
        say!("a Full Scan is due ({occasion})");
        self.scan(Trigger::Due);
    }

    /// Sends one event to everyone listening, dropping whoever has gone away.
    fn publish(&self, event: StateEvent) {
        let mut listening = self
            .subscribers
            .lock()
            .expect("the subscribers are not poisoned");
        listening.retain(|subscriber| subscriber.send(event.clone()).is_ok());
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
                // A subscribed connection carries no more requests: the daemon
                // writes events on it until the client goes away.
                for event in receiver {
                    if connection.send(&Message::Event(event)).is_err() {
                        return;
                    }
                }
                return;
            }
            let result = self.answer(request);
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
    fn answer(self: &Arc<Daemon>, request: Request) -> Result<serde_json::Value, RequestError> {
        match request {
            Request::Status => Ok(self.status().to_value()),
            Request::ScanNow => {
                let started = self.scan(Trigger::ScanNow);
                Ok(serde_json::json!({ "started": started }))
            }
            // Handled by the caller, which turns the connection into a stream.
            Request::Subscribe => Ok(serde_json::Value::Bool(true)),
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
            stopping,
            handle: Some(handle),
        }
    }
}

/// A daemon answering on a thread of its own.
pub struct Background {
    daemon: Arc<Daemon>,
    listener: Arc<SocketListener>,
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
    // The due check runs from the start; the watcher starts behind the first
    // Full Scan, because nothing has declared a watch root yet.
    daemon.check_when_due();
    daemon.scan(Trigger::DaemonStart);
    Ok(Running {
        daemon,
        listener: Arc::new(listener),
    })
}

/// Runs the daemon until the process is stopped.
pub fn run(options: &Options) -> Result<(), Box<dyn Error>> {
    start(options)?.serve_forever();
    Ok(())
}
