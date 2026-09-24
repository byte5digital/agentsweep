//! The daemon itself: what it holds, what it answers and when it scans.
//!
//! One Full Scan at start, one socket, one Scan at a time. The accept loop and
//! the Scan run on threads of their own, and a connection gets one more, so a
//! client asking for status while a Full Scan is running is answered at once
//! out of what the last Scan left.
//!
//! Nothing here is asynchronous. A Scan is processor-bound and a YARA-X
//! scanner cannot move between threads, so the daemon is a handful of threads
//! and a few locks rather than a runtime.

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use agentsweep_core::chain::ChainState;
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::finding::{Finding, FindingId};
use agentsweep_core::health::{Health, Protection, StateFileHealth};
use agentsweep_core::keychain::{KeySource, MemoryKeySource};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::state::{RecordedFinding, State, StateFile, StateWriter, Trigger};
use agentsweep_ipc::peer::PeerCheck;
use agentsweep_ipc::protocol::{
    Hello, Message, Refusal, Request, RequestError, StateEvent, Status, check_version, welcome,
};
use agentsweep_ipc::socket::{Connection, SocketListener};

use crate::full_scan::{self, Progress, ScanRun};
use crate::machine::Machine;
use crate::options::{KeySourceChoice, Options};
use crate::stores::{open_the_baseline, open_the_event_log};

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

/// Everything the daemon holds while it runs.
pub struct Daemon {
    directory: DataDirectory,
    keys: Box<dyn KeySource + Send + Sync>,
    machine: Machine,
    check: Arc<dyn PeerCheck>,
    /// The cached derivation, which is what a client is answered out of.
    state: Mutex<State>,
    /// Every state a client is shown, by the precedence of spec section 6.6.
    health: Mutex<Health>,
    /// The Findings the last Scan raised, which the next one compares against
    /// to know what is gone. Never stored: a restart derives them again.
    raised: Mutex<Vec<Finding>>,
    /// True while a Scan is running. It is the lock as well as the flag: one
    /// Scan at a time, and "Scan now" during one joins it.
    scanning: AtomicBool,
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
        let directory = options.data_dir.clone();
        directory.create()?;
        let keys: Box<dyn KeySource + Send + Sync> = match options.key_source {
            KeySourceChoice::Keychain => Box::new(keychain()),
            KeySourceChoice::Memory => Box::new(MemoryKeySource::empty()),
        };

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
            state: Mutex::new(state),
            health: Mutex::new(health),
            raised: Mutex::new(Vec::new()),
            scanning: AtomicBool::new(false),
            subscribers: Mutex::new(Vec::new()),
        }))
    }

    /// Every state the machine is in right now.
    pub fn health(&self) -> Health {
        let mut health = self
            .health
            .lock()
            .expect("the health is not poisoned")
            .clone();
        health.scanning = self.scanning.load(Ordering::SeqCst);
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

    /// Runs a Full Scan unless one is already running, which is what "Scan
    /// now" joins rather than starts again (spec section 6.4).
    ///
    /// Answers with true when this call started one.
    pub fn scan(self: &Arc<Daemon>, trigger: Trigger) -> bool {
        if self.scanning.swap(true, Ordering::SeqCst) {
            return false;
        }
        let daemon = Arc::clone(self);
        std::thread::spawn(move || {
            daemon.publish(StateEvent::ScanStarted {
                trigger,
                at: Timestamp::now(),
            });
            let previous = daemon
                .raised
                .lock()
                .expect("the last Scan is not poisoned")
                .clone();
            let watcher = Watching(Arc::clone(&daemon));
            let run = full_scan::run(
                &daemon.machine,
                &daemon.directory,
                &*daemon.keys,
                &previous,
                trigger,
                &watcher,
            );
            match run {
                Ok(run) => daemon.took(run),
                Err(error) => say!("the Full Scan failed: {error}"),
            }
            daemon.scanning.store(false, Ordering::SeqCst);
        });
        true
    }

    /// Takes what one Full Scan decided: the cached state, the health and the
    /// events every subscriber is sent.
    fn took(self: &Arc<Daemon>, run: ScanRun) {
        let mut changed: Vec<(FindingId, String)> = Vec::new();
        {
            let mut state = self.state.lock().expect("the state is not poisoned");
            let before: BTreeMap<FindingId, String> = state
                .findings
                .iter()
                .map(|finding| (finding.id.clone(), finding.state.to_string()))
                .collect();

            let at = run.summary.started_at;
            let findings: Vec<RecordedFinding> = run
                .standing
                .iter()
                .map(|found| {
                    let first_seen = state.first_seen(&found.id).unwrap_or(at);
                    let notified = state.notified_at(&found.id);
                    RecordedFinding::of(found, first_seen).notified(notified)
                })
                .collect();

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
            health.items = run.summary.items;
            health.open_findings = state.open_count();
        }

        *self.raised.lock().expect("the last Scan is not poisoned") = run.raised;

        say!(
            "Full Scan ({}): {} Items, {} Findings, {} ms, {} project roots, {} watch roots",
            run.summary.trigger,
            run.summary.items,
            run.summary.findings(),
            run.summary.duration_ms,
            run.roots.len(),
            run.watch_roots.all().count()
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
        self.publish(StateEvent::ScanFinished {
            summary: Box::new(run.summary),
        });
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
    let daemon = Daemon::open(options)?;
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
