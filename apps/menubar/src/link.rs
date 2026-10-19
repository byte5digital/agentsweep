//! The app's link to the daemon: one subscription, kept open for as long as
//! the app runs, and the view it turns into.
//!
//! The daemon opens every subscription with the Health as it stands and sends
//! it again whenever it moves, so the popover follows the stream and never
//! polls a daemon that answers. A daemon that does not answer is Protection
//! off at once, and the link tries again every second, which is how the
//! popover recovers when `KeepAlive` brings the daemon back.
//!
//! The handshake is where the version check happens (spec section 9.5): a
//! daemon of another version is from another bundle, and the app re-registers
//! it once per launch, which stops that daemon and starts its own.
//!
//! A daemon that does not answer at all can be the same thing one step
//! earlier: a job SMAppService calls enabled, registered by another bundle
//! version or with a code identity launchd now refuses to spawn. While no
//! daemon answers, the link asks launchd about the job, and re-registers a
//! stale one on the same once-per-launch allowance.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use agentsweep_ipc::protocol::{Refusal, Role, StateEvent};
use agentsweep_ipc::{Client, ClientError};

use crate::popover::{Off, View};
use crate::supervision::{self, ServiceState, Services, Stale};

/// How long the link waits before it asks a daemon that did not answer again.
pub const RETRY: Duration = Duration::from_secs(1);

/// How often, at most, the link asks launchd about the daemon's job while no
/// daemon answers: launchd's own pace between two spawns of a job that keeps
/// failing, so each look can see a new last exit.
pub const JOB_CHECK: Duration = Duration::from_secs(10);

/// How long the popover keeps saying the background item was registered
/// again while the daemon it started has not answered yet; after that, a
/// daemon still silent is Protection off.
pub const REGISTERED_AGAIN: Duration = Duration::from_secs(60);

/// What the link hands to whoever shows it.
#[derive(Clone, Debug, PartialEq)]
pub enum Update {
    /// The popover's view changed.
    View(View),
    /// One state event, for the window that follows Scans and Findings.
    Event(StateEvent),
}

/// Where the link connects.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Socket {
    /// The documented socket of the installed daemon.
    #[default]
    Installed,
    /// Another one, which only a debug build of the app takes, so a developer
    /// runs the app against a daemon started with `--socket`.
    At(PathBuf),
}

impl Socket {
    /// The socket this build of the app connects to: the documented one,
    /// or in a debug build the one `AGENTSWEEP_DEV_SOCKET` names.
    pub fn for_this_build() -> Socket {
        if cfg!(debug_assertions)
            && let Some(path) = std::env::var_os("AGENTSWEEP_DEV_SOCKET").filter(|p| !p.is_empty())
        {
            return Socket::At(PathBuf::from(path));
        }
        Socket::Installed
    }

    /// A new connection to the daemon, shaken hands with as the app.
    pub(crate) fn connect(&self) -> Result<Client, ClientError> {
        match self {
            Socket::Installed => Client::connect(Role::App),
            Socket::At(path) => Client::connect_at(path, Role::App),
        }
    }
}

/// The link, until it is stopped.
pub struct Link {
    socket: Socket,
    services: Arc<dyn Services>,
    retry: Duration,
    stopping: Arc<AtomicBool>,
    /// A daemon of another version, or a stale job, is re-registered once
    /// per launch. A second mismatch means the bundle itself is half updated,
    /// and asking again would only restart the daemon in a loop.
    restarted: bool,
    /// When launchd was last asked about the job.
    job_checked: Option<Instant>,
    /// The stale job this launch registered again, and when.
    registered_again: Option<(Instant, Stale)>,
}

impl Link {
    /// A link to the daemon at `socket`, supervised through `services`.
    pub fn new(socket: Socket, services: Arc<dyn Services>) -> Link {
        Link {
            socket,
            services,
            retry: RETRY,
            stopping: Arc::new(AtomicBool::new(false)),
            restarted: false,
            job_checked: None,
            registered_again: None,
        }
    }

    /// The same, retrying at a pace of the caller's choosing.
    pub fn retrying_every(mut self, retry: Duration) -> Link {
        self.retry = retry;
        self
    }

    /// A flag that stops the link at its next turn.
    pub fn stopper(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stopping)
    }

    /// Follows the daemon until stopped, handing every update to `sink`.
    pub fn run(mut self, sink: impl Fn(Update)) {
        while !self.stopping.load(Ordering::SeqCst) {
            self.once(&sink);
            if self.stopping.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(self.retry);
        }
    }

    /// One connection, from the handshake to the end of its stream.
    pub fn once(&mut self, sink: &impl Fn(Update)) {
        let client = match self.socket.connect() {
            Ok(client) => client,
            Err(ClientError::Refused(Refusal::VersionMismatch { .. })) => {
                sink(Update::View(View::updating()));
                if !self.restarted {
                    self.restarted = true;
                    let _ = supervision::restart_daemon(&*self.services);
                }
                return;
            }
            Err(ClientError::Refused(refusal)) => {
                sink(Update::View(self.off(Off::Refused(refusal.message()))));
                return;
            }
            Err(error) => {
                let view = match self.repair_stale_job() {
                    Some(view) => view,
                    None => self.silent(error.unreachable()),
                };
                sink(Update::View(view));
                return;
            }
        };
        self.registered_again = None;
        let mut stream = match client.subscribe() {
            Ok(stream) => stream,
            Err(error) => {
                sink(Update::View(self.silent(error.unreachable())));
                return;
            }
        };
        loop {
            if self.stopping.load(Ordering::SeqCst) {
                return;
            }
            match stream.next_event() {
                Ok(Some(event)) => {
                    if let StateEvent::HealthChanged { health } = &event {
                        let view = match supervision::off_by_registration(self.services.agent()) {
                            Some(off) => View::off(&off),
                            None => View::of(health),
                        };
                        sink(Update::View(view));
                    }
                    sink(Update::Event(event));
                }
                // The daemon went away: a kill, a crash, or an exit for the
                // new binary. Protection is off until it answers again.
                Ok(None) | Err(_) => {
                    sink(Update::View(
                        self.silent("the daemon stopped answering".to_string()),
                    ));
                    return;
                }
            }
        }
    }

    /// While no daemon answers: re-registers a stale job, once per launch,
    /// and answers with the view that says so for as long as the daemon it
    /// started takes to answer. `None` is a daemon that is merely down.
    fn repair_stale_job(&mut self) -> Option<View> {
        if let Some((at, stale)) = &self.registered_again {
            return (at.elapsed() < REGISTERED_AGAIN).then(|| View::registered_again(stale));
        }
        if self.restarted || !self.services.supervises() {
            return None;
        }
        if self
            .job_checked
            .is_some_and(|checked| checked.elapsed() < JOB_CHECK)
        {
            return None;
        }
        self.job_checked = Some(Instant::now());
        // Only an enabled registration can be stale, so launchd is asked
        // nothing about any other.
        let agent = self.services.agent();
        if agent != ServiceState::Enabled {
            return None;
        }
        let stale = supervision::stale_job(
            agent,
            self.services.job().as_ref(),
            supervision::BUNDLE_VERSION,
        )?;
        self.restarted = true;
        match supervision::restart_daemon(&*self.services) {
            Ok(()) => {
                let view = View::registered_again(&stale);
                self.registered_again = Some((Instant::now(), stale));
                Some(view)
            }
            Err(error) => {
                eprintln!(
                    "agentsweep-menubar: the stale daemon job could not be registered again: {error}"
                );
                None
            }
        }
    }

    /// No daemon answers: "Not watching right now" when the daemon's
    /// registration is enabled, so launchd has a job to start (spec section
    /// 8.6); Protection off otherwise, a developer run among them.
    fn silent(&self, reason: String) -> View {
        match self.services.supervises() && self.services.agent() == ServiceState::Enabled {
            true => View::not_watching(&reason),
            false => self.off(Off::Unreachable(reason)),
        }
    }

    /// Protection off, for the reason the registration gives when it gives
    /// one, and for `otherwise` when it does not.
    fn off(&self, otherwise: Off) -> View {
        View::off(&supervision::off_by_registration(self.services.agent()).unwrap_or(otherwise))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use agentsweep_core::health::Health;
    use agentsweep_ipc::protocol::{Hello, Message, welcome};
    use agentsweep_ipc::socket::SocketListener;

    use crate::popover::Orb;
    use crate::supervision::tests::Recorded;
    use crate::supervision::{BUNDLE_VERSION, EX_CONFIG, Job, Unsupervised};

    fn socket_in(directory: &tempfile::TempDir) -> PathBuf {
        directory.path().join("agentsweep.sock")
    }

    fn views(updates: &Mutex<Vec<Update>>) -> Vec<View> {
        updates
            .lock()
            .expect("the updates")
            .iter()
            .filter_map(|update| match update {
                Update::View(view) => Some(view.clone()),
                Update::Event(_) => None,
            })
            .collect()
    }

    /// A daemon that answers the handshake and the subscription, then sends
    /// these Health values one after the other and hangs up.
    fn daemon_sending(
        socket: &std::path::Path,
        healths: Vec<Health>,
    ) -> std::thread::JoinHandle<()> {
        let listener = SocketListener::bind(socket).expect("a socket");
        std::thread::spawn(move || {
            let mut connection = listener.accept().expect("a connection");
            match connection.receive().expect("a message") {
                Some(Message::Hello(Hello { role, .. })) => assert_eq!(role, Role::App),
                other => panic!("expected a handshake, got {other:?}"),
            }
            connection.send(&welcome()).expect("a welcome");
            match connection.receive().expect("a message") {
                Some(Message::Request { id, .. }) => connection
                    .send(&Message::Response {
                        id,
                        result: Ok(serde_json::Value::Bool(true)),
                    })
                    .expect("an answer"),
                other => panic!("expected the subscription, got {other:?}"),
            }
            for health in healths {
                connection
                    .send(&Message::Event(StateEvent::HealthChanged {
                        health: Box::new(health),
                    }))
                    .expect("an event");
            }
        })
    }

    /// "Not watching right now" appears only when the registration is
    /// enabled and no daemon answers; it offers Start it, not Login Items.
    #[test]
    fn an_enabled_registration_with_no_daemon_is_not_watching_right_now() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let services = Arc::new(Recorded::with(ServiceState::Enabled, ServiceState::Enabled));
        let mut link = Link::new(Socket::At(socket_in(&directory)), services);
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        let seen = views(&updates);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].banner, Some(crate::banner::Banner::NotWatching));
        assert!(!seen[0].login_items);

        for state in [
            ServiceState::RequiresApproval,
            ServiceState::NotRegistered,
            ServiceState::NotFound,
        ] {
            let services = Arc::new(Recorded::with(state, ServiceState::Enabled));
            let mut link = Link::new(Socket::At(socket_in(&directory)), services);
            let updates = Mutex::new(Vec::new());
            link.once(&|update| updates.lock().expect("the updates").push(update));
            let seen = views(&updates);
            assert!(
                matches!(
                    seen[0].banner,
                    Some(crate::banner::Banner::ProtectionOff { .. })
                ),
                "{state}: {:?}",
                seen[0].banner
            );
            assert!(seen[0].login_items, "{state}");
        }
        let mut link = Link::new(Socket::At(socket_in(&directory)), Arc::new(Unsupervised));
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        assert!(views(&updates)[0].login_items, "a developer run");
    }

    #[test]
    fn a_daemon_that_does_not_answer_is_protection_off_with_login_items() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let services = Arc::new(Recorded::with(
            ServiceState::NotFound,
            ServiceState::Enabled,
        ));
        let mut link = Link::new(Socket::At(socket_in(&directory)), services);
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        let seen = views(&updates);
        assert_eq!(seen.len(), 1);
        assert!(seen[0].protection_off);
        assert!(seen[0].login_items);
        assert_eq!(seen[0].sentence, "Protection is off.");
    }

    /// Every Health the stream carries becomes the popover's view, in order,
    /// and the end of the stream is Protection off.
    #[test]
    fn the_view_follows_the_health_on_the_stream() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let socket = socket_in(&directory);
        let scanning = Health {
            scanning: true,
            ..Health::running()
        };
        let finding = Health {
            open_threats: 1,
            ..Health::running()
        };
        let daemon = daemon_sending(&socket, vec![scanning, finding]);
        let services = Arc::new(Recorded::with(ServiceState::Enabled, ServiceState::Enabled));
        let mut link = Link::new(Socket::At(socket), services);
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        daemon.join().expect("the daemon thread");

        let seen = views(&updates);
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert_eq!(seen[0].sentence, "Checking now.");
        assert_eq!(seen[1].orb, Orb::Attention);
        assert!(seen[2].protection_off, "the daemon hung up");
        let events = updates
            .lock()
            .expect("the updates")
            .iter()
            .filter(|update| matches!(update, Update::Event(StateEvent::HealthChanged { .. })))
            .count();
        assert_eq!(events, 2);
    }

    /// Approval withdrawn in Login Items turns Protection off even while a
    /// daemon still answers.
    #[test]
    fn a_registration_waiting_for_approval_wins_over_a_daemon_that_answers() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let socket = socket_in(&directory);
        let daemon = daemon_sending(&socket, vec![Health::running()]);
        let services = Arc::new(Recorded::with(
            ServiceState::RequiresApproval,
            ServiceState::Enabled,
        ));
        let mut link = Link::new(Socket::At(socket), services);
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        daemon.join().expect("the daemon thread");
        let seen = views(&updates);
        assert!(seen.iter().all(|view| view.protection_off), "{seen:?}");
        assert!(seen[0].detail.contains("approval"), "{}", seen[0].detail);
    }

    /// A daemon of another version is re-registered once, and the popover
    /// says it is updating rather than that Protection is off.
    #[test]
    fn a_version_mismatch_restarts_the_daemon_once() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let socket = socket_in(&directory);
        let listener = SocketListener::bind(&socket).expect("a socket");
        let daemon = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut connection = listener.accept().expect("a connection");
                let _ = connection.receive().expect("a handshake");
                connection
                    .send(&Message::Refused(Refusal::VersionMismatch {
                        daemon_version: "0.0.1".to_string(),
                        peer_version: agentsweep_core::VERSION.to_string(),
                    }))
                    .expect("a refusal");
            }
        });
        let services = Arc::new(Recorded::with(ServiceState::Enabled, ServiceState::Enabled));
        let mut link = Link::new(Socket::At(socket), services.clone());
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        link.once(&|update| updates.lock().expect("the updates").push(update));
        daemon.join().expect("the daemon thread");

        assert_eq!(services.calls(), vec!["unregister agent", "register agent"]);
        let seen = views(&updates);
        assert!(
            seen.iter().all(|view| view.orb == Orb::Updating),
            "{seen:?}"
        );
    }

    fn silent_daemon_with(job: Job) -> (Arc<Recorded>, Link, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let services =
            Arc::new(Recorded::with(ServiceState::Enabled, ServiceState::Enabled).holding(job));
        let link = Link::new(Socket::At(socket_in(&directory)), services.clone());
        (services, link, directory)
    }

    /// The job SMAppService calls enabled was registered by another bundle
    /// version, and no daemon answers: the app registers it again, once, and
    /// the popover says so instead of Protection off.
    #[test]
    fn a_job_of_another_version_with_no_daemon_answering_is_registered_again_once() {
        let (services, mut link, _directory) = silent_daemon_with(Job {
            parent_bundle_version: Some("0.0.1".to_string()),
            last_exit: None,
        });
        let updates = Mutex::new(Vec::new());
        for _ in 0..3 {
            link.once(&|update| updates.lock().expect("the updates").push(update));
        }
        assert_eq!(services.calls(), vec!["unregister agent", "register agent"]);
        let seen = views(&updates);
        assert_eq!(seen.len(), 3);
        for view in &seen {
            assert_eq!(view.orb, Orb::Updating);
            assert!(!view.protection_off);
            assert_eq!(
                view.sentence,
                "AgentSweep registered its background item again."
            );
            assert_eq!(
                view.detail,
                "The background item was registered by version 0.0.1."
            );
        }
    }

    /// A job of the app's own version whose daemon does not answer, within
    /// the KeepAlive window or after it, is Protection off and is left to
    /// launchd.
    #[test]
    fn a_job_of_this_version_with_no_daemon_answering_is_left_alone() {
        for last_exit in [None, Some(0), Some(75), Some(9)] {
            let (services, mut link, _directory) = silent_daemon_with(Job {
                parent_bundle_version: Some(BUNDLE_VERSION.to_string()),
                last_exit,
            });
            // Asked past the pace at which launchd is consulted.
            link.job_checked = Some(Instant::now() - JOB_CHECK * 2);
            let updates = Mutex::new(Vec::new());
            link.once(&|update| updates.lock().expect("the updates").push(update));
            link.once(&|update| updates.lock().expect("the updates").push(update));
            assert!(services.calls().is_empty(), "{last_exit:?}");
            assert!(views(&updates).iter().all(|view| view.protection_off));
        }
    }

    /// launchd refused to spawn the job (exit 78, `EX_CONFIG`), which is what
    /// a new code identity behind an old registration looks like: the app
    /// registers it again, once.
    #[test]
    fn a_job_launchd_cannot_spawn_with_no_daemon_answering_is_registered_again_once() {
        let (services, mut link, _directory) = silent_daemon_with(Job {
            parent_bundle_version: Some(BUNDLE_VERSION.to_string()),
            last_exit: Some(EX_CONFIG),
        });
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        // The fresh job fails again, and the allowance is spent.
        *services.job.lock().expect("the job") = Some(Job {
            parent_bundle_version: Some(BUNDLE_VERSION.to_string()),
            last_exit: Some(EX_CONFIG),
        });
        link.job_checked = Some(Instant::now() - JOB_CHECK * 2);
        link.registered_again = None;
        link.once(&|update| updates.lock().expect("the updates").push(update));
        assert_eq!(services.calls(), vec!["unregister agent", "register agent"]);
        let seen = views(&updates);
        assert_eq!(seen[0].orb, Orb::Updating);
        assert_eq!(
            seen[0].detail,
            "launchd could not start the background item as registered."
        );
        assert!(seen[1].protection_off, "{:?}", seen[1]);
    }

    /// The popover says the item was registered again only for a while: a
    /// daemon that still does not answer after that is Protection off.
    #[test]
    fn a_daemon_silent_long_after_registering_again_is_protection_off() {
        let (_services, mut link, _directory) = silent_daemon_with(Job {
            parent_bundle_version: Some("0.0.1".to_string()),
            last_exit: None,
        });
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        link.registered_again = Some((Instant::now() - REGISTERED_AGAIN * 2, Stale::CannotSpawn));
        link.once(&|update| updates.lock().expect("the updates").push(update));
        let seen = views(&updates);
        assert_eq!(seen[0].orb, Orb::Updating);
        assert!(seen[1].protection_off, "{:?}", seen[1]);
    }

    /// A version mismatch at the handshake and a stale job share the one
    /// re-registration a launch allows.
    #[test]
    fn a_handshake_restart_spends_the_allowance_for_a_stale_job() {
        let (services, mut link, _directory) = silent_daemon_with(Job {
            parent_bundle_version: Some("0.0.1".to_string()),
            last_exit: Some(EX_CONFIG),
        });
        link.restarted = true;
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        assert!(services.calls().is_empty());
        assert!(views(&updates)[0].protection_off);
    }

    /// A developer run supervises nothing, so it never asks launchd and never
    /// registers, whatever a job would say.
    #[test]
    fn a_developer_run_never_registers_a_job_again() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let mut link = Link::new(
            Socket::At(socket_in(&directory)),
            Arc::new(supervision::Unsupervised),
        );
        let updates = Mutex::new(Vec::new());
        link.once(&|update| updates.lock().expect("the updates").push(update));
        assert!(views(&updates)[0].protection_off);
        assert!(link.job_checked.is_none());
    }

    /// The loop itself: a stopped link returns, and while the daemon is away
    /// it keeps saying so at the retry pace.
    #[test]
    fn the_link_retries_until_it_is_stopped() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let services = Arc::new(Recorded::with(ServiceState::Enabled, ServiceState::Enabled));
        let link = Link::new(Socket::At(socket_in(&directory)), services)
            .retrying_every(Duration::from_millis(10));
        let stopper = link.stopper();
        let updates = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&updates);
        let running = std::thread::spawn(move || {
            link.run(|update| {
                let mut all = seen.lock().expect("the updates");
                all.push(update);
                if all.len() >= 3 {
                    stopper.store(true, Ordering::SeqCst);
                }
            })
        });
        running.join().expect("the link stops");
        assert!(views(&updates).len() >= 3);
    }

    #[test]
    fn only_a_debug_build_reads_the_developer_socket() {
        // The variable is not set in the suite, so both builds take the
        // documented socket here; what a debug build does with it set is
        // the one branch above.
        if std::env::var_os("AGENTSWEEP_DEV_SOCKET").is_none() {
            assert_eq!(Socket::for_this_build(), Socket::Installed);
        }
    }
}
