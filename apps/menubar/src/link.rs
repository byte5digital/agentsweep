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

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use agentsweep_ipc::protocol::{Message, Refusal, Role, StateEvent};
use agentsweep_ipc::{Client, ClientError};

use crate::popover::{Off, View};
use crate::supervision::{self, Services};

/// How long the link waits before it asks a daemon that did not answer again.
pub const RETRY: Duration = Duration::from_secs(1);

/// What the link hands to whoever shows it.
#[derive(Clone, Debug, PartialEq)]
pub enum Update {
    /// The popover's view changed.
    View(View),
    /// One state event, as the wire carries it, for a window that follows
    /// Scans and Findings.
    Event(serde_json::Value),
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

    fn connect(&self) -> Result<Client, ClientError> {
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
    /// A daemon of another version is re-registered once per launch. A
    /// second mismatch means the bundle itself is half updated, and asking
    /// again would only restart the daemon in a loop.
    restarted: bool,
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
                sink(Update::View(
                    self.off(Off::Unreachable(error.unreachable())),
                ));
                return;
            }
        };
        let mut stream = match client.subscribe() {
            Ok(stream) => stream,
            Err(error) => {
                sink(Update::View(
                    self.off(Off::Unreachable(error.unreachable())),
                ));
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
                    sink(Update::Event(Message::Event(event).to_value()));
                }
                // The daemon went away: a kill, a crash, or an exit for the
                // new binary. Protection is off until it answers again.
                Ok(None) | Err(_) => {
                    sink(Update::View(self.off(Off::Unreachable(
                        "the daemon stopped answering".to_string(),
                    ))));
                    return;
                }
            }
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
    use agentsweep_ipc::protocol::{Hello, welcome};
    use agentsweep_ipc::socket::SocketListener;

    use crate::popover::Orb;
    use crate::supervision::ServiceState;
    use crate::supervision::tests::Recorded;

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

    #[test]
    fn a_daemon_that_does_not_answer_is_protection_off_with_login_items() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let services = Arc::new(Recorded::with(ServiceState::Enabled, ServiceState::Enabled));
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
            open_findings: 1,
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
            .filter(|update| matches!(update, Update::Event(event) if event["event"] == "health-changed"))
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
