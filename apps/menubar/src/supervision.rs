//! Keeping the daemon registered: SMAppService for the launch agent and for
//! the app as a login item (spec section 9.5).
//!
//! The daemon registers through `SMAppService.agent` from the plist inside the
//! bundle, and the app through `SMAppService.mainApp`. What is decided about
//! them (register what is not registered, re-register on a version mismatch
//! or a stale job, call Protection off when approval is missing) is plain
//! logic over [`Services`], so it is tested with a stand-in that records what it was
//! asked. [`SystemServices`] is the thin part that asks the operating system;
//! it needs a real, signed bundle and is checked by hand (`docs/hand-checks.md`).

use std::fmt;

use crate::popover::Off;

/// Where one SMAppService registration stands, as the operating system says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceState {
    /// Not registered, or unregistered since.
    NotRegistered,
    /// Registered and allowed to run.
    Enabled,
    /// Registered and waiting for the user to allow it in Login Items.
    RequiresApproval,
    /// The operating system cannot find the service. SMAppService answers
    /// this for a service that was never registered as well as for an app
    /// that does not run out of its bundle, so a supervising app registers
    /// on it like on [`ServiceState::NotRegistered`].
    NotFound,
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ServiceState::NotRegistered => "not registered",
            ServiceState::Enabled => "enabled",
            ServiceState::RequiresApproval => "requires approval",
            ServiceState::NotFound => "not found",
        })
    }
}

/// The two registrations and the one pane the app reaches into.
pub trait Services: Send + Sync {
    /// Whether these services register anything at all. A developer run of
    /// the app pointed at a developer's daemon does not.
    fn supervises(&self) -> bool {
        true
    }
    /// Where the daemon's launch agent stands.
    fn agent(&self) -> ServiceState;
    /// Registers the daemon's launch agent, which starts it.
    fn register_agent(&self) -> Result<(), String>;
    /// Unregisters it, which stops it.
    fn unregister_agent(&self) -> Result<(), String>;
    /// Asks launchd to start the registered job now.
    fn start_agent(&self) -> Result<(), String>;
    /// What launchd holds about the daemon's job, where it says anything.
    /// SMAppService answers only whether the job is enabled, so this is the
    /// one place that reads past it.
    fn job(&self) -> Option<Job> {
        None
    }
    /// Where the app's login item stands.
    fn login_item(&self) -> ServiceState;
    /// Registers the app as a login item.
    fn register_login_item(&self) -> Result<(), String>;
    /// Unregisters it.
    fn unregister_login_item(&self) -> Result<(), String>;
    /// Opens System Settings at Login Items.
    fn open_login_items(&self);
}

/// What launching the app did about the registrations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Launched {
    /// The daemon's launch agent was registered by this launch.
    pub registered_agent: bool,
    /// The app was registered as a login item by this launch.
    pub registered_login_item: bool,
    /// What could not be done, for the log.
    pub failures: Vec<String>,
}

/// True for a registration there is none of yet. SMAppService answers "not
/// found" for a service that was never registered too.
fn unregistered(state: ServiceState) -> bool {
    matches!(state, ServiceState::NotRegistered | ServiceState::NotFound)
}

/// Whether this launch shows the onboarding wizard: whenever the daemon is
/// not registered (the owner's decision of 2026-10-14). Onboarding is done
/// when the daemon is registered, so no flag is kept, and a reinstall after
/// Uninstall shows it again. A developer run supervises nothing and never
/// shows it.
pub fn shows_onboarding(services: &dyn Services) -> bool {
    services.supervises() && unregistered(services.agent())
}

/// What every launch of the app does. A launch that shows the onboarding
/// wizard registers nothing: onboarding screen 5 does (spec section 6.8).
/// Any other launch registers the login item when it is not registered and
/// leaves alone what is.
pub fn on_launch(services: &dyn Services) -> Launched {
    if shows_onboarding(services) {
        return Launched::default();
    }
    register(services)
}

/// Registers the daemon and the login item, whichever is not registered,
/// and leaves alone what is: what onboarding screen 5 does. A registration
/// that needs approval stays as it is: only the user can give it, in Login
/// Items.
pub fn register(services: &dyn Services) -> Launched {
    let mut launched = Launched::default();
    if !services.supervises() {
        return launched;
    }
    if unregistered(services.agent()) {
        match services.register_agent() {
            Ok(()) => launched.registered_agent = true,
            Err(error) => launched
                .failures
                .push(format!("the daemon could not be registered: {error}")),
        }
    }
    if unregistered(services.login_item()) {
        match services.register_login_item() {
            Ok(()) => launched.registered_login_item = true,
            Err(error) => launched
                .failures
                .push(format!("the login item could not be registered: {error}")),
        }
    }
    launched
}

/// Re-registers the daemon, which stops the one running and starts the one
/// the bundle carries now. What a version mismatch at the handshake calls for
/// (spec section 9.5): the daemon running is from another bundle than the
/// app's.
pub fn restart_daemon(services: &dyn Services) -> Result<(), String> {
    // An agent that is not registered has nothing to stop.
    if services.agent() != ServiceState::NotRegistered {
        services.unregister_agent()?;
    }
    services.register_agent()
}

/// **Start it** on "Not watching right now" (spec section 8.6): asks
/// launchd to start the registered daemon job. A job launchd no longer holds
/// (one taken out with `launchctl bootout`, while SMAppService still calls
/// the registration enabled) cannot be started that way, so the daemon is
/// registered again instead, which loads and starts it. Only an enabled
/// registration is started: one waiting for approval is the user's to give
/// in Login Items, and a developer run supervises nothing.
pub fn start_daemon(services: &dyn Services) -> Result<(), String> {
    if !services.supervises() {
        return Err("a developer run starts nothing".to_string());
    }
    if services.agent() != ServiceState::Enabled {
        return Err(format!(
            "the background item is {}, so there is nothing to start",
            services.agent()
        ));
    }
    match services.start_agent() {
        Ok(()) => Ok(()),
        Err(_) => restart_daemon(services),
    }
}

/// The version the bundle carries, which is the app's own: Tauri takes the
/// bundle version from this crate's version, the workspace one.
pub const BUNDLE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The exit status launchd records when it refuses to spawn a job's program,
/// `EX_CONFIG`: on 2026-09-29 a job registered for an older bundle and an old
/// code identity met a rebuilt daemon at the same path this way, eight times,
/// with nothing in the log.
pub const EX_CONFIG: i32 = 78;

/// What launchd holds about the daemon's job.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Job {
    /// The version of the bundle that registered the job.
    pub parent_bundle_version: Option<String>,
    /// The status the job's program last exited with, absent when it never
    /// exited.
    pub last_exit: Option<i32>,
}

/// Why a registered job no longer fits the bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Stale {
    /// The job was registered by a bundle of another version.
    Version {
        /// The version that registered it.
        registered: String,
    },
    /// launchd could not spawn the job's program.
    CannotSpawn,
}

/// Whether the daemon's job is stale, asked only while no daemon answers. An
/// enabled registration is not trusted alone: a job registered by another
/// bundle version, or one launchd cannot spawn, stays enabled and never runs.
/// A job of this bundle's version whose daemon is merely down (a crash,
/// `KeepAlive` not yet done, a bundle gone) is Protection off, not stale; a
/// registration that is not enabled is [`on_launch`]'s or the user's.
pub fn stale_job(agent: ServiceState, job: Option<&Job>, bundle_version: &str) -> Option<Stale> {
    if agent != ServiceState::Enabled {
        return None;
    }
    let job = job?;
    if let Some(registered) = &job.parent_bundle_version
        && registered != bundle_version
    {
        return Some(Stale::Version {
            registered: registered.clone(),
        });
    }
    (job.last_exit == Some(EX_CONFIG)).then_some(Stale::CannotSpawn)
}

/// The job, from what `launchctl print` says about it. The output is not an
/// interface launchd promises, so whatever is not found is absent, and an
/// absent fact never makes a job stale.
pub fn job_from_launchctl(text: &str) -> Job {
    let value = |key: &str| {
        text.lines().find_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name.trim() == key).then(|| value.trim().to_string())
        })
    };
    Job {
        parent_bundle_version: value("parent bundle version").filter(|v| !v.is_empty()),
        last_exit: value("last exit code").and_then(|v| {
            let end = v
                .char_indices()
                .find(|&(at, c)| !(c.is_ascii_digit() || (at == 0 && c == '-')))
                .map_or(v.len(), |(at, _)| at);
            v[..end].parse().ok()
        }),
    }
}

/// True when there is a registration to take off: one that runs, or one that
/// waits for approval.
fn registered(state: ServiceState) -> bool {
    matches!(
        state,
        ServiceState::Enabled | ServiceState::RequiresApproval
    )
}

/// Unregisters the daemon and the login item, whichever is registered, and
/// answers with what could not be done.
///
/// Nothing in the app calls this yet: Uninstall arrives with its own
/// milestone. It is what the developer flag `--developer-unregister` runs, so
/// a hand check can take a test install off the machine completely
/// (`docs/hand-checks.md`).
pub fn unregister_everything(services: &dyn Services) -> Vec<String> {
    let mut failures = Vec::new();
    if registered(services.agent())
        && let Err(error) = services.unregister_agent()
    {
        failures.push(format!("the daemon could not be unregistered: {error}"));
    }
    if registered(services.login_item())
        && let Err(error) = services.unregister_login_item()
    {
        failures.push(format!("the login item could not be unregistered: {error}"));
    }
    failures
}

/// Whether the registration alone says Protection is off, whatever the socket
/// answers (spec section 6.6, rung 1). A service the operating system cannot
/// find is a developer run of the app, which supervises nothing and reads the
/// socket alone.
pub fn off_by_registration(agent: ServiceState) -> Option<Off> {
    match agent {
        ServiceState::RequiresApproval => Some(Off::NeedsApproval),
        ServiceState::NotRegistered => Some(Off::NotRegistered),
        ServiceState::Enabled | ServiceState::NotFound => None,
    }
}

/// SMAppService itself.
#[derive(Debug, Default)]
pub struct SystemServices;

/// No service manager at all: what a developer run of the app supervises when
/// it is pointed at a developer's daemon. It registers nothing and finds
/// nothing, so the app reads the socket alone and never touches the real
/// launch agent or Login Items.
#[derive(Debug, Default)]
pub struct Unsupervised;

impl Services for Unsupervised {
    fn supervises(&self) -> bool {
        false
    }
    fn agent(&self) -> ServiceState {
        ServiceState::NotFound
    }
    fn register_agent(&self) -> Result<(), String> {
        Err("a developer run registers nothing".to_string())
    }
    fn unregister_agent(&self) -> Result<(), String> {
        Err("a developer run registers nothing".to_string())
    }
    fn start_agent(&self) -> Result<(), String> {
        Err("a developer run starts nothing".to_string())
    }
    fn login_item(&self) -> ServiceState {
        ServiceState::NotFound
    }
    fn register_login_item(&self) -> Result<(), String> {
        Err("a developer run registers nothing".to_string())
    }
    fn unregister_login_item(&self) -> Result<(), String> {
        Err("a developer run registers nothing".to_string())
    }
    fn open_login_items(&self) {}
}

#[cfg(target_os = "macos")]
mod system {
    use objc2_foundation::NSString;
    use objc2_service_management::{SMAppService, SMAppServiceStatus};

    use agentsweep_core::DAEMON_LABEL;

    use super::{Job, ServiceState, Services, SystemServices, job_from_launchctl};
    use crate::launch_agent::PLIST_NAME;

    unsafe extern "C" {
        /// The user id of the process, which names its launchd GUI domain.
        safe fn getuid() -> u32;
    }

    fn agent() -> objc2::rc::Retained<SMAppService> {
        // Safety: a class method taking a valid NSString, answering an owned
        // object; nothing is shared or aliased.
        unsafe { SMAppService::agentServiceWithPlistName(&NSString::from_str(PLIST_NAME)) }
    }

    fn main_app() -> objc2::rc::Retained<SMAppService> {
        // Safety: a class method with no arguments answering an owned object.
        unsafe { SMAppService::mainAppService() }
    }

    fn state(service: &SMAppService) -> ServiceState {
        // Safety: reads one property of a live object.
        let status = unsafe { service.status() };
        match status {
            SMAppServiceStatus::Enabled => ServiceState::Enabled,
            SMAppServiceStatus::RequiresApproval => ServiceState::RequiresApproval,
            SMAppServiceStatus::NotFound => ServiceState::NotFound,
            _ => ServiceState::NotRegistered,
        }
    }

    fn done(
        result: Result<(), objc2::rc::Retained<objc2_foundation::NSError>>,
    ) -> Result<(), String> {
        result.map_err(|error| error.localizedDescription().to_string())
    }

    impl Services for SystemServices {
        fn agent(&self) -> ServiceState {
            state(&agent())
        }

        fn register_agent(&self) -> Result<(), String> {
            // Safety: a method of a live object that reports failure as an
            // NSError, which the binding turns into the error side.
            done(unsafe { agent().registerAndReturnError() })
        }

        fn unregister_agent(&self) -> Result<(), String> {
            // Safety: as above.
            done(unsafe { agent().unregisterAndReturnError() })
        }

        /// SMAppService cannot start a registered job, so this asks
        /// launchd with `launchctl kickstart`, which starts the job as
        /// registered and runs no other program.
        fn start_agent(&self) -> Result<(), String> {
            let target = format!("gui/{}/{DAEMON_LABEL}", getuid());
            let status = std::process::Command::new("/bin/launchctl")
                .args(["kickstart", &target])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map_err(|error| error.to_string())?;
            match status.success() {
                true => Ok(()),
                false => Err(format!("launchd did not start the job: {status}")),
            }
        }

        /// SMAppService answers neither the bundle version a job was
        /// registered by nor its last exit, so this reads launchd's own
        /// record of the job with `launchctl print`, which only reads. A job
        /// launchd does not know, or an answer that cannot be read, is no
        /// record at all.
        fn job(&self) -> Option<Job> {
            let target = format!("gui/{}/{DAEMON_LABEL}", getuid());
            let output = std::process::Command::new("/bin/launchctl")
                .args(["print", &target])
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            Some(job_from_launchctl(&String::from_utf8_lossy(&output.stdout)))
        }

        fn login_item(&self) -> ServiceState {
            state(&main_app())
        }

        fn register_login_item(&self) -> Result<(), String> {
            // Safety: as above.
            done(unsafe { main_app().registerAndReturnError() })
        }

        fn unregister_login_item(&self) -> Result<(), String> {
            // Safety: as above.
            done(unsafe { main_app().unregisterAndReturnError() })
        }

        fn open_login_items(&self) {
            // Safety: a class method with no arguments and no result.
            unsafe { SMAppService::openSystemSettingsLoginItems() }
        }
    }
}

/// Off macOS there is no SMAppService; the integration layer for the other
/// platforms is a later effort (spec section 6.1). Nothing is found, so the
/// app reads the socket alone.
#[cfg(not(target_os = "macos"))]
impl Services for SystemServices {
    fn agent(&self) -> ServiceState {
        ServiceState::NotFound
    }
    fn register_agent(&self) -> Result<(), String> {
        Err("there is no service manager on this platform".to_string())
    }
    fn unregister_agent(&self) -> Result<(), String> {
        Err("there is no service manager on this platform".to_string())
    }
    fn start_agent(&self) -> Result<(), String> {
        Err("there is no service manager on this platform".to_string())
    }
    fn login_item(&self) -> ServiceState {
        ServiceState::NotFound
    }
    fn register_login_item(&self) -> Result<(), String> {
        Err("there is no service manager on this platform".to_string())
    }
    fn unregister_login_item(&self) -> Result<(), String> {
        Err("there is no service manager on this platform".to_string())
    }
    fn open_login_items(&self) {}
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::Mutex;

    /// A stand-in for SMAppService that records every call and whose states
    /// a test sets.
    #[derive(Debug)]
    pub(crate) struct Recorded {
        pub(crate) agent: Mutex<ServiceState>,
        pub(crate) login_item: Mutex<ServiceState>,
        pub(crate) calls: Mutex<Vec<&'static str>>,
        pub(crate) refuse: bool,
        /// True when launchd no longer holds the job, so starting it fails.
        pub(crate) unloaded: bool,
        /// What launchd would say about the job, which a test sets and a
        /// registration replaces with a fresh job of this bundle.
        pub(crate) job: Mutex<Option<Job>>,
    }

    impl Recorded {
        pub(crate) fn with(agent: ServiceState, login_item: ServiceState) -> Recorded {
            Recorded {
                agent: Mutex::new(agent),
                login_item: Mutex::new(login_item),
                calls: Mutex::new(Vec::new()),
                refuse: false,
                unloaded: false,
                job: Mutex::new(None),
            }
        }

        /// The same, with launchd holding this job.
        pub(crate) fn holding(self, job: Job) -> Recorded {
            *self.job.lock().expect("the job") = Some(job);
            self
        }

        pub(crate) fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().expect("the calls").clone()
        }

        fn call(&self, name: &'static str) -> Result<(), String> {
            self.calls.lock().expect("the calls").push(name);
            match self.refuse {
                true => Err("refused".to_string()),
                false => Ok(()),
            }
        }
    }

    impl Services for Recorded {
        fn agent(&self) -> ServiceState {
            *self.agent.lock().expect("the agent")
        }
        fn register_agent(&self) -> Result<(), String> {
            self.call("register agent")?;
            *self.agent.lock().expect("the agent") = ServiceState::Enabled;
            *self.job.lock().expect("the job") = Some(Job {
                parent_bundle_version: Some(BUNDLE_VERSION.to_string()),
                last_exit: None,
            });
            Ok(())
        }
        fn unregister_agent(&self) -> Result<(), String> {
            self.call("unregister agent")?;
            *self.agent.lock().expect("the agent") = ServiceState::NotRegistered;
            *self.job.lock().expect("the job") = None;
            Ok(())
        }
        fn start_agent(&self) -> Result<(), String> {
            self.call("start agent")?;
            match self.unloaded {
                true => Err("Could not find service".to_string()),
                false => Ok(()),
            }
        }
        fn job(&self) -> Option<Job> {
            self.job.lock().expect("the job").clone()
        }
        fn login_item(&self) -> ServiceState {
            *self.login_item.lock().expect("the login item")
        }
        fn register_login_item(&self) -> Result<(), String> {
            self.call("register login item")?;
            *self.login_item.lock().expect("the login item") = ServiceState::Enabled;
            Ok(())
        }
        fn unregister_login_item(&self) -> Result<(), String> {
            self.call("unregister login item")?;
            *self.login_item.lock().expect("the login item") = ServiceState::NotRegistered;
            Ok(())
        }
        fn open_login_items(&self) {
            let _ = self.call("open login items");
        }
    }

    /// A launch with the daemon not registered shows the onboarding wizard
    /// and registers nothing: screen 5 does.
    #[test]
    fn a_launch_that_shows_the_wizard_registers_nothing() {
        for state in [ServiceState::NotRegistered, ServiceState::NotFound] {
            let services = Recorded::with(state, state);
            assert!(shows_onboarding(&services), "{state}");
            assert_eq!(on_launch(&services), Launched::default());
            assert!(services.calls().is_empty(), "{state}");
        }
    }

    /// Screen 5 registers the daemon and the login item.
    #[test]
    fn registering_registers_the_daemon_and_the_login_item() {
        let services = Recorded::with(ServiceState::NotRegistered, ServiceState::NotRegistered);
        let launched = register(&services);
        assert!(launched.registered_agent);
        assert!(launched.registered_login_item);
        assert!(launched.failures.is_empty());
        assert_eq!(
            services.calls(),
            vec!["register agent", "register login item"]
        );
        assert!(!shows_onboarding(&services));
    }

    /// SMAppService says "not found" for an agent that was never registered,
    /// and that is registered like any other.
    #[test]
    fn a_service_the_system_cannot_find_yet_is_registered() {
        let services = Recorded::with(ServiceState::NotFound, ServiceState::NotFound);
        let launched = register(&services);
        assert!(launched.registered_agent && launched.registered_login_item);
        assert_eq!(
            services.calls(),
            vec!["register agent", "register login item"]
        );
    }

    /// A launch that does not show the wizard registers as before: the login
    /// item when it is missing, and nothing that is registered.
    #[test]
    fn a_launch_that_does_not_show_the_wizard_registers_as_before() {
        let services = Recorded::with(ServiceState::Enabled, ServiceState::NotRegistered);
        assert!(!shows_onboarding(&services));
        let launched = on_launch(&services);
        assert!(!launched.registered_agent && launched.registered_login_item);
        assert_eq!(services.calls(), vec!["register login item"]);
    }

    #[test]
    fn a_later_launch_leaves_what_is_registered_alone() {
        let services = Recorded::with(ServiceState::Enabled, ServiceState::Enabled);
        assert!(!shows_onboarding(&services));
        assert_eq!(on_launch(&services), Launched::default());
        assert!(services.calls().is_empty());
    }

    /// Approval is the user's to give, so a launch never registers over it.
    #[test]
    fn a_registration_waiting_for_approval_is_left_to_the_user() {
        let services = Recorded::with(
            ServiceState::RequiresApproval,
            ServiceState::RequiresApproval,
        );
        assert_eq!(on_launch(&services), Launched::default());
        assert_eq!(
            off_by_registration(services.agent()),
            Some(Off::NeedsApproval)
        );
    }

    #[test]
    fn a_registration_that_fails_is_reported_not_hidden() {
        let mut services = Recorded::with(ServiceState::NotRegistered, ServiceState::NotRegistered);
        services.refuse = true;
        let launched = register(&services);
        assert!(!launched.registered_agent);
        assert_eq!(launched.failures.len(), 2);
        assert_eq!(
            off_by_registration(services.agent()),
            Some(Off::NotRegistered)
        );
    }

    /// A version mismatch re-registers: the daemon running is stopped and the
    /// bundle's own is started.
    #[test]
    fn restarting_the_daemon_unregisters_then_registers() {
        let services = Recorded::with(ServiceState::Enabled, ServiceState::Enabled);
        restart_daemon(&services).expect("a restart");
        assert_eq!(services.calls(), vec!["unregister agent", "register agent"]);
        assert_eq!(services.agent(), ServiceState::Enabled);

        let services = Recorded::with(ServiceState::NotRegistered, ServiceState::Enabled);
        restart_daemon(&services).expect("a restart");
        assert_eq!(services.calls(), vec!["register agent"]);
    }

    /// Start it asks launchd to start the registered job and registers
    /// nothing while launchd holds it.
    #[test]
    fn start_it_asks_launchd_to_start_the_registered_job() {
        let services = Recorded::with(ServiceState::Enabled, ServiceState::Enabled);
        start_daemon(&services).expect("a start");
        assert_eq!(services.calls(), vec!["start agent"]);
    }

    /// A job launchd no longer holds is registered again, which loads it.
    #[test]
    fn start_it_registers_again_a_job_launchd_no_longer_holds() {
        let mut services = Recorded::with(ServiceState::Enabled, ServiceState::Enabled);
        services.unloaded = true;
        start_daemon(&services).expect("a start");
        assert_eq!(
            services.calls(),
            vec!["start agent", "unregister agent", "register agent"]
        );
        assert_eq!(services.agent(), ServiceState::Enabled);
    }

    /// Only an enabled registration is started; a developer run starts
    /// nothing.
    #[test]
    fn start_it_starts_only_an_enabled_registration() {
        for state in [
            ServiceState::RequiresApproval,
            ServiceState::NotRegistered,
            ServiceState::NotFound,
        ] {
            let services = Recorded::with(state, ServiceState::Enabled);
            assert!(start_daemon(&services).is_err(), "{state}");
            assert!(services.calls().is_empty(), "{state}");
        }
        assert!(start_daemon(&Unsupervised).is_err());
    }

    fn job(version: &str, last_exit: Option<i32>) -> Job {
        Job {
            parent_bundle_version: Some(version.to_string()),
            last_exit,
        }
    }

    /// A job registered by another bundle version is stale, whatever its
    /// last exit; one of this version is stale only when launchd could not
    /// spawn it.
    #[test]
    fn a_job_of_another_version_or_one_launchd_cannot_spawn_is_stale() {
        let enabled = ServiceState::Enabled;
        assert_eq!(
            stale_job(enabled, Some(&job("0.0.1", None)), "0.0.2"),
            Some(Stale::Version {
                registered: "0.0.1".to_string()
            })
        );
        assert_eq!(
            stale_job(enabled, Some(&job("0.0.2", Some(EX_CONFIG))), "0.0.2"),
            Some(Stale::CannotSpawn)
        );
        for last_exit in [None, Some(0), Some(75), Some(9)] {
            assert_eq!(
                stale_job(enabled, Some(&job("0.0.2", last_exit)), "0.0.2"),
                None
            );
        }
        let unknown = Job {
            parent_bundle_version: None,
            last_exit: Some(EX_CONFIG),
        };
        assert_eq!(
            stale_job(enabled, Some(&unknown), "0.0.2"),
            Some(Stale::CannotSpawn)
        );
        assert_eq!(stale_job(enabled, Some(&Job::default()), "0.0.2"), None);
        assert_eq!(stale_job(enabled, None, "0.0.2"), None);
    }

    /// Only an enabled registration can be stale: one waiting for approval is
    /// the user's, and one not registered is registered at launch anyway.
    #[test]
    fn only_an_enabled_registration_is_judged_stale() {
        let old = job("0.0.1", Some(EX_CONFIG));
        for state in [
            ServiceState::RequiresApproval,
            ServiceState::NotRegistered,
            ServiceState::NotFound,
        ] {
            assert_eq!(stale_job(state, Some(&old), "0.0.2"), None, "{state}");
        }
    }

    /// The facts are read from launchd's record as `launchctl print` lays it
    /// out, and what is missing or unreadable stays absent.
    #[test]
    fn the_job_is_read_from_launchds_record() {
        let record = "gui/501/de.byte5.agentsweep.daemon = {
\tactive count = 0
\tpath = /Users/someone/AgentSweep.app/Contents/Library/LaunchAgents/de.byte5.agentsweep.daemon.plist
\ttype = LaunchAgent
\tstate = not running

\tprogram identifier = Contents/MacOS/agentsweepd (mode: 2)
\tparent bundle identifier = de.byte5.agentsweep
\tparent bundle version = 0.1.0
\truns = 8
\tlast exit code = 78: EX_CONFIG
}
";
        assert_eq!(
            job_from_launchctl(record),
            Job {
                parent_bundle_version: Some("0.1.0".to_string()),
                last_exit: Some(78),
            }
        );
        assert_eq!(
            job_from_launchctl("\tlast exit code = (never exited)\n").last_exit,
            None
        );
        assert_eq!(
            job_from_launchctl("\tlast exit code = 0\n").last_exit,
            Some(0)
        );
        assert_eq!(job_from_launchctl("Could not find service"), Job::default());
    }

    /// A developer run registers nothing and, finding nothing, leaves
    /// Protection to what the socket says.
    #[test]
    fn a_developer_run_supervises_nothing() {
        assert!(!shows_onboarding(&Unsupervised));
        assert_eq!(on_launch(&Unsupervised), Launched::default());
        assert_eq!(register(&Unsupervised), Launched::default());
        assert_eq!(off_by_registration(Unsupervised.agent()), None);
        assert!(unregister_everything(&Unsupervised).is_empty());
    }

    /// Taking a test install off the machine unregisters both, and only what
    /// is registered.
    #[test]
    fn unregistering_everything_takes_off_both_registrations() {
        let services = Recorded::with(ServiceState::Enabled, ServiceState::RequiresApproval);
        assert!(unregister_everything(&services).is_empty());
        assert_eq!(
            services.calls(),
            vec!["unregister agent", "unregister login item"]
        );
        assert_eq!(services.agent(), ServiceState::NotRegistered);
        assert_eq!(services.login_item(), ServiceState::NotRegistered);

        let services = Recorded::with(ServiceState::NotRegistered, ServiceState::NotRegistered);
        assert!(unregister_everything(&services).is_empty());
        assert!(services.calls().is_empty());
    }

    /// A developer run of the app is not in a bundle, so it has no service to
    /// find and reads the socket alone.
    #[test]
    fn only_approval_and_registration_turn_protection_off_by_themselves() {
        assert_eq!(off_by_registration(ServiceState::Enabled), None);
        assert_eq!(off_by_registration(ServiceState::NotFound), None);
        assert_eq!(
            off_by_registration(ServiceState::NotRegistered),
            Some(Off::NotRegistered)
        );
    }
}
