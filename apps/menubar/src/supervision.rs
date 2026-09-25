//! Keeping the daemon registered: SMAppService for the launch agent and for
//! the app as a login item (spec section 9.5).
//!
//! The daemon registers through `SMAppService.agent` from the plist inside the
//! bundle, and the app through `SMAppService.mainApp`. What is decided about
//! them (register what is not registered, re-register on a version mismatch,
//! call Protection off when approval is missing) is plain logic over
//! [`Services`], so it is tested with a stand-in that records what it was
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
    /// The operating system cannot find the service: an app that does not run
    /// out of its bundle, which is every developer run.
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
    /// Where the daemon's launch agent stands.
    fn agent(&self) -> ServiceState;
    /// Registers the daemon's launch agent, which starts it.
    fn register_agent(&self) -> Result<(), String>;
    /// Unregisters it, which stops it.
    fn unregister_agent(&self) -> Result<(), String>;
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

/// What every launch of the app does: register the daemon and the login item
/// when either is not registered, and leave alone what is. There is no
/// onboarding yet to ask first; registering is what onboarding screen 5 will
/// do (spec section 6.8). A registration that needs approval stays as it is:
/// only the user can give it, in Login Items.
pub fn on_launch(services: &dyn Services) -> Launched {
    let mut launched = Launched::default();
    if services.agent() == ServiceState::NotRegistered {
        match services.register_agent() {
            Ok(()) => launched.registered_agent = true,
            Err(error) => launched
                .failures
                .push(format!("the daemon could not be registered: {error}")),
        }
    }
    if services.login_item() == ServiceState::NotRegistered {
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

/// Unregisters the daemon and the login item, whichever is registered, and
/// answers with what could not be done.
///
/// Nothing in the app calls this yet: Uninstall arrives with its own
/// milestone. It is what the developer flag `--developer-unregister` runs, so
/// a hand check can take a test install off the machine completely
/// (`docs/hand-checks.md`).
pub fn unregister_everything(services: &dyn Services) -> Vec<String> {
    let mut failures = Vec::new();
    if services.agent() != ServiceState::NotRegistered
        && let Err(error) = services.unregister_agent()
    {
        failures.push(format!("the daemon could not be unregistered: {error}"));
    }
    if services.login_item() != ServiceState::NotRegistered
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

#[cfg(target_os = "macos")]
mod system {
    use objc2_foundation::NSString;
    use objc2_service_management::{SMAppService, SMAppServiceStatus};

    use super::{ServiceState, Services, SystemServices};
    use crate::launch_agent::PLIST_NAME;

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
    }

    impl Recorded {
        pub(crate) fn with(agent: ServiceState, login_item: ServiceState) -> Recorded {
            Recorded {
                agent: Mutex::new(agent),
                login_item: Mutex::new(login_item),
                calls: Mutex::new(Vec::new()),
                refuse: false,
            }
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
            Ok(())
        }
        fn unregister_agent(&self) -> Result<(), String> {
            self.call("unregister agent")?;
            *self.agent.lock().expect("the agent") = ServiceState::NotRegistered;
            Ok(())
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

    #[test]
    fn a_first_launch_registers_the_daemon_and_the_login_item() {
        let services = Recorded::with(ServiceState::NotRegistered, ServiceState::NotRegistered);
        let launched = on_launch(&services);
        assert!(launched.registered_agent);
        assert!(launched.registered_login_item);
        assert!(launched.failures.is_empty());
        assert_eq!(
            services.calls(),
            vec!["register agent", "register login item"]
        );
    }

    #[test]
    fn a_later_launch_leaves_what_is_registered_alone() {
        let services = Recorded::with(ServiceState::Enabled, ServiceState::Enabled);
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
        let launched = on_launch(&services);
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
