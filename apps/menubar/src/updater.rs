//! The app updater (spec section 9.4).
//!
//! The update check is the second of the three disclosed requests (spec
//! section 1.1): a GET of the fixed [`ENDPOINT`], with no identifiers, made
//! by the Tauri updater plugin from the endpoint and the minisign public key
//! pinned in `tauri.conf.json`. The app checks at launch and once a day,
//! only while the update toggle is on, downloads a newer release in the
//! background, verifies its signature, says [`READY`] in the popover and
//! installs it on the next quit. It never restarts on its own. Once the
//! replaced bundle is in place, the daemon's bundle watch brings it back on
//! the new version (spec section 9.5).
//!
//! The pinned key is a development key until the release prerequisites of
//! spec section 9.8 produce the real one; its secret half is committed under
//! `apps/menubar/development-keys/` for the tests and the CI bundle alone.
//!
//! What decides is here and tested at its seams: [`toggle`] resolves the
//! update toggle, [`Updates`] holds when a check is due, the update that is
//! ready and its install at quit. A [`Source`] checks and downloads, an
//! [`Installer`] installs; [`PluginSource`] and [`PluginInstaller`] are the
//! plugin behind them, and [`Remembered`] keeps the app's own copy of the
//! toggle.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use tauri::{AppHandle, Runtime};
use tauri_plugin_updater::UpdaterExt;

/// The updater endpoint: the `latest.json` of the latest release of the
/// project's repository. It carries no variable, so every check asks the
/// same URL.
pub const ENDPOINT: &str =
    "https://github.com/byte5digital/agentsweep/releases/latest/download/latest.json";

/// The popover's line once an update is downloaded and verified (spec
/// section 8.1).
pub const READY: &str = "Update ready, restart AgentSweep";

/// How long after one check the next is due.
pub const EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// How often the app looks whether a check is due. A check itself happens
/// at launch and then once every [`EVERY`].
pub const LOOK_EVERY: Duration = Duration::from_secs(60);

/// The app's own copy of the last update toggle it read from the daemon.
pub trait Remembered: Send + Sync {
    /// The copy, or nothing when the app never kept one.
    fn recall(&self) -> Option<bool>;

    /// Keeps `on` as the copy.
    fn remember(&self, on: bool);
}

/// Whether the update check is on, and keeps the app's copy of it.
///
/// `held` is the choice onboarding holds for a daemon that has not taken it
/// yet, `daemon` the toggle the daemon answered with, if one answered. A
/// held choice comes first, since the daemon does not know it yet; then the
/// daemon's answer; with neither, the app's copy; with no copy yet, the
/// default of the settings file. Whatever was read is remembered, so a
/// user's "off" is never overridden by a daemon that does not answer (the
/// owner's decision of 2026-10-14).
pub fn toggle(held: Option<bool>, daemon: Option<bool>, copy: &dyn Remembered) -> bool {
    match held.or(daemon) {
        Some(on) => {
            copy.remember(on);
            on
        }
        None => copy
            .recall()
            .unwrap_or_else(|| agentsweep_core::settings::Settings::default().update_check),
    }
}

/// Checks for a newer release and, when there is one, downloads it and
/// verifies its signature. Answers with the update ready to install, or
/// nothing when there is no newer release.
pub trait Source<R> {
    /// One check: one GET of the endpoint, and the archive's when it names
    /// a newer release.
    fn fetch(&self) -> Result<Option<R>, String>;
}

/// Installs an update that is ready.
pub trait Installer<R> {
    /// Puts the update in place of the running bundle. Never restarts.
    fn install(&self, ready: R) -> Result<(), String>;
}

/// What one look at the schedule did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Look {
    /// No check was due, or an update is ready and nothing more is asked.
    NotDue,
    /// A check was due and the toggle is off: no request was made.
    Off,
    /// The check found no newer release.
    Current,
    /// A newer release is downloaded and verified.
    Ready,
    /// The check failed: unreachable, refused, or a signature that does not
    /// verify. Nothing is ready; the next check is due a day later.
    Failed(String),
}

/// The updater's state while the app runs: when the last check was, and the
/// update that is ready.
pub struct Updates<R> {
    inner: Mutex<Inner<R>>,
}

struct Inner<R> {
    /// When the last check was asked, none before the first.
    last: Option<SystemTime>,
    /// The update downloaded and verified, until the quit installs it.
    ready: Option<R>,
    /// True once nothing may be installed any more: after Uninstall, and
    /// after the quit took the update.
    closed: bool,
}

impl<R> Default for Updates<R> {
    fn default() -> Self {
        Updates::new()
    }
}

impl<R> Updates<R> {
    /// Nothing checked yet, so the first look is due: the check at launch.
    pub fn new() -> Self {
        Updates {
            inner: Mutex::new(Inner {
                last: None,
                ready: None,
                closed: false,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<R>> {
        self.inner.lock().expect("the updates are not poisoned")
    }

    /// One look at the schedule at `now`. A check is due at launch and a day
    /// after the last one; a clock set back makes it due too. Only when it
    /// is due is `on` asked whether the toggle is on, and only when it is on
    /// does `source` make its request. An update that is ready ends the
    /// checks: it waits for the quit.
    pub fn look(&self, now: SystemTime, on: impl FnOnce() -> bool, source: &dyn Source<R>) -> Look {
        {
            let inner = self.lock();
            if inner.ready.is_some() || inner.closed {
                return Look::NotDue;
            }
            let due = inner
                .last
                .is_none_or(|last| match now.duration_since(last) {
                    Ok(since) => since >= EVERY,
                    Err(_) => true,
                });
            if !due {
                return Look::NotDue;
            }
        }
        if !on() {
            return Look::Off;
        }
        self.lock().last = Some(now);
        let fetched = source.fetch();
        let mut inner = self.lock();
        match fetched {
            Ok(Some(ready)) if !inner.closed => {
                inner.ready = Some(ready);
                Look::Ready
            }
            Ok(_) => Look::Current,
            Err(why) => Look::Failed(why),
        }
    }

    /// The popover's line while an update is ready.
    pub fn line(&self) -> Option<&'static str> {
        self.lock().ready.as_ref().map(|_| READY)
    }

    /// The quit: installs the update that is ready, once, through
    /// `installer`, and answers how that went; nothing when none is ready.
    /// Nothing restarts the app.
    pub fn on_quit(&self, installer: &dyn Installer<R>) -> Option<Result<(), String>> {
        let ready = {
            let mut inner = self.lock();
            inner.closed = true;
            inner.ready.take()
        };
        ready.map(|ready| installer.install(ready))
    }

    /// Uninstall: the bundle goes to the Trash, so nothing may be installed
    /// in its place at the quit that follows, and nothing more is checked.
    pub fn forget(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        inner.ready = None;
    }
}

/// The popover's view with the update line in it: `updateReady` is the line
/// while an update is ready, null otherwise. It shows whatever else the
/// popover shows, banners included.
pub fn into_popover(mut view: serde_json::Value, line: Option<&'static str>) -> serde_json::Value {
    if let Some(object) = view.as_object_mut() {
        object.insert("updateReady".to_string(), serde_json::Value::from(line));
    }
    view
}

/// An update the plugin downloaded and verified.
pub struct Ready {
    update: tauri_plugin_updater::Update,
    bytes: Vec<u8>,
}

impl Ready {
    /// The version the update brings.
    pub fn version(&self) -> &str {
        &self.update.version
    }

    /// The verified archive.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The Tauri updater plugin as the [`Source`]: the endpoint and the public
/// key come from the plugin's configuration, which `tauri.conf.json` pins.
pub struct PluginSource<R: Runtime>(pub AppHandle<R>);

impl<R: Runtime> Source<Ready> for PluginSource<R> {
    fn fetch(&self) -> Result<Option<Ready>, String> {
        let app = self.0.clone();
        tauri::async_runtime::block_on(async move {
            let updater = app.updater().map_err(|why| why.to_string())?;
            let Some(update) = updater.check().await.map_err(|why| why.to_string())? else {
                return Ok(None);
            };
            // The plugin verifies the minisign signature over the whole
            // archive before it answers with the bytes.
            let bytes = update
                .download(|_, _| {}, || {})
                .await
                .map_err(|why| why.to_string())?;
            Ok(Some(Ready { update, bytes }))
        })
    }
}

/// The Tauri updater plugin as the [`Installer`]: it unpacks the verified
/// archive in place of the running bundle and does not restart.
pub struct PluginInstaller;

impl Installer<Ready> for PluginInstaller {
    fn install(&self, ready: Ready) -> Result<(), String> {
        ready
            .update
            .install(&ready.bytes)
            .map_err(|why| why.to_string())
    }
}

/// The app's preferences (`~/Library/Preferences/de.byte5.agentsweep.plist`)
/// as the place of the app's copy of the toggle. **Delete everything** on
/// Uninstall removes them (spec section 9.6).
pub struct Preferences;

/// The key the copy is kept under in the app's preferences.
pub const PREFERENCE_KEY: &str = "update_check";

#[cfg(target_os = "macos")]
impl Remembered for Preferences {
    fn recall(&self) -> Option<bool> {
        use objc2_foundation::{NSString, NSUserDefaults};
        let defaults = NSUserDefaults::standardUserDefaults();
        let key = NSString::from_str(PREFERENCE_KEY);
        defaults
            .objectForKey(&key)
            .map(|_| defaults.boolForKey(&key))
    }

    fn remember(&self, on: bool) {
        use objc2_foundation::{NSString, NSUserDefaults};
        let defaults = NSUserDefaults::standardUserDefaults();
        defaults.setBool_forKey(on, &NSString::from_str(PREFERENCE_KEY));
    }
}

#[cfg(not(target_os = "macos"))]
impl Remembered for Preferences {
    fn recall(&self) -> Option<bool> {
        None
    }

    fn remember(&self, _on: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{Cell, RefCell};

    /// The copy in memory.
    #[derive(Default)]
    struct Copy(Mutex<Option<bool>>);

    impl Remembered for Copy {
        fn recall(&self) -> Option<bool> {
            *self.0.lock().expect("the copy")
        }

        fn remember(&self, on: bool) {
            *self.0.lock().expect("the copy") = Some(on);
        }
    }

    /// A source that counts its checks and answers what it was given.
    struct Counting {
        checks: Cell<usize>,
        answer: RefCell<Result<Option<&'static str>, String>>,
    }

    impl Counting {
        fn answering(answer: Result<Option<&'static str>, String>) -> Counting {
            Counting {
                checks: Cell::new(0),
                answer: RefCell::new(answer),
            }
        }
    }

    impl Source<&'static str> for Counting {
        fn fetch(&self) -> Result<Option<&'static str>, String> {
            self.checks.set(self.checks.get() + 1);
            self.answer.borrow().clone()
        }
    }

    /// An installer that counts its installs.
    #[derive(Default)]
    struct Installs(RefCell<Vec<&'static str>>);

    impl Installer<&'static str> for Installs {
        fn install(&self, ready: &'static str) -> Result<(), String> {
            self.0.borrow_mut().push(ready);
            Ok(())
        }
    }

    fn launch() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    #[test]
    fn the_daemons_answer_is_used_and_remembered() {
        let copy = Copy::default();
        assert!(!toggle(None, Some(false), &copy));
        assert_eq!(copy.recall(), Some(false));
        assert!(toggle(None, Some(true), &copy));
        assert_eq!(copy.recall(), Some(true));
    }

    #[test]
    fn with_no_daemon_answering_the_copy_is_used_and_a_users_off_stays_off() {
        let copy = Copy::default();
        copy.remember(false);
        assert!(!toggle(None, None, &copy));
        assert_eq!(copy.recall(), Some(false));
    }

    #[test]
    fn with_no_copy_yet_the_default_of_the_settings_file_is_used() {
        let copy = Copy::default();
        assert_eq!(
            toggle(None, None, &copy),
            agentsweep_core::settings::Settings::default().update_check
        );
        assert!(
            toggle(None, None, &copy),
            "on by default (spec section 1.1)"
        );
        assert_eq!(copy.recall(), None, "a default is not a copy");
    }

    #[test]
    fn a_choice_onboarding_holds_comes_before_a_daemon_that_does_not_know_it_yet() {
        let copy = Copy::default();
        assert!(!toggle(Some(false), Some(true), &copy));
        assert_eq!(copy.recall(), Some(false));
    }

    #[test]
    fn a_check_is_due_at_launch_and_then_once_a_day() {
        let updates = Updates::new();
        let source = Counting::answering(Ok(None));
        assert_eq!(updates.look(launch(), || true, &source), Look::Current);
        let hour = Duration::from_secs(3600);
        for hours in 1..24 {
            assert_eq!(
                updates.look(launch() + hour * hours, || true, &source),
                Look::NotDue
            );
        }
        assert_eq!(
            updates.look(launch() + EVERY, || true, &source),
            Look::Current
        );
        assert_eq!(source.checks.get(), 2);
    }

    #[test]
    fn with_the_toggle_off_nothing_is_asked_at_launch_or_after_a_day() {
        let updates = Updates::new();
        let source = Counting::answering(Ok(Some("0.2.0")));
        assert_eq!(updates.look(launch(), || false, &source), Look::Off);
        assert_eq!(updates.look(launch() + EVERY, || false, &source), Look::Off);
        assert_eq!(
            updates.look(launch() + EVERY * 2, || false, &source),
            Look::Off
        );
        assert_eq!(source.checks.get(), 0);
        assert_eq!(updates.line(), None);
    }

    #[test]
    fn the_toggle_is_asked_only_when_a_check_is_due() {
        let updates = Updates::new();
        let source = Counting::answering(Ok(None));
        let asked = Cell::new(0);
        let on = || {
            asked.set(asked.get() + 1);
            true
        };
        updates.look(launch(), on, &source);
        updates.look(launch() + LOOK_EVERY, on, &source);
        assert_eq!(asked.get(), 1);
    }

    #[test]
    fn a_toggle_turned_on_later_checks_at_the_next_look() {
        let updates = Updates::new();
        let source = Counting::answering(Ok(None));
        assert_eq!(updates.look(launch(), || false, &source), Look::Off);
        assert_eq!(
            updates.look(launch() + LOOK_EVERY, || true, &source),
            Look::Current
        );
        assert_eq!(source.checks.get(), 1);
    }

    #[test]
    fn a_clock_set_back_makes_the_check_due() {
        let updates = Updates::new();
        let source = Counting::answering(Ok(None));
        updates.look(launch(), || true, &source);
        assert_eq!(
            updates.look(launch() - Duration::from_secs(60), || true, &source),
            Look::Current
        );
    }

    #[test]
    fn a_ready_update_shows_its_line_and_ends_the_checks() {
        let updates = Updates::new();
        let source = Counting::answering(Ok(Some("0.2.0")));
        assert_eq!(updates.line(), None);
        assert_eq!(updates.look(launch(), || true, &source), Look::Ready);
        assert_eq!(updates.line(), Some(READY));
        assert_eq!(
            updates.look(launch() + EVERY, || true, &source),
            Look::NotDue
        );
        assert_eq!(source.checks.get(), 1);
    }

    #[test]
    fn a_failed_check_shows_nothing_and_is_due_again_a_day_later() {
        let updates = Updates::new();
        let source = Counting::answering(Err("the signature does not verify".to_string()));
        assert!(matches!(
            updates.look(launch(), || true, &source),
            Look::Failed(_)
        ));
        assert_eq!(updates.line(), None);
        assert_eq!(
            updates.look(launch() + LOOK_EVERY, || true, &source),
            Look::NotDue
        );
        *source.answer.borrow_mut() = Ok(None);
        assert_eq!(
            updates.look(launch() + EVERY, || true, &source),
            Look::Current
        );
    }

    #[test]
    fn the_popover_carries_the_line_only_while_an_update_is_ready() {
        use agentsweep_core::settings::Posture;

        use crate::popover::View;

        let updates = Updates::new();
        let view = View::unknown().to_value(Posture::Simple);
        assert_eq!(
            into_popover(view.clone(), updates.line())["updateReady"],
            serde_json::Value::Null
        );
        updates.look(launch(), || true, &Counting::answering(Ok(Some("0.2.0"))));
        let shown = into_popover(view.clone(), updates.line());
        assert_eq!(shown["updateReady"], READY);
        assert_eq!(shown["orb"], view["orb"], "the rest stays as it was");
    }

    #[test]
    fn the_quit_installs_a_ready_update_once() {
        let updates = Updates::new();
        updates.look(launch(), || true, &Counting::answering(Ok(Some("0.2.0"))));
        let installs = Installs::default();
        assert_eq!(updates.on_quit(&installs), Some(Ok(())));
        assert_eq!(updates.on_quit(&installs), None);
        assert_eq!(*installs.0.borrow(), vec!["0.2.0"]);
    }

    #[test]
    fn the_quit_installs_nothing_when_no_update_is_ready() {
        let updates = Updates::new();
        updates.look(launch(), || true, &Counting::answering(Ok(None)));
        let installs = Installs::default();
        assert_eq!(updates.on_quit(&installs), None);
        assert!(installs.0.borrow().is_empty());
    }

    #[test]
    fn nothing_installs_without_a_quit() {
        let updates = Updates::new();
        let source = Counting::answering(Ok(Some("0.2.0")));
        let installs = Installs::default();
        for days in 0..3 {
            updates.look(launch() + EVERY * days, || true, &source);
        }
        assert_eq!(updates.line(), Some(READY));
        assert!(installs.0.borrow().is_empty());
    }

    #[test]
    fn after_uninstall_the_quit_installs_nothing_and_nothing_is_checked() {
        let updates = Updates::new();
        let source = Counting::answering(Ok(Some("0.2.0")));
        updates.look(launch(), || true, &source);
        updates.forget();
        assert_eq!(updates.line(), None);
        let installs = Installs::default();
        assert_eq!(updates.on_quit(&installs), None);
        assert!(installs.0.borrow().is_empty());
        assert_eq!(
            updates.look(launch() + EVERY, || true, &source),
            Look::NotDue
        );
        assert_eq!(source.checks.get(), 1);
    }
}
