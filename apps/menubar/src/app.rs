//! The Tauri shell: the tray icon, the popover, the Findings window and the
//! commands both call.
//!
//! Everything that decides something is in the modules beside this one and is
//! tested there; this is the part that needs a window server, which the suite
//! never starts. Every command is a thin call into [`Asking`], which sends
//! the request the command line interface sends; the app never scans.
//!
//! Commands the frontend may call:
//! - `popover`: the popover's view as it stands, for a popover that just
//!   loaded.
//! - `open_login_items`: System Settings at Login Items.
//! - `start_daemon`: **Start it** on "Not watching right now", which asks
//!   launchd to start the registered daemon job ([`supervision::start_daemon`]).
//! - `start_fresh_record`, `look_at_records`, `show_what_changed`,
//!   `scan_again_trusting_nothing`: the integrity banners' buttons, each the
//!   daemon's matching request; the window then opens on Activity at the
//!   break point or at the restart record ([`crate::integrity`]).
//! - `quit`: quits the app. Protection stays on: the daemon is a launch agent
//!   of its own and does not go with the app.
//! - `open_window`: opens the Findings window, which makes the app a regular
//!   app with a Dock icon until the window is closed.
//! - `findings`: the Findings window's view as it stands: the list, the
//!   sidebar with its counts, the Overview, the two Finding panes and the
//!   Posture.
//! - `folder`: the Scan a folder dialog's view, for a window that just
//!   loaded.
//! - `quarantine`, `restore`, `trust`, `acknowledge`, `fix`, `re_enable`,
//!   `purge`, `untrust`: the action requests, each answered with the daemon's sentence, the lines
//!   under it (after a Quarantine, its confirmation) and, for a Restore that
//!   met something else at the original place, the two conflict choices. A
//!   Quarantine of a never-auto kind is the switch that neutralises its line
//!   in place, and its Restore switches the line back on.
//! - `false_alarm_report`, `open_false_alarm_report`: **Report false
//!   positive** and the one-time card after a Restore or a Trust: the
//!   prepared GitHub issue for the dialog, then its new-issue page in the
//!   user's browser; the app sends nothing (spec section 8.8,
//!   [`crate::false_alarm`]).
//! - `copy_for_admin`: puts the message about a Managed Finding for whoever
//!   administers the Mac on the clipboard (spec section 8.4).
//! - `open_the_file`: **Open the file** in an Exposure's how-to, which asks
//!   macOS to open the file the Finding concerns in the default editor; the
//!   app never reads it (spec section 8.5).
//! - `change_settings`: moves one choice of the Settings pane through the
//!   daemon's `settings` request; the pane follows the answer.
//! - `switch_gate`: **Stop the AI from using flagged items**, the daemon's
//!   `gate-hooks` request ([`crate::gate`]); the daemon writes or removes
//!   the entries and the pane follows its answer.
//! - `ai_check_look`, `change_engine`, `turn_on_claude`, `remove_claude_key`
//!   and `preview_request`: the AI check in the Settings pane
//!   ([`crate::ai_check`]). The Claude API key passes through
//!   `turn_on_claude` once, to the daemon, and the app keeps no copy.
//! - `install_cli`: **Install command line tool**, the link in
//!   `~/.local/bin` ([`crate::cli_link`]).
//! - `open_full_disk_access`: System Settings at Full Disk Access, best
//!   effort, or at Privacy & Security without an anchor.
//! - `show_rules_folder`: the user's own rules folder in Finder.
//! - `open_not_protected`: the README's list of what AgentSweep does not
//!   protect against, in the browser.
//! - `reveal_in_finder`: shows a quarantined Item's payload in Finder, in
//!   the Developer Posture only, at the path the daemon's reveal-receipt
//!   answer names (spec sections 5.1 and 8.5).
//! - `scan_now`: asks the daemon for a Full Scan; the progress arrives on the
//!   stream.
//! - `scan_folder`: **Scan a folder** from the popover or the Overview, which
//!   opens the one Scan a folder dialog on the Findings window
//!   ([`crate::folder`]).
//! - `choose_folder`, `scan_dropped`: the dialog's folder picker and its drop
//!   zone, each a Folder Scan by the daemon whose answer arrives on
//!   `agentsweep://folder`; `close_folder`: the dialog was closed.
//! - `onboarding`, `onboarding_back`, `onboarding_choose`, `onboarding_next`,
//!   `onboarding_engine`, `onboarding_claude`, `onboarding_toggle`,
//!   `onboarding_look_there`: the onboarding wizard's view and its moves
//!   ([`crate::onboarding`]); Next on screen 5 registers the daemon and the
//!   login item, and on screen 6 closes the wizard.
//!
//! Events the frontend may listen to:
//! - `agentsweep://view`: the popover's view, whenever it changes.
//! - `agentsweep://state-event`: every state event on the daemon's subscribe
//!   stream, as the wire carries it.
//! - `agentsweep://findings`: the Findings window's view, whenever the list,
//!   a count, the Overview or the Posture changes.
//! - `agentsweep://folder`: the Scan a folder dialog: open with no folder
//!   chosen, a drop refused, or the Folder Scan running, done or failed; null
//!   when it is closed.
//! - `agentsweep://pane`: the pane the Findings window turns to, by its id,
//!   when a click on a notification brought the app to the front.
//! - `agentsweep://activity-at`: the Event Log sequence the Activity pane
//!   opens at after an integrity button, or null for the pane alone.
//! - `agentsweep://onboarding`: the onboarding wizard's view, when the engine
//!   look arrived or screen 6's first check finished.
//!
//! Notifications (spec sections 6.7 and 8.7) are raised here through the
//! notification plugin, on every launch and on every stream event that may
//! carry one ([`crate::notifications`]). Launched with the windowless
//! argument, the app starts into the menu bar with no window
//! ([`crate::window::Start`]).

use std::sync::{Arc, Mutex};

use serde_json::Value;
use tauri::image::Image;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, LogicalPosition, Manager, Monitor, PhysicalPosition, Rect, RunEvent,
    WebviewWindow, WindowEvent,
};
use tauri_plugin_notification::{NotificationExt, PermissionState};

use agentsweep_core::envelope::Timestamp;
use agentsweep_core::keychain::ClaudeKey;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::settings::{JudgementEngine, Posture};
use agentsweep_ipc::protocol::{Message, StateEvent};

use crate::ai_check;
use crate::asking::{ActionRequest, Asking, refusal, scan_now_line};
use crate::banner::Button;
use crate::cli_link;
use crate::developer::offers_reveal;
use crate::false_alarm::{self, Reports, SystemBrowser};
use crate::findings::Follow;
use crate::folder;
use crate::frame::Frame;
use crate::gate;
use crate::glyph::{self, Mark};
use crate::how_to::{self, SystemOpener};
use crate::integrity;
use crate::inventory::Inventory;
use crate::link::{Link, Socket, Update};
use crate::notifications::{Activation, Notice, Notifications, Notifier};
use crate::onboarding::{self, Handover, Step, Wizard};
use crate::placement;
use crate::popover::View;
use crate::reveal::{self, SystemFinder};
use crate::settings_pane::{
    self, FULL_DISK_ACCESS_PANES, FULL_DISK_ACCESS_UNOPENED, NOT_PROTECTED_LINK,
};
use crate::supervision::{self, Services, SystemServices, Unsupervised};
use crate::uninstall;
use crate::window::{Presence, Start, presence};
use crate::wording;

/// The tray icon's id.
const TRAY: &str = "agentsweep";

/// The popover window's label, as `tauri.conf.json` declares it.
const POPOVER: &str = "popover";

/// The Findings window's label, as `tauri.conf.json` declares it.
const WINDOW: &str = "findings";

/// The onboarding wizard's label, as `tauri.conf.json` declares it.
const ONBOARDING: &str = "onboarding";

/// The event the onboarding wizard's view arrives on when it changed
/// outside its own commands: the engine look, and the first check finished.
pub const ONBOARDING_EVENT: &str = "agentsweep://onboarding";

/// The event the popover's view arrives on.
pub const VIEW_EVENT: &str = "agentsweep://view";

/// The event every daemon state event arrives on.
pub const STATE_EVENT: &str = "agentsweep://state-event";

/// The event the Findings window's list arrives on.
pub const FINDINGS_EVENT: &str = "agentsweep://findings";

/// The event the Folder Scan in hand arrives on.
pub const FOLDER_EVENT: &str = "agentsweep://folder";

/// The event that turns the Findings window to a pane.
pub const PANE_EVENT: &str = "agentsweep://pane";

/// The event that opens the Activity pane at one record.
pub const ACTIVITY_AT_EVENT: &str = "agentsweep://activity-at";

/// The notification plugin, which posts through the operating system.
struct PluginNotifier(AppHandle);

impl Notifier for PluginNotifier {
    fn ask_permission(&self) -> bool {
        matches!(
            self.0.notification().request_permission(),
            Ok(PermissionState::Granted)
        )
    }

    fn show(&self, notice: &Notice) -> bool {
        self.0
            .notification()
            .builder()
            .title(&notice.title)
            .body(&notice.body)
            .show()
            .is_ok()
    }
}

/// Raises every un-notified change the daemon holds when `event` may carry
/// one. The Health that opens every subscription is how this runs on
/// launch. A daemon that does not answer leaves them for the next trigger.
fn notify(app: &AppHandle, event: &StateEvent) {
    let Some(notifications) = app.try_state::<Notifications>() else {
        return;
    };
    let _ = notifications.follow(&app.state::<Shell>().asking, event);
}

/// The app came to the front: after a notification the Findings window
/// opens on Needs your decision; an ordinary activation does nothing extra.
fn activated(app: &AppHandle, activation: Activation) {
    let Some(pane) = app
        .try_state::<Notifications>()
        .and_then(|notifications| notifications.activated(activation))
    else {
        return;
    };
    show_window(app);
    let _ = app.emit(PANE_EVENT, pane.id());
}

/// Tells [`activated`] whenever the app becomes the active one, which is
/// what a click on one of its notifications does: the plugin has no click
/// callbacks on desktop (spec section 6.1).
#[cfg(target_os = "macos")]
fn observe_activation(app: &AppHandle) {
    use objc2_app_kit::NSApplicationDidBecomeActiveNotification;
    use objc2_foundation::{NSNotification, NSNotificationCenter};

    let handle = app.clone();
    let block = block2::RcBlock::new(move |_: std::ptr::NonNull<NSNotification>| {
        activated(&handle, Activation::BecameActive);
    });
    // SAFETY: the name is AppKit's own constant, no object or queue narrows
    // the observation, and the block captures only a handle that lives as
    // long as the app. The observer stays for the life of the process.
    let observer = unsafe {
        NSNotificationCenter::defaultCenter().addObserverForName_object_queue_usingBlock(
            Some(NSApplicationDidBecomeActiveNotification),
            None,
            None,
            &block,
        )
    };
    std::mem::forget(observer);
}

#[cfg(not(target_os = "macos"))]
fn observe_activation(_app: &AppHandle) {}

/// What the shell holds while it runs.
struct Shell {
    view: Mutex<View>,
    services: Arc<dyn Services>,
    frame: Mutex<Frame>,
    folder: Mutex<Value>,
    asking: Arc<Asking>,
    /// The wizard while onboarding shows, nothing once it is done.
    onboarding: Mutex<Option<Wizard>>,
    /// The answers held for the daemon since onboarding.
    handover: Mutex<Handover>,
}

/// The popover's view as it stands, in the window's Posture.
#[tauri::command]
fn popover(shell: tauri::State<'_, Shell>) -> Value {
    let posture = shell
        .frame
        .lock()
        .expect("the frame is not poisoned")
        .posture();
    shell
        .view
        .lock()
        .expect("the view is not poisoned")
        .to_value(posture)
}

/// Sends the popover's view as it stands, in the window's Posture.
fn send_view(app: &AppHandle) {
    let value = popover(app.state::<Shell>());
    let _ = app.emit(VIEW_EVENT, value);
}

/// Opens System Settings at Login Items, where approval is given.
#[tauri::command]
fn open_login_items(shell: tauri::State<'_, Shell>) {
    shell.services.open_login_items();
}

/// **Start it**: asks launchd to start the registered daemon job. The link
/// sees the daemon once it answers.
#[tauri::command]
async fn start_daemon(app: AppHandle) -> Result<String, String> {
    let services = Arc::clone(&app.state::<Shell>().services);
    tauri::async_runtime::spawn_blocking(move || supervision::start_daemon(&*services))
        .await
        .map_err(|error| format!("AgentSweep could not be started: {error}"))?
        .map(|()| "Starting AgentSweep.".to_string())
        .map_err(|why| format!("AgentSweep could not be started: {why}"))
}

/// One integrity button: its request, then the window on Activity at the
/// record it concerns.
async fn answer_records(app: AppHandle, button: Button) -> Result<String, String> {
    let (health, activity) = {
        let shell = app.state::<Shell>();
        let frame = shell.frame.lock().expect("the frame is not poisoned");
        (frame.health().clone(), frame.activity().clone())
    };
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let pressed = tauri::async_runtime::spawn_blocking(move || {
        integrity::press(button, &health, &activity, &*asking)
    })
    .await
    .map_err(|error| format!("AgentSweep could not be asked: {error}"))??;
    show_window(&app);
    let _ = app.emit(ACTIVITY_AT_EVENT, pressed.focus);
    Ok(pressed.line)
}

/// "Start a fresh record".
#[tauri::command]
async fn start_fresh_record(app: AppHandle) -> Result<String, String> {
    answer_records(app, Button::StartFreshRecord).await
}

/// "Look at the records".
#[tauri::command]
async fn look_at_records(app: AppHandle) -> Result<String, String> {
    answer_records(app, Button::LookAtRecords).await
}

/// "Show what changed".
#[tauri::command]
async fn show_what_changed(app: AppHandle) -> Result<String, String> {
    answer_records(app, Button::ShowWhatChanged).await
}

/// "Scan again, trusting nothing".
#[tauri::command]
async fn scan_again_trusting_nothing(app: AppHandle) -> Result<String, String> {
    answer_records(app, Button::ScanAgainTrustingNothing).await
}

/// Quits the app and nothing else.
#[tauri::command]
fn quit(app: AppHandle) {
    app.exit(0);
}

/// Opens the Findings window.
#[tauri::command]
fn open_window(app: AppHandle) {
    show_window(&app);
}

/// The Findings window's view, fetched first when it was never loaded.
#[tauri::command]
async fn findings(app: AppHandle) -> Result<Value, String> {
    let loaded = app
        .state::<Shell>()
        .frame
        .lock()
        .expect("the frame is not poisoned")
        .findings()
        .loaded();
    if !loaded {
        let handle = app.clone();
        let _ = tauri::async_runtime::spawn_blocking(move || refresh(&handle)).await;
    }
    Ok(app
        .state::<Shell>()
        .frame
        .lock()
        .expect("the frame is not poisoned")
        .to_value())
}

/// The last Folder Scan's view.
#[tauri::command]
fn folder(shell: tauri::State<'_, Shell>) -> Value {
    shell.folder.lock().expect("the folder view").clone()
}

/// Runs a blocking request off the main thread, its failure as a sentence.
async fn blocking<T: Send + 'static>(
    ask: impl FnOnce() -> Result<T, agentsweep_ipc::ClientError> + Send + 'static,
) -> Result<T, String> {
    match tauri::async_runtime::spawn_blocking(ask).await {
        Ok(Ok(answer)) => Ok(answer),
        Ok(Err(error)) => Err(refusal(&error)),
        Err(error) => Err(format!("AgentSweep could not be asked: {error}")),
    }
}

/// Carries out one action request and answers with its view, with the
/// one-time false-alarm card after a Restore or a Trust. The report is
/// prepared before the action, while the Finding is still listed as it was.
async fn act(app: AppHandle, request: Option<ActionRequest>) -> Result<Value, String> {
    let request = request.ok_or_else(|| "That is not an action AgentSweep knows.".to_string())?;
    let report = match request {
        ActionRequest::Restore(..) | ActionRequest::Trust(..) => {
            prepare_report(&app, request.target())
        }
        _ => None,
    };
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let asked = request.clone();
    let answer = tauri::async_runtime::spawn_blocking(move || asking.act(&asked))
        .await
        .map_err(|error| format!("AgentSweep could not be asked: {error}"))?;
    Ok(false_alarm::after_action(&request, answer, report.as_ref()))
}

/// The false-alarm report on a listed Finding, kept for the dialog's button.
fn prepare_report(app: &AppHandle, target: &str) -> Option<false_alarm::Report> {
    let report = {
        let shell = app.state::<Shell>();
        let frame = shell.frame.lock().expect("the frame is not poisoned");
        let finding = frame.findings().get(target)?;
        let context = false_alarm::Context {
            rule_pack: frame.health().rule_pack,
            app: app.package_info().version.to_string(),
            macos: false_alarm::this_macos(),
        };
        false_alarm::report(finding, &context)?
    };
    Some(app.state::<Reports>().keep(target, report))
}

/// **Report false positive** in a Finding's detail header: the prepared
/// issue, exactly as its address will carry it.
#[tauri::command]
fn false_alarm_report(app: AppHandle, target: String) -> Result<Value, String> {
    prepare_report(&app, &target)
        .map(|report| report.to_value())
        .ok_or_else(|| "This Finding names nothing that could be reported.".to_string())
}

/// The dialog's **Open on GitHub**: the issue the app prepared for the
/// Finding opens in the user's browser. The window names only the Finding,
/// never an address, and the app makes no request.
#[tauri::command]
async fn open_false_alarm_report(app: AppHandle, target: String) -> Result<String, String> {
    let report = app
        .state::<Reports>()
        .get(&target)
        .ok_or_else(|| "There is no prepared report for this Finding any more.".to_string())?;
    tauri::async_runtime::spawn_blocking(move || false_alarm::open_report(&report, &SystemBrowser))
        .await
        .map_err(|error| format!("The browser could not be opened: {error}"))?
}

/// A manual Quarantine, or switching a never-auto kind's line off.
#[tauri::command]
async fn quarantine(app: AppHandle, target: String) -> Result<Value, String> {
    act(app, ActionRequest::of("quarantine", &target, None)).await
}

/// A Restore: `refuse` first, `replace` or `beside` once the user chose.
#[tauri::command]
async fn restore(
    app: AppHandle,
    target: String,
    conflict: Option<String>,
) -> Result<Value, String> {
    act(
        app,
        ActionRequest::of("restore", &target, conflict.as_deref()),
    )
    .await
}

/// Trust this version, or keep an Exposure as it is.
#[tauri::command]
async fn trust(app: AppHandle, target: String) -> Result<Value, String> {
    act(app, ActionRequest::of("trust", &target, None)).await
}

/// "Yes, that was me" on a Drift question.
#[tauri::command]
async fn acknowledge(app: AppHandle, target: String) -> Result<Value, String> {
    act(app, ActionRequest::of("acknowledge", &target, None)).await
}

/// The one-click fix of Exposures 0018 and 0019.
#[tauri::command]
async fn fix(app: AppHandle, target: String) -> Result<Value, String> {
    act(app, ActionRequest::of("fix", &target, None)).await
}

/// A stopped plugin back on for its newer, clean version.
#[tauri::command]
async fn re_enable(app: AppHandle, target: String) -> Result<Value, String> {
    act(app, ActionRequest::of("re_enable", &target, None)).await
}

/// Delete permanently, asked only after the window's confirmation.
#[tauri::command]
async fn purge(app: AppHandle, target: String) -> Result<Value, String> {
    act(app, ActionRequest::of("purge", &target, None)).await
}

/// Stop trusting this, from the Trusted section of the Quarantine pane.
#[tauri::command]
async fn untrust(app: AppHandle, target: String) -> Result<Value, String> {
    act(app, ActionRequest::of("untrust", &target, None)).await
}

/// **Copy a message for your admin** on a Managed Finding: the message names
/// the Item and why it was flagged, and holds no value of it.
#[tauri::command]
fn copy_for_admin(shell: tauri::State<'_, Shell>, target: String) -> Result<String, String> {
    let finding = shell
        .frame
        .lock()
        .expect("the frame is not poisoned")
        .findings()
        .get(&target)
        .cloned()
        .ok_or_else(|| "That Finding is no longer listed.".to_string())?;
    let message = wording::simple(&finding)
        .admin_message
        .ok_or_else(|| "Only something your admin controls has a message for them.".to_string())?;
    match put_on_clipboard(&message) {
        true => Ok("A message for your admin is on the clipboard.".to_string()),
        false => Err("The message could not be put on the clipboard.".to_string()),
    }
}

/// **Open the file** in an Exposure's how-to: the file the daemon named
/// beside the Finding opens in the user's default editor. The window names
/// only the Finding, never a path, and the app never reads the file.
#[tauri::command]
async fn open_the_file(app: AppHandle, target: String) -> Result<String, String> {
    let (finding, posture) = {
        let shell = app.state::<Shell>();
        let frame = shell.frame.lock().expect("the frame is not poisoned");
        let finding = frame
            .findings()
            .get(&target)
            .cloned()
            .ok_or_else(|| "That Finding is no longer listed.".to_string())?;
        (finding, frame.posture())
    };
    tauri::async_runtime::spawn_blocking(move || {
        how_to::open_the_file(&finding, posture, &SystemOpener)
    })
    .await
    .map_err(|error| format!("The file could not be opened: {error}"))?
}

/// **Reveal in Finder** on a quarantined Item, in the Developer Posture: the
/// daemon names the payload through the reveal-receipt request, and the
/// Finder is asked on the main thread to select it.
#[tauri::command]
async fn reveal_in_finder(app: AppHandle, target: String) -> Result<String, String> {
    let (finding, posture) = {
        let shell = app.state::<Shell>();
        let frame = shell.frame.lock().expect("the frame is not poisoned");
        let finding = frame
            .findings()
            .get(&target)
            .cloned()
            .ok_or_else(|| "That Finding is no longer listed.".to_string())?;
        (finding, frame.posture())
    };
    if !offers_reveal(&finding, posture) {
        return Err(
            "Reveal in Finder is offered on a quarantined Item in the Developer Posture only."
                .to_string(),
        );
    }
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let receipts = tauri::async_runtime::spawn_blocking(move || asking.receipts())
        .await
        .map_err(|error| format!("AgentSweep could not be asked: {error}"))?;
    let (sender, receiver) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let _ = sender.send(reveal::reveal_in_finder(
            &finding,
            posture,
            || receipts,
            &SystemFinder,
        ));
    })
    .map_err(|error| format!("Finder could not be asked: {error}"))?;
    tauri::async_runtime::spawn_blocking(move || receiver.recv())
        .await
        .map_err(|error| format!("Finder could not be asked: {error}"))?
        .map_err(|error| format!("Finder could not be asked: {error}"))?
}

/// Puts text on the general pasteboard, answering whether it is there.
#[cfg(target_os = "macos")]
fn put_on_clipboard(text: &str) -> bool {
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
    use objc2_foundation::NSString;

    let board = NSPasteboard::generalPasteboard();
    board.clearContents();
    // SAFETY: the pasteboard type is a constant AppKit exports and never
    // changes.
    let kind = unsafe { NSPasteboardTypeString };
    board.setString_forType(&NSString::from_str(text), kind)
}

/// Anywhere but macOS there is no clipboard yet (spec section 6.1).
#[cfg(not(target_os = "macos"))]
fn put_on_clipboard(_text: &str) -> bool {
    false
}

/// Moves one choice of the Settings pane: the daemon answers with every
/// choice, which the frame takes and the window is sent again with.
#[tauri::command]
async fn change_settings(app: AppHandle, change: Value) -> Result<String, String> {
    let change = settings_pane::change_of(&change)?;
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let answer = blocking(move || asking.change_settings(&change))
        .await
        .map_err(|why| why.replace("Nothing was done", "Nothing was changed"))?;
    let follow = app
        .state::<Shell>()
        .frame
        .lock()
        .expect("the frame is not poisoned")
        .settings(&answer);
    if follow != Follow::Nothing {
        render(&app);
    }
    Ok(settings_pane::RECORDED.to_string())
}

/// Turns the Gate switch on or off through the daemon, which takes the
/// entries away from every Agent or registers them again; the pane follows
/// the answer.
#[tauri::command]
async fn switch_gate(app: AppHandle, on: bool) -> Result<String, String> {
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let answer = off_main(move || gate::switch(&asking, on)).await?;
    let follow = app
        .state::<Shell>()
        .frame
        .lock()
        .expect("the frame is not poisoned")
        .gate_hooks(answer);
    if follow != Follow::Nothing {
        render(&app);
    }
    Ok(settings_pane::RECORDED.to_string())
}

/// Takes the daemon's engine answer into the frame, sends the window again
/// and answers the line saying whether the change was recorded.
fn take_engine(app: &AppHandle, state: &agentsweep_ipc::engine::EngineState) -> String {
    let posture = {
        let shell = app.state::<Shell>();
        let mut frame = shell.frame.lock().expect("the frame is not poisoned");
        frame.engine(state);
        frame.posture()
    };
    render(app);
    ai_check::recorded_line(state, posture)
}

/// Runs one AI check step off the main thread.
async fn off_main<T: Send + 'static>(
    step: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(step)
        .await
        .map_err(|error| format!("AgentSweep could not be asked: {error}"))?
}

/// Asks the daemon where the AI check stands, with whether Ollama runs and
/// whether Apple's on-device model is available; the window asks it when
/// the Settings pane opens.
#[tauri::command]
async fn ai_check_look(app: AppHandle) -> Result<(), String> {
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let state = blocking(move || asking.engine()).await?;
    take_engine(&app, &state);
    Ok(())
}

/// Moves one choice of the AI check: an engine card, the Ollama address or
/// the Claude model id.
#[tauri::command]
async fn change_engine(app: AppHandle, change: Value) -> Result<String, String> {
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let state = off_main(move || ai_check::change(&asking, &change)).await?;
    Ok(take_engine(&app, &state))
}

/// "I agree, turn it on": the typed key, if any, goes to the daemon once and
/// is wiped here; then the Claude engine is turned on.
#[tauri::command]
async fn turn_on_claude(app: AppHandle, key: Option<String>) -> Result<String, String> {
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let state = off_main(move || ai_check::turn_on_claude(&asking, key)).await?;
    Ok(take_engine(&app, &state))
}

/// Removes the Claude API key, which turns the Claude engine off.
#[tauri::command]
async fn remove_claude_key(app: AppHandle) -> Result<String, String> {
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let state = off_main(move || ai_check::remove_claude_key(&asking)).await?;
    Ok(take_engine(&app, &state))
}

/// "Preview a request": the daemon's redacted request for Claude about one
/// Item, or about the sample Item.
#[tauri::command]
async fn preview_request(app: AppHandle, item: Option<String>) -> Result<Value, String> {
    let asking = Arc::clone(&app.state::<Shell>().asking);
    off_main(move || ai_check::preview(&asking, item.as_deref())).await
}

/// The Uninstall dialog, with how many Items are in quarantine now.
#[tauri::command]
async fn uninstall_offer(app: AppHandle) -> Result<Value, String> {
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let receipts = blocking(move || asking.receipts()).await?;
    Ok(uninstall::view(receipts.len()))
}

/// **Uninstall AgentSweep…** with the choice the dialog sent: the daemon
/// applies it, the registrations go, the app goes to the Trash and quits a
/// moment later, so the pane can say what was done (spec section 9.6).
#[tauri::command]
async fn uninstall_agentsweep(app: AppHandle, asked: Value) -> Result<Vec<String>, String> {
    let choice = uninstall::choice_of(&asked)?;
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let services = Arc::clone(&app.state::<Shell>().services);
    let bundle = std::env::current_exe()
        .ok()
        .and_then(|exe| uninstall::bundle_of(&exe));
    let done = tauri::async_runtime::spawn_blocking(move || {
        uninstall::carry_out(
            &asking,
            &*services,
            &uninstall::SystemTrash,
            bundle.as_deref(),
            choice,
        )
    })
    .await
    .map_err(|error| format!("AgentSweep could not be asked: {error}"))??;
    if done.trashed.is_ok() {
        let handle = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(4));
            handle.exit(0);
        });
    }
    Ok(done.lines())
}

/// The onboarding wizard's view, or nothing once it is done.
#[tauri::command]
fn onboarding(shell: tauri::State<'_, Shell>) -> Value {
    shell
        .onboarding
        .lock()
        .expect("the wizard is not poisoned")
        .as_ref()
        .map_or(Value::Null, Wizard::to_value)
}

/// Back in the wizard.
#[tauri::command]
fn onboarding_back(shell: tauri::State<'_, Shell>) -> Value {
    let mut held = shell.onboarding.lock().expect("the wizard is not poisoned");
    held.as_mut().map_or(Value::Null, |wizard| {
        wizard.back();
        wizard.to_value()
    })
}

/// An answer on screen 3: `simple` or `developer`.
#[tauri::command]
fn onboarding_choose(shell: tauri::State<'_, Shell>, posture: String) -> Result<Value, String> {
    let posture = Posture::parse(&posture)
        .ok_or_else(|| "That is not a choice AgentSweep knows.".to_string())?;
    let mut held = shell.onboarding.lock().expect("the wizard is not poisoned");
    Ok(held.as_mut().map_or(Value::Null, |wizard| {
        wizard.choose(posture);
        wizard.to_value()
    }))
}

/// Renders the wizard's view in the onboarding window, for a change that
/// did not come from one of its own commands.
fn show_wizard(app: &AppHandle) {
    let view = app
        .state::<Shell>()
        .onboarding
        .lock()
        .expect("the wizard is not poisoned")
        .as_ref()
        .map_or(Value::Null, Wizard::to_value);
    if !view.is_null() {
        let _ = app.emit(ONBOARDING_EVENT, view);
    }
}

/// Closes the wizard: it is done, and the app is a menu bar app again.
fn close_wizard(app: &AppHandle) {
    *app.state::<Shell>()
        .onboarding
        .lock()
        .expect("the wizard is not poisoned") = None;
    if let Some(window) = app.get_webview_window(ONBOARDING) {
        let _ = window.hide();
    }
    present(app, presence(false));
}

/// Next in the wizard. On screen 5 it registers the daemon and the login
/// item once, asks for notification permission, holds the answers until the
/// daemon answers, and moves to screen 6; on screen 6, once the first check
/// finished, it closes the wizard and the view is then nothing.
#[tauri::command]
async fn onboarding_next(app: AppHandle) -> Result<Value, String> {
    let step = {
        let shell = app.state::<Shell>();
        let mut held = shell.onboarding.lock().expect("the wizard is not poisoned");
        let Some(wizard) = held.as_mut() else {
            return Ok(Value::Null);
        };
        match wizard.forward() {
            Step::Register => Step::Register,
            Step::Done => Step::Done,
            Step::Moved | Step::ConfirmOllama | Step::Waiting => return Ok(wizard.to_value()),
        }
    };
    if step == Step::Done {
        close_wizard(&app);
        return Ok(Value::Null);
    }
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let shell = handle.state::<Shell>();
        let launched = {
            let mut held = shell.onboarding.lock().expect("the wizard is not poisoned");
            let mut handover = shell
                .handover
                .lock()
                .expect("the hand-over is not poisoned");
            held.as_mut().and_then(|wizard| {
                wizard.leave_background(&*shell.services, &mut handover, Timestamp::now())
            })
        };
        for failure in launched.iter().flat_map(|launched| &launched.failures) {
            eprintln!("agentsweep-menubar: {failure}");
        }
        if let Some(notifications) = handle.try_state::<Notifications>() {
            notifications.ask_permission_now();
        }
    })
    .await
    .map_err(|error| format!("AgentSweep could not register its background item: {error}"))?;
    // A daemon that already answers, as after a reinstall, takes the
    // answers now rather than at its next Health.
    let handle = app.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || hand_over(&handle)).await;
    Ok(onboarding(app.state::<Shell>()))
}

/// A choice on screen 4: `apple`, `ollama` or `off`. With `confirmed`, the
/// one confirmation Ollama needs was given.
#[tauri::command]
fn onboarding_engine(
    shell: tauri::State<'_, Shell>,
    engine: String,
    confirmed: Option<bool>,
) -> Result<Value, String> {
    let engine = JudgementEngine::parse(&engine)
        .ok_or_else(|| "That is not a choice AgentSweep knows.".to_string())?;
    let mut held = shell.onboarding.lock().expect("the wizard is not poisoned");
    let Some(wizard) = held.as_mut() else {
        return Ok(Value::Null);
    };
    wizard.choose_engine(engine)?;
    if confirmed == Some(true) {
        wizard.confirm_ollama();
    }
    Ok(wizard.to_value())
}

/// "I agree, turn it on" on the Claude consent screen in the wizard: the
/// typed key is held in memory for the daemon, which takes it once it
/// answers; the typed text is wiped before this returns.
#[tauri::command]
fn onboarding_claude(shell: tauri::State<'_, Shell>, key: Option<String>) -> Result<Value, String> {
    let mut held = shell.onboarding.lock().expect("the wizard is not poisoned");
    let Some(wizard) = held.as_mut() else {
        if let Some(typed) = key {
            ai_check::wipe(typed);
        }
        return Ok(Value::Null);
    };
    match key {
        Some(typed) => {
            let key = ClaudeKey::new(&typed);
            ai_check::wipe(typed);
            let key = key.map_err(|_| {
                "Nothing was changed: that does not look like a Claude API key.".to_string()
            })?;
            shell
                .handover
                .lock()
                .expect("the hand-over is not poisoned")
                .hold_key(key);
        }
        None => return Err("Nothing was changed: a Claude API key is needed.".to_string()),
    }
    wizard.agree_to_claude();
    Ok(wizard.to_value())
}

/// A toggle on screen 5: `rule_feed` or `update_check`.
#[tauri::command]
fn onboarding_toggle(
    shell: tauri::State<'_, Shell>,
    key: String,
    on: bool,
) -> Result<Value, String> {
    let mut held = shell.onboarding.lock().expect("the wizard is not poisoned");
    let Some(wizard) = held.as_mut() else {
        return Ok(Value::Null);
    };
    wizard.toggle(&key, on)?;
    Ok(wizard.to_value())
}

/// The button of screen 5's protected-location line: registers the daemon
/// and the login item once, and sends check-now once, as soon as the daemon
/// answers and its first Full Scan has found the projects that Need
/// Permission, so the operating system's prompt appears while the user is
/// looking.
#[tauri::command]
fn onboarding_look_there(app: AppHandle) -> Value {
    let shell = app.state::<Shell>();
    let launched = {
        let mut held = shell.onboarding.lock().expect("the wizard is not poisoned");
        let Some(wizard) = held.as_mut() else {
            return Value::Null;
        };
        if !wizard.look_there() {
            return wizard.to_value();
        }
        let now = Timestamp::now();
        let launched = wizard.register_once(&*shell.services, now);
        (wizard.to_value(), launched, now)
    };
    let (view, launched, since) = launched;
    for failure in launched.iter().flat_map(|launched| &launched.failures) {
        eprintln!("agentsweep-menubar: {failure}");
    }
    let asking = Arc::clone(&shell.asking);
    let _ = std::thread::Builder::new()
        .name("agentsweep-check-now".to_string())
        .spawn(move || check_now_when_ready(&asking, since));
    view
}

/// Waits, for five minutes at most, until the daemon answers and a Full
/// Scan that finished after `since` has pooled the projects, then sends
/// check-now once.
fn check_now_when_ready(asking: &Asking, since: Timestamp) {
    for _ in 0..300 {
        if let Ok(status) = asking.status()
            && !status.health.scanning
            && status
                .scan
                .as_ref()
                .is_some_and(|scan| scan.finished_at() >= since)
        {
            if let Err(error) = asking.check_now() {
                eprintln!("agentsweep-menubar: check-now was not taken: {error}");
            }
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    eprintln!("agentsweep-menubar: the daemon did not answer, so check-now was not sent");
}

/// Screen 6 asks the daemon for its status after `event` while it waits for
/// the first check, and shows what it found.
fn first_check(app: &AppHandle, event: &StateEvent) {
    let shell = app.state::<Shell>();
    let wants = shell
        .onboarding
        .lock()
        .expect("the wizard is not poisoned")
        .as_ref()
        .is_some_and(|wizard| wizard.wants_status(event));
    if !wants {
        return;
    }
    let Ok(status) = shell.asking.status() else {
        return;
    };
    let done = shell
        .onboarding
        .lock()
        .expect("the wizard is not poisoned")
        .as_mut()
        .is_some_and(|wizard| wizard.take_status(&status));
    if done {
        show_wizard(app);
    }
}

/// Hands the answers held since onboarding to the daemon, now that it
/// answers, and shows the window in the Posture it took.
fn hand_over(app: &AppHandle) {
    let shell = app.state::<Shell>();
    let state = shell
        .handover
        .lock()
        .expect("the hand-over is not poisoned")
        .deliver(&*shell.asking);
    if let Some(state) = state {
        let follow = shell
            .frame
            .lock()
            .expect("the frame is not poisoned")
            .settings(&state);
        if follow != Follow::Nothing {
            render(app);
        }
    }
}

/// Shows the onboarding wizard, which makes the app a regular app while it
/// is open.
fn show_onboarding(app: &AppHandle) {
    present(app, presence(true));
    if let Some(window) = app.get_webview_window(ONBOARDING) {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// **Install command line tool**: the link to the bundle's `agentsweep` in
/// `~/.local/bin`, answered with the lines the pane shows.
#[tauri::command]
fn install_cli() -> Result<Vec<String>, String> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| "Your home folder is not known, so nothing was installed.".to_string())?;
    let cli = std::env::current_exe()
        .ok()
        .and_then(|exe| cli_link::bundled_cli(&exe))
        .ok_or_else(|| {
            "This copy of AgentSweep carries no command line tool, so nothing was installed."
                .to_string()
        })?;
    let path = std::env::var_os("PATH");
    cli_link::install(std::path::Path::new(&home), &cli, path.as_deref())
        .map(|installed| installed.lines())
        .map_err(|refused| refused.to_string())
}

/// System Settings at Full Disk Access: each pane address in turn until one
/// opens, the last one without an anchor.
#[tauri::command]
fn open_full_disk_access() -> Result<(), String> {
    match FULL_DISK_ACCESS_PANES.iter().any(|pane| open(&[pane])) {
        true => Ok(()),
        false => Err(FULL_DISK_ACCESS_UNOPENED.to_string()),
    }
}

/// The user's own rules folder in Finder, or the data directory it belongs
/// in while it does not exist yet. The app creates nothing there.
#[tauri::command]
fn show_rules_folder() -> Result<String, String> {
    let directory =
        DataDirectory::for_user().ok_or_else(|| "Your home folder is not known.".to_string())?;
    let rules = directory.user_rules();
    if rules.is_dir() && open(&[std::ffi::OsStr::new("-R"), rules.as_os_str()]) {
        return Ok(String::new());
    }
    if directory.root().is_dir() && open(&[directory.root().as_os_str()]) {
        return Ok(
            "There is no rules.d folder yet. Make one here and put your rules in it.".to_string(),
        );
    }
    Err("AgentSweep has not made its folder yet. It does once it has started.".to_string())
}

/// The README's full list of what AgentSweep does not protect against, in
/// the browser. The address is fixed; the window cannot name another.
#[tauri::command]
fn open_not_protected() -> Result<(), String> {
    match open(&[NOT_PROTECTED_LINK]) {
        true => Ok(()),
        false => Err(format!(
            "The browser could not be opened: {NOT_PROTECTED_LINK}"
        )),
    }
}

/// Hands arguments to macOS's `open`, never through a shell, and answers
/// whether it succeeded.
fn open<S: AsRef<std::ffi::OsStr>>(arguments: &[S]) -> bool {
    std::process::Command::new("/usr/bin/open")
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Asks the daemon for a Full Scan. Its progress arrives on the stream.
#[tauri::command]
async fn scan_now(app: AppHandle) -> Result<String, String> {
    let asking = Arc::clone(&app.state::<Shell>().asking);
    blocking(move || asking.scan_now())
        .await
        .map(|started| scan_now_line(started).to_string())
}

/// **Scan a folder**, from the popover and from the Overview alike: shows
/// the Findings window with the Scan a folder dialog open on it. A Folder
/// Scan already running stays in sight.
#[tauri::command]
fn scan_folder(app: AppHandle) {
    show_window(&app);
    let current = app
        .state::<Shell>()
        .folder
        .lock()
        .expect("the folder view")
        .clone();
    if current["state"] == "running" {
        tell_folder(&app, current);
    } else {
        tell_folder(&app, folder::choosing_view());
    }
}

/// The dialog's **Choose a folder** button: the native folder picker, then a
/// Folder Scan by the daemon, whose answer arrives on `agentsweep://folder`.
#[tauri::command]
async fn choose_folder(app: AppHandle) -> Result<(), String> {
    let Some(picked) = pick_folder(&app).await? else {
        return Ok(());
    };
    run_folder_scan(&app, picked.display().to_string()).await;
    Ok(())
}

/// One drop onto the dialog: the paths it carried, resolved by the app to one
/// absolute folder path before the Folder Scan request is sent (ADR 0008),
/// or refused without asking the daemon.
#[tauri::command]
async fn scan_dropped(app: AppHandle, paths: Vec<String>) {
    match folder::resolve_drop(&paths) {
        Ok(root) => run_folder_scan(&app, root).await,
        Err(refused) => tell_folder(&app, folder::refused_view(&refused)),
    }
}

/// The dialog was closed: a window that loads later opens without it.
#[tauri::command]
fn close_folder(app: AppHandle) {
    *app.state::<Shell>().folder.lock().expect("the folder view") = Value::Null;
}

/// A Folder Scan of one absolute folder path by the daemon, on a connection
/// of its own, its progress and its answer sent to the dialog.
async fn run_folder_scan(app: &AppHandle, root: String) {
    let posture = app
        .state::<Shell>()
        .frame
        .lock()
        .expect("the frame is not poisoned")
        .posture();
    tell_folder(app, folder::running_view(&root, posture));
    let asking = Arc::clone(&app.state::<Shell>().asking);
    let path = root.clone();
    let view = tauri::async_runtime::spawn_blocking(move || folder::scan(&asking, &path, posture))
        .await
        .unwrap_or_else(|error| {
            folder::failed_view(
                &root,
                &format!("AgentSweep could not be asked: {error}"),
                posture,
            )
        });
    tell_folder(app, view);
}

/// The native folder picker, answering with the folder or nothing when the
/// user cancelled.
#[cfg(target_os = "macos")]
async fn pick_folder(app: &AppHandle) -> Result<Option<std::path::PathBuf>, String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    // The picker is AppKit's own panel, which runs on the main thread.
    app.run_on_main_thread(move || {
        let picked = rfd::FileDialog::new()
            .set_title("Scan a folder")
            .pick_folder();
        let _ = sender.send(picked);
    })
    .map_err(|error| format!("The folder picker could not be opened: {error}"))?;
    tauri::async_runtime::spawn_blocking(move || receiver.recv().ok().flatten())
        .await
        .map_err(|error| format!("The folder picker could not be opened: {error}"))
}

/// Anywhere but macOS there is no picker yet (spec section 6.1: the other
/// platforms are a later effort).
#[cfg(not(target_os = "macos"))]
async fn pick_folder(_app: &AppHandle) -> Result<Option<std::path::PathBuf>, String> {
    Err("Scan a folder is not available on this platform yet.".to_string())
}

/// Keeps and sends the Folder Scan view.
fn tell_folder(app: &AppHandle, view: Value) {
    *app.state::<Shell>().folder.lock().expect("the folder view") = view.clone();
    let _ = app.emit(FOLDER_EVENT, view);
}

/// Shows the Findings window and makes the app a regular one while it is
/// open (spec section 8.1; Tauri issue 15005 is why [`crate::window`] says
/// this is a hand check).
fn show_window(app: &AppHandle) {
    if let Some(notifications) = app.try_state::<Notifications>() {
        notifications.seen();
    }
    if let Some(popover) = app.get_webview_window(POPOVER) {
        let _ = popover.hide();
    }
    present(app, presence(true));
    if let Some(window) = app.get_webview_window(WINDOW) {
        // A window already open, or in the Dock, comes back where it was; one
        // that opens anew opens centred on the display the user is working on.
        let open = window.is_visible().unwrap_or(false) || window.is_minimized().unwrap_or(false);
        if !open && let Some(display) = display_under_pointer(app) {
            let placed = placement::window_position(display, size_of(&window));
            let _ = window.set_position(LogicalPosition::new(placed.x, placed.y));
        }
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Switches the activation policy: `Regular` while the window is open,
/// `Accessory` otherwise.
fn present(app: &AppHandle, presence: Presence) {
    #[cfg(target_os = "macos")]
    {
        let policy = match presence {
            Presence::Regular => tauri::ActivationPolicy::Regular,
            Presence::MenuBar => tauri::ActivationPolicy::Accessory,
        };
        let _ = app.set_activation_policy(policy);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (app, presence);
}

/// Asks the daemon for the status and the settings and loads the list and
/// the Posture from them. The Posture is read again with every status, so a
/// choice that moved while no daemon answered shows once one does; between
/// two statuses the `settings-changed` event keeps it.
fn refresh(app: &AppHandle) {
    let shell = app.state::<Shell>();
    let status = shell.asking.status();
    let settings = shell.asking.settings();
    let value = {
        let mut frame = shell.frame.lock().expect("the frame is not poisoned");
        match status {
            Ok(status) => frame.load(&status),
            // The link says Protection is off when the daemon is away; a
            // status that failed otherwise leaves the list as it was.
            Err(_) => return,
        }
        // Settings that cannot be read leave the Posture as it was.
        if let Ok(settings) = settings {
            frame.settings(&settings);
        }
        frame.to_value()
    };
    let _ = app.emit(FINDINGS_EVENT, value);
}

/// Sends the window's view as it stands, and the popover's with it, whose
/// banner follows the window's Posture.
fn render(app: &AppHandle) {
    let value = app
        .state::<Shell>()
        .frame
        .lock()
        .expect("the frame is not poisoned")
        .to_value();
    let _ = app.emit(FINDINGS_EVENT, value);
    send_view(app);
}

/// The glyph for a view, as a template image.
fn icon(view: &View) -> Image<'static> {
    Image::new_owned(glyph::pixels(Mark::of(view.orb)), glyph::SIZE, glyph::SIZE)
}

/// Takes one update from the link: a new view goes to the tray and the
/// popover, a state event to the window's frame and both windows.
fn take(app: &AppHandle, update: Update) {
    match update {
        Update::View(view) => {
            let shell = app.state::<Shell>();
            let follow = shell
                .frame
                .lock()
                .expect("the frame is not poisoned")
                .view(&view);
            if follow != Follow::Nothing {
                render(app);
            }
            let changed_glyph = {
                let mut held = shell.view.lock().expect("the view is not poisoned");
                if *held == view {
                    return;
                }
                let changed = Mark::of(held.orb) != Mark::of(view.orb);
                *held = view.clone();
                changed
            };
            if changed_glyph && let Some(tray) = app.tray_by_id(TRAY) {
                let _ = tray.set_icon(Some(icon(&view)));
                let _ = tray.set_icon_as_template(true);
            }
            if let Some(tray) = app.tray_by_id(TRAY) {
                let _ = tray.set_tooltip(Some(format!("AgentSweep: {}", view.sentence)));
            }
            send_view(app);
        }
        Update::Event(event) => {
            // Health arrives only from a daemon that answers, which is when
            // the answers held since onboarding are handed over.
            if matches!(event, StateEvent::HealthChanged { .. }) {
                hand_over(app);
            }
            first_check(app, &event);
            let follow = app
                .state::<Shell>()
                .frame
                .lock()
                .expect("the frame is not poisoned")
                .apply(&event);
            notify(app, &event);
            let _ = app.emit(STATE_EVENT, Message::Event(event).to_value());
            match follow {
                Follow::Nothing => {}
                // The move shows at once; the details follow from the status.
                Follow::Render => render(app),
                Follow::Refresh => {
                    render(app);
                    refresh(app);
                }
            }
        }
    }
}

/// Shows the popover under the tray icon, on the display the icon is on, or
/// hides it when it is showing.
fn toggle(app: &AppHandle, anchor: Rect) {
    let Some(window) = app.get_webview_window(POPOVER) else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        return;
    }
    // The tray reports the icon in the physical pixels of its own display.
    // The pointer is on the icon that was just clicked, so the display under
    // the pointer is the display under the icon.
    if let Some(display) = display_under_pointer(app) {
        let at = anchor.position.to_physical::<f64>(display.scale);
        let size = anchor.size.to_physical::<f64>(display.scale);
        let icon = placement::Icon {
            x: at.x,
            y: at.y,
            width: size.width,
            height: size.height,
        };
        let placed = placement::popover_position(icon, display, size_of(&window));
        let _ = window.set_position(LogicalPosition::new(placed.x, placed.y));
    }
    // A user who opens the popover has looked: bringing the app to the
    // front for it is an ordinary activation.
    if let Some(notifications) = app.try_state::<Notifications>() {
        notifications.seen();
    }
    let _ = window.show();
    let _ = window.set_focus();
}

/// A window's outer size in points.
fn size_of(window: &WebviewWindow) -> placement::Size {
    let scale = window.scale_factor().unwrap_or(1.0);
    let size = window
        .outer_size()
        .map(|size| size.to_logical::<f64>(scale))
        .unwrap_or_default();
    placement::Size {
        width: size.width,
        height: size.height,
    }
}

/// The display under the pointer, as the operating system reports it, or the
/// main display when there is none.
fn display_under_pointer(app: &AppHandle) -> Option<placement::Display> {
    let main = app.primary_monitor().ok().flatten();
    let under = app.cursor_position().ok().and_then(|pointer| {
        let scale = main.as_ref().map_or(1.0, Monitor::scale_factor);
        let point = placement::pointer_in_points(pointer.x, pointer.y, scale);
        app.monitor_from_point(point.x, point.y).ok().flatten()
    });
    under.or(main).map(|monitor| placement::Display {
        x: monitor.position().x,
        y: monitor.position().y,
        width: monitor.size().width,
        height: monitor.size().height,
        scale: monitor.scale_factor(),
    })
}

/// A frame that names the user's own rules folder for the Settings pane.
fn rules_folder_named(mut frame: Frame) -> Frame {
    if let Some(directory) = DataDirectory::for_user() {
        frame.set_rules_folder(directory.user_rules().display().to_string());
    }
    frame
}

/// Runs the app until it is quit, started the way `start` says.
pub fn run(start: Start) {
    // A debug build pointed at a developer's daemon supervises nothing, so a
    // hand run never registers the real launch agent or a login item.
    let socket = Socket::for_this_build();
    let services: Arc<dyn Services> = match socket {
        Socket::Installed => Arc::new(SystemServices),
        Socket::At(_) => Arc::new(Unsupervised),
    };
    let shell = Shell {
        view: Mutex::new(View::unknown()),
        services: Arc::clone(&services),
        frame: Mutex::new(rules_folder_named(Frame::new())),
        folder: Mutex::new(Value::Null),
        asking: Arc::new(Asking::new(socket.clone())),
        onboarding: Mutex::new(None),
        handover: Mutex::new(Handover::default()),
    };

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(shell)
        .manage(Reports::default())
        .invoke_handler(tauri::generate_handler![
            popover,
            open_login_items,
            start_daemon,
            start_fresh_record,
            look_at_records,
            show_what_changed,
            scan_again_trusting_nothing,
            quit,
            open_window,
            findings,
            folder,
            quarantine,
            restore,
            trust,
            acknowledge,
            fix,
            re_enable,
            purge,
            untrust,
            copy_for_admin,
            false_alarm_report,
            open_false_alarm_report,
            open_the_file,
            change_settings,
            switch_gate,
            ai_check_look,
            change_engine,
            turn_on_claude,
            remove_claude_key,
            preview_request,
            install_cli,
            open_full_disk_access,
            show_rules_folder,
            open_not_protected,
            reveal_in_finder,
            scan_now,
            scan_folder,
            choose_folder,
            scan_dropped,
            close_folder,
            onboarding,
            onboarding_back,
            onboarding_choose,
            onboarding_next,
            uninstall_offer,
            uninstall_agentsweep,
            onboarding_engine,
            onboarding_claude,
            onboarding_toggle,
            onboarding_look_there
        ])
        .setup(move |app| {
            // Menu bar only while idle: no Dock icon and no Cmd-Tab entry
            // (spec section 8.1).
            // A windowless start, by the daemon, is menu bar only too.
            present(app.handle(), start.presence());
            app.manage(Notifications::new(Box::new(PluginNotifier(
                app.handle().clone(),
            ))));
            observe_activation(app.handle());

            TrayIconBuilder::with_id(TRAY)
                .icon(icon(&View::unknown()))
                .icon_as_template(true)
                .tooltip("AgentSweep")
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        rect,
                        ..
                    } = event
                    {
                        toggle(tray.app_handle(), rect);
                    }
                })
                .build(app)?;

            if let Some(window) = app.get_webview_window(POPOVER) {
                let hide = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::Focused(false) = event {
                        let _ = hide.hide();
                    }
                });
                // A debug build can open the popover at start, so a developer
                // (or a screenshot) sees it without clicking the menu bar.
                if cfg!(debug_assertions)
                    && std::env::var_os("AGENTSWEEP_DEV_SHOW_POPOVER").is_some()
                {
                    let _ = window.set_position(PhysicalPosition::new(40.0, 80.0));
                    let _ = window.show();
                }
            }

            // Closing the Findings window, with its red button or with Cmd-W
            // (Close Window in the menu Tauri gives a macOS app by default),
            // hides it and makes the app menu bar only again. Cmd-Q (Quit in
            // that menu, shown while the window makes the app a regular one)
            // quits the app as the popover's Quit does; the daemon is a
            // launch agent of its own and keeps running. The owner's decision
            // of 2026-10-14.
            if let Some(window) = app.get_webview_window(WINDOW) {
                let hide = window.clone();
                let handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = hide.hide();
                        present(&handle, presence(false));
                    }
                });
                if cfg!(debug_assertions)
                    && start == Start::Ordinary
                    && std::env::var_os("AGENTSWEEP_DEV_SHOW_WINDOW").is_some()
                {
                    show_window(app.handle());
                }
            }

            // Closing the wizard hides it; it shows again on the next launch,
            // since the daemon is still not registered.
            if let Some(window) = app.get_webview_window(ONBOARDING) {
                let hide = window.clone();
                let handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = hide.hide();
                        present(&handle, presence(false));
                    }
                });
            }

            // The registrations and the link run off the main thread: both
            // wait on the operating system, and the menu bar must not.
            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("agentsweep-link".to_string())
                .spawn(move || {
                    // A launch where the daemon is not registered shows the
                    // onboarding wizard and registers nothing; its screen 2
                    // is the Inventory, which the app runs itself.
                    if start.shows_onboarding(supervision::shows_onboarding(&*services)) {
                        let inventory = Inventory::of_this_mac().unwrap_or_default();
                        *handle
                            .state::<Shell>()
                            .onboarding
                            .lock()
                            .expect("the wizard is not poisoned") = Some(Wizard::new(inventory));
                        show_onboarding(&handle);
                        // Screen 4 preselects from the engine answer: the
                        // daemon's, when one already answers, else the same
                        // look taken on this Mac.
                        let look = handle
                            .state::<Shell>()
                            .asking
                            .engine()
                            .unwrap_or_else(|_| onboarding::look_here());
                        if let Some(wizard) = handle
                            .state::<Shell>()
                            .onboarding
                            .lock()
                            .expect("the wizard is not poisoned")
                            .as_mut()
                        {
                            wizard.look(look);
                        }
                        show_wizard(&handle);
                    }
                    let launched = supervision::on_launch(&*services);
                    for failure in &launched.failures {
                        eprintln!("agentsweep-menubar: {failure}");
                    }
                    Link::new(socket, services).run(|update| take(&handle, update));
                })?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("the AgentSweep app builds");
    app.run(|app, event| {
        // macOS asks a running app to reopen when it is launched again or
        // clicked in Finder; after a notification that opens the window.
        #[cfg(target_os = "macos")]
        if let RunEvent::Reopen { .. } = event {
            activated(app, Activation::Reopen);
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (app, event);
    });
}
