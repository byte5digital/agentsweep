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
//! - `quit`: quits the app. Protection stays on: the daemon is a launch agent
//!   of its own and does not go with the app.
//! - `open_window`: opens the Findings window, which makes the app a regular
//!   app with a Dock icon until the window is closed.
//! - `findings`: the Findings window's view as it stands: the list, the
//!   sidebar with its counts, the Overview, the two Finding panes and the
//!   Posture.
//! - `folder`: the last Folder Scan's view, for a window that just loaded.
//! - `quarantine`, `restore`, `trust`, `acknowledge`, `fix`, `re_enable`: the
//!   action requests, each answered with the daemon's sentence, the lines
//!   under it (after a Quarantine, its confirmation) and, for a Restore that
//!   met something else at the original place, the two conflict choices. A
//!   Quarantine of a never-auto kind is the switch that neutralises its line
//!   in place, and its Restore switches the line back on.
//! - `copy_for_admin`: puts the message about a Managed Finding for whoever
//!   administers the Mac on the clipboard (spec section 8.4).
//! - `change_settings`: moves one choice of the Settings pane through the
//!   daemon's `settings` request; the pane follows the answer.
//! - `install_cli`: **Install command line tool**, the link in
//!   `~/.local/bin` ([`crate::cli_link`]).
//! - `open_full_disk_access`: System Settings at Full Disk Access, best
//!   effort, or at Privacy & Security without an anchor.
//! - `show_rules_folder`: the user's own rules folder in Finder.
//! - `open_not_protected`: the README's list of what AgentSweep does not
//!   protect against, in the browser.
//! - `scan_now`: asks the daemon for a Full Scan; the progress arrives on the
//!   stream.
//! - `scan_folder`: the native folder picker, then a Folder Scan by the
//!   daemon, whose answer arrives on `agentsweep://folder`.
//!
//! Events the frontend may listen to:
//! - `agentsweep://view`: the popover's view, whenever it changes.
//! - `agentsweep://state-event`: every state event on the daemon's subscribe
//!   stream, as the wire carries it.
//! - `agentsweep://findings`: the Findings window's view, whenever the list,
//!   a count, the Overview or the Posture changes.
//! - `agentsweep://folder`: the Folder Scan in hand: running, done or failed.

use std::sync::{Arc, Mutex};

use serde_json::Value;
use tauri::image::Image;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, LogicalPosition, Manager, Monitor, PhysicalPosition, Rect, WebviewWindow,
    WindowEvent,
};

use agentsweep_core::paths::DataDirectory;
use agentsweep_ipc::protocol::Message;

use crate::asking::{ActionRequest, Asking, refusal, scan_now_line};
use crate::cli_link;
use crate::findings::Follow;
use crate::folder;
use crate::frame::Frame;
use crate::glyph::{self, Mark};
use crate::link::{Link, Socket, Update};
use crate::placement;
use crate::popover::View;
use crate::settings_pane::{
    self, FULL_DISK_ACCESS_PANES, FULL_DISK_ACCESS_UNOPENED, NOT_PROTECTED_LINK,
};
use crate::supervision::{self, Services, SystemServices, Unsupervised};
use crate::window::{Presence, presence};
use crate::wording;

/// The tray icon's id.
const TRAY: &str = "agentsweep";

/// The popover window's label, as `tauri.conf.json` declares it.
const POPOVER: &str = "popover";

/// The Findings window's label, as `tauri.conf.json` declares it.
const WINDOW: &str = "findings";

/// The event the popover's view arrives on.
pub const VIEW_EVENT: &str = "agentsweep://view";

/// The event every daemon state event arrives on.
pub const STATE_EVENT: &str = "agentsweep://state-event";

/// The event the Findings window's list arrives on.
pub const FINDINGS_EVENT: &str = "agentsweep://findings";

/// The event the Folder Scan in hand arrives on.
pub const FOLDER_EVENT: &str = "agentsweep://folder";

/// What the shell holds while it runs.
struct Shell {
    view: Mutex<View>,
    services: Arc<dyn Services>,
    frame: Mutex<Frame>,
    folder: Mutex<Value>,
    asking: Arc<Asking>,
}

/// The popover's view as it stands.
#[tauri::command]
fn popover(shell: tauri::State<'_, Shell>) -> Value {
    shell
        .view
        .lock()
        .expect("the view is not poisoned")
        .to_value()
}

/// Opens System Settings at Login Items, where approval is given.
#[tauri::command]
fn open_login_items(shell: tauri::State<'_, Shell>) {
    shell.services.open_login_items();
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

/// Carries out one action request and answers with its view.
async fn act(app: AppHandle, request: Option<ActionRequest>) -> Result<Value, String> {
    let request = request.ok_or_else(|| "That is not an action AgentSweep knows.".to_string())?;
    let asking = Arc::clone(&app.state::<Shell>().asking);
    tauri::async_runtime::spawn_blocking(move || asking.act(&request))
        .await
        .map_err(|error| format!("AgentSweep could not be asked: {error}"))
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

/// The folder picker, then a Folder Scan by the daemon. The window opens
/// first, so the picker and the answer have somewhere to be.
#[tauri::command]
async fn scan_folder(app: AppHandle) -> Result<Value, String> {
    show_window(&app);
    let Some(picked) = pick_folder(&app).await? else {
        return Ok(Value::Null);
    };
    let root = picked.display().to_string();
    tell_folder(&app, folder::running_view(&root));

    let asking = Arc::clone(&app.state::<Shell>().asking);
    let path = root.clone();
    let view = match blocking(move || asking.folder_scan(&path)).await {
        Ok(result) => folder::result_view(&result),
        Err(why) => folder::failed_view(
            &root,
            &why.replace("Nothing was done", "Nothing was checked"),
        ),
    };
    tell_folder(&app, view.clone());
    Ok(view)
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

/// Sends the window's view as it stands.
fn render(app: &AppHandle) {
    let value = app
        .state::<Shell>()
        .frame
        .lock()
        .expect("the frame is not poisoned")
        .to_value();
    let _ = app.emit(FINDINGS_EVENT, value);
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
            let _ = app.emit(VIEW_EVENT, view.to_value());
        }
        Update::Event(event) => {
            let follow = app
                .state::<Shell>()
                .frame
                .lock()
                .expect("the frame is not poisoned")
                .apply(&event);
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

/// Runs the app until it is quit.
pub fn run() {
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
    };

    tauri::Builder::default()
        .manage(shell)
        .invoke_handler(tauri::generate_handler![
            popover,
            open_login_items,
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
            copy_for_admin,
            change_settings,
            install_cli,
            open_full_disk_access,
            show_rules_folder,
            open_not_protected,
            scan_now,
            scan_folder
        ])
        .setup(move |app| {
            // Menu bar only while idle: no Dock icon and no Cmd-Tab entry
            // (spec section 8.1).
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

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
                    && std::env::var_os("AGENTSWEEP_DEV_SHOW_WINDOW").is_some()
                {
                    show_window(app.handle());
                }
            }

            // The registrations and the link run off the main thread: both
            // wait on the operating system, and the menu bar must not.
            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("agentsweep-link".to_string())
                .spawn(move || {
                    let launched = supervision::on_launch(&*services);
                    for failure in &launched.failures {
                        eprintln!("agentsweep-menubar: {failure}");
                    }
                    Link::new(socket, services).run(|update| take(&handle, update));
                })?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the AgentSweep app runs");
}
