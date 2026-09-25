//! The Tauri shell: the tray icon, the popover window and the commands the
//! popover calls.
//!
//! Everything that decides something is in the modules beside this one and is
//! tested there; this is the part that needs a window server, which the suite
//! never starts.
//!
//! Commands the frontend may call:
//! - `popover`: the view as it stands, for a popover that just loaded.
//! - `open_login_items`: System Settings at Login Items.
//! - `quit`: quits the app. Protection stays on: the daemon is a launch agent
//!   of its own and does not go with the app.
//!
//! Events the frontend may listen to:
//! - `agentsweep://view`: the popover's view, whenever it changes.
//! - `agentsweep://state-event`: every state event on the daemon's subscribe
//!   stream, as the wire carries it.

use std::sync::{Arc, Mutex};

use tauri::image::Image;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, Rect, WindowEvent};

use crate::glyph::{self, Mark};
use crate::link::{Link, Socket, Update};
use crate::popover::View;
use crate::supervision::{self, Services, SystemServices, Unsupervised};

/// The tray icon's id.
const TRAY: &str = "agentsweep";

/// The popover window's label, as `tauri.conf.json` declares it.
const POPOVER: &str = "popover";

/// The event the popover's view arrives on.
pub const VIEW_EVENT: &str = "agentsweep://view";

/// The event every daemon state event arrives on.
pub const STATE_EVENT: &str = "agentsweep://state-event";

/// What the shell holds while it runs.
struct Shell {
    view: Mutex<View>,
    services: Arc<dyn Services>,
}

/// The view as it stands.
#[tauri::command]
fn popover(shell: tauri::State<'_, Shell>) -> serde_json::Value {
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

/// The glyph for a view, as a template image.
fn icon(view: &View) -> Image<'static> {
    Image::new_owned(glyph::pixels(Mark::of(view.orb)), glyph::SIZE, glyph::SIZE)
}

/// Takes one update from the link: a new view goes to the tray and the
/// popover, a state event to the popover.
fn take(app: &AppHandle, update: Update) {
    match update {
        Update::View(view) => {
            let shell = app.state::<Shell>();
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
            let _ = app.emit(STATE_EVENT, event);
        }
    }
}

/// Shows the popover under the tray icon, or hides it when it is showing.
fn toggle(app: &AppHandle, anchor: Rect) {
    let Some(window) = app.get_webview_window(POPOVER) else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        return;
    }
    let scale = window.scale_factor().unwrap_or(1.0);
    let at = anchor.position.to_physical::<f64>(scale);
    let size = anchor.size.to_physical::<f64>(scale);
    let width = window
        .outer_size()
        .map(|size| f64::from(size.width))
        .unwrap_or(0.0);
    let x = at.x + size.width / 2.0 - width / 2.0;
    let y = at.y + size.height;
    let _ = window.set_position(PhysicalPosition::new(x.max(0.0), y));
    let _ = window.show();
    let _ = window.set_focus();
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
    };

    tauri::Builder::default()
        .manage(shell)
        .invoke_handler(tauri::generate_handler![popover, open_login_items, quit])
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
