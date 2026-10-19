//! The AgentSweep menu bar app.
//!
//! The app never scans (spec section 6.2). It shows the onboarding wizard
//! while the daemon is not registered, registers the daemon and itself with
//! SMAppService from its last screen, keeps one subscription to the daemon
//! open, and renders
//! what comes down it: the status orb, one Health sentence by precedence, the
//! last check time, and "Protection is off" with the way to Login Items when
//! the daemon is not running or not allowed to. It is menu bar only while
//! idle.
//!
//! Layout:
//! - [`launch_agent`]: the plist the bundle carries and the names in it.
//! - [`inventory`]: the onboarding Inventory, which the app runs itself.
//! - [`onboarding`]: the onboarding wizard and the answers it holds for the
//!   daemon.
//! - [`supervision`]: SMAppService for the daemon and the login item, and the
//!   decisions over it.
//! - [`link`]: the connection to the daemon and the version handshake.
//! - [`asking`]: the requests the window and the popover send, on a
//!   connection of their own, and their answers in the command line
//!   interface's words.
//! - [`popover`]: the view the popover renders.
//! - [`banner`]: the integrity and Protection banners that replace the
//!   status sentence, and their buttons.
//! - [`integrity`]: what the integrity buttons ask the daemon and where the
//!   Activity pane opens after them.
//! - [`findings`]: the Findings window's list, kept from the status and the
//!   subscribe stream, with the actions the daemon allows on each Finding.
//! - [`actions`]: the buttons of spec section 8.5 on one Finding in a
//!   Posture, and the confirmations before and after them.
//! - [`frame`]: the window's sidebar, its counts, the two Finding panes and
//!   the Posture the window is shown in.
//! - [`quarantine`]: the Quarantine pane: every Item in quarantine with its
//!   actions, and the Trusted section at its foot.
//! - [`activity`]: the Activity pane: the Event Log's lines, newest first,
//!   followed from the stream.
//! - [`overview`]: the Overview pane: the status sentence, the Agents, the
//!   last check, the Rule Pack's date and the Scan in hand.
//! - [`wording`]: how a Finding reads in the Simple Posture, and the
//!   technical table behind it.
//! - [`developer`]: how a Finding reads in the Developer Posture, the
//!   Ambiguous Items it alone lists, and when Reveal in Finder is offered.
//! - [`reveal`]: Reveal in Finder through the daemon's reveal-receipt
//!   request, behind a Finder seam.
//! - [`how_to`]: **Show me how to fix this** on an Exposure, and **Open the
//!   file** behind an Opener seam; the app never reads the file.
//! - [`folder`]: the answer of a Folder Scan as the window shows it.
//! - [`settings_pane`]: the Settings pane: the Detail choice, the background
//!   toggles, Advanced and what AgentSweep does not protect against.
//! - [`ai_check`]: the AI check in the Settings pane: the four engine
//!   cards, the Ollama confirmation, the Claude consent screen and the key
//!   handed to the daemon once.
//! - [`cli_link`]: **Install command line tool**, the link in
//!   `~/.local/bin`.
//! - [`notifications`]: what each un-notified change says when the app
//!   raises it, behind a Notifier seam, and the window it opens after.
//! - [`window`]: when the app shows in the Dock and how it starts.
//! - [`placement`]: where the popover and the Findings window open.
//! - [`glyph`]: the menu bar icon in its three states.
//! - [`app`]: the Tauri shell around them, which the suite never starts.

#![warn(missing_docs)]

pub mod actions;
pub mod activity;
pub mod ai_check;
pub mod app;
pub mod asking;
pub mod banner;
pub mod cli_link;
pub mod developer;
pub mod findings;
pub mod folder;
pub mod frame;
pub mod glyph;
pub mod how_to;
pub mod integrity;
pub mod inventory;
pub mod launch_agent;
pub mod link;
pub mod notifications;
pub mod onboarding;
pub mod overview;
pub mod placement;
pub mod popover;
pub mod quarantine;
pub mod reveal;
pub mod settings_pane;
pub mod supervision;
pub mod window;
pub mod wording;
