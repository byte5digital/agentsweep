//! The AgentSweep menu bar app.
//!
//! The app never scans (spec section 6.2). It registers the daemon and itself
//! with SMAppService, keeps one subscription to the daemon open, and renders
//! what comes down it: the status orb, one Health sentence by precedence, the
//! last check time, and "Protection is off" with the way to Login Items when
//! the daemon is not running or not allowed to. It is menu bar only while
//! idle.
//!
//! Layout:
//! - [`launch_agent`]: the plist the bundle carries and the names in it.
//! - [`supervision`]: SMAppService for the daemon and the login item, and the
//!   decisions over it.
//! - [`link`]: the connection to the daemon and the version handshake.
//! - [`popover`]: the view the popover renders.
//! - [`glyph`]: the menu bar icon in its three states.
//! - [`app`]: the Tauri shell around them, which the suite never starts.

#![warn(missing_docs)]

pub mod app;
pub mod glyph;
pub mod launch_agent;
pub mod link;
pub mod popover;
pub mod supervision;
