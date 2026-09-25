//! When the app shows in the Dock (spec section 8.1, "Dock and Cmd-Tab").
//!
//! Menu bar only while idle; a regular app with a Dock icon, a Cmd-Tab entry
//! and menus while the Findings window is open; menu bar only again once it
//! is closed. The popover never counts: it is part of the menu bar.
//!
//! Tauri issue 15005 reports the Dock icon of a menu-bar-only app misbehaving
//! when the app is launched from an installed bundle rather than in
//! development. The switch below is the design either way; whether an
//! installed bundle honours it is a hand check on every release draft
//! (`docs/hand-checks.md`), and a fix, if one is needed, patches the switch
//! rather than the design (spec section 12).

/// How the app presents itself to macOS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    /// Menu bar only: no Dock icon, no Cmd-Tab entry. `Accessory`.
    MenuBar,
    /// A regular app: Dock icon, Cmd-Tab, menus. `Regular`.
    Regular,
}

/// The presence the app takes with the Findings window open or closed.
pub fn presence(window_open: bool) -> Presence {
    match window_open {
        true => Presence::Regular,
        false => Presence::MenuBar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dock_icon_shows_only_while_the_window_is_open() {
        assert_eq!(presence(true), Presence::Regular);
        assert_eq!(presence(false), Presence::MenuBar);
    }
}
