//! When the app shows in the Dock (spec section 8.1, "Dock and Cmd-Tab"),
//! and how it starts (spec section 6.7).
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

/// How the app was started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Start {
    /// By the user, from Finder, Spotlight or the login item.
    Ordinary,
    /// By the daemon, with [`agentsweep_ipc::WINDOWLESS`], because it has
    /// something to tell and no app was running (spec section 6.7): into the
    /// menu bar with no window and no Dock icon, to notify and stay.
    Windowless,
}

impl Start {
    /// How the app was started, from its launch arguments (without the
    /// program name).
    pub fn of<I: IntoIterator<Item = S>, S: AsRef<str>>(arguments: I) -> Start {
        match arguments
            .into_iter()
            .any(|argument| argument.as_ref() == agentsweep_ipc::WINDOWLESS)
        {
            true => Start::Windowless,
            false => Start::Ordinary,
        }
    }

    /// Whether the onboarding wizard may show at start while the daemon is
    /// not registered. A windowless start shows no window at all.
    pub fn shows_onboarding(self, unregistered: bool) -> bool {
        self == Start::Ordinary && unregistered
    }

    /// The presence the app starts with: menu bar only either way, which is
    /// also what the bundle's `LSUIElement` says before the first line runs.
    pub fn presence(self) -> Presence {
        presence(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_windowless_argument_starts_into_the_menu_bar_with_no_window() {
        let start = Start::of(["--windowless"]);
        assert_eq!(start, Start::Windowless);
        assert!(!start.shows_onboarding(true));
        assert!(!start.shows_onboarding(false));
        assert_eq!(start.presence(), Presence::MenuBar);
    }

    #[test]
    fn without_it_the_app_starts_as_before() {
        let start = Start::of(Vec::<String>::new());
        assert_eq!(start, Start::Ordinary);
        assert_eq!(Start::of(["--developer-status"]), Start::Ordinary);
        assert!(start.shows_onboarding(true));
        assert!(!start.shows_onboarding(false));
        assert_eq!(start.presence(), Presence::MenuBar);
    }

    #[test]
    fn the_dock_icon_shows_only_while_the_window_is_open() {
        assert_eq!(presence(true), Presence::Regular);
        assert_eq!(presence(false), Presence::MenuBar);
    }
}
