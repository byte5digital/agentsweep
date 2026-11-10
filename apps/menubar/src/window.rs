//! When the app shows in the Dock (spec section 8.1, "Dock and Cmd-Tab"),
//! how it starts (spec sections 6.7 and 8.1), and what a reopen of the
//! running app shows.
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
    /// By the user: from Finder, the Dock, Spotlight or `open`. Opens the
    /// Findings window (spec section 8.1).
    Ordinary,
    /// By macOS at login, through the app's login item (spec section 9.5):
    /// into the menu bar with no window.
    AtLogin,
    /// By the daemon, with [`agentsweep_ipc::WINDOWLESS`], because it has
    /// something to tell and no app was running (spec section 6.7): into the
    /// menu bar with no window and no Dock icon, to notify and stay.
    Windowless,
}

impl Start {
    /// How the app was started, from its launch arguments (without the
    /// program name). Whether it was the login item only AppKit knows, once
    /// the app has finished launching ([`Start::at_login`]).
    pub fn of<I: IntoIterator<Item = S>, S: AsRef<str>>(arguments: I) -> Start {
        match arguments
            .into_iter()
            .any(|argument| argument.as_ref() == agentsweep_ipc::WINDOWLESS)
        {
            true => Start::Windowless,
            false => Start::Ordinary,
        }
    }

    /// The start once AppKit said whether the login item launched the app.
    /// A windowless start stays windowless whatever launched it.
    pub fn at_login(self, launched_as_login_item: bool) -> Start {
        match (self, launched_as_login_item) {
            (Start::Ordinary, true) => Start::AtLogin,
            (start, _) => start,
        }
    }

    /// Whether the onboarding wizard may show at start while the daemon is
    /// not registered: at every launch (spec section 8.3) but the windowless
    /// one, which shows no window at all.
    pub fn shows_onboarding(self, unregistered: bool) -> bool {
        self != Start::Windowless && unregistered
    }

    /// Whether the Findings window opens at start: on a launch by the user,
    /// unless the onboarding wizard shows in its place. A launch at login and
    /// a windowless one open no window (spec section 8.1).
    pub fn opens_window(self, unregistered: bool) -> bool {
        self == Start::Ordinary && !self.shows_onboarding(unregistered)
    }

    /// The presence the app starts with: menu bar only either way, which is
    /// also what the bundle's `LSUIElement` says before the first line runs.
    pub fn presence(self) -> Presence {
        presence(false)
    }
}

/// `kAEOpenApplication`, the Apple event that launches an app.
pub const OPEN_APPLICATION: u32 = u32::from_be_bytes(*b"oapp");

/// `keyAEPropData`, the parameter of that event which says how it came.
pub const PROPERTY_DATA: u32 = u32::from_be_bytes(*b"prdt");

/// `keyAELaunchedAsLogInItem`, the value that parameter has when the login
/// item launched the app.
pub const LAUNCHED_AS_LOGIN_ITEM: u32 = u32::from_be_bytes(*b"lgit");

/// Whether the Apple event the app was launched with says the login item
/// launched it: its id and, when it has one, the enumerated value of its
/// [`PROPERTY_DATA`] parameter, as AppKit reports them once the app has
/// finished launching.
pub fn launched_at_login(event: Option<u32>, property: Option<u32>) -> bool {
    event == Some(OPEN_APPLICATION) && property == Some(LAUNCHED_AS_LOGIN_ITEM)
}

/// Whether the login item launched the app, from the Apple event AppKit is
/// handling. It still holds the one the app was launched with while the app
/// finishes launching, which is when Tauri runs the app's setup.
#[cfg(target_os = "macos")]
pub fn launched_as_login_item() -> bool {
    use objc2_foundation::NSAppleEventManager;

    NSAppleEventManager::sharedAppleEventManager()
        .currentAppleEvent()
        .is_some_and(|event| says_login_item(&event))
}

/// Not on macOS: no login item launches the app.
#[cfg(not(target_os = "macos"))]
pub fn launched_as_login_item() -> bool {
    false
}

/// Whether `event` is the launch of the app by its login item.
#[cfg(target_os = "macos")]
fn says_login_item(event: &objc2_foundation::NSAppleEventDescriptor) -> bool {
    use objc2::rc::Retained;
    use objc2_foundation::NSAppleEventDescriptor;

    // SAFETY: `eventID` and `paramDescriptorForKeyword:` are methods of
    // NSAppleEventDescriptor that take and answer four-character codes.
    // objc2-foundation types them only behind a feature that would add a
    // crate, so they are sent directly, with the signatures AppKit declares.
    let id: u32 = unsafe { objc2::msg_send![event, eventID] };
    let property: Option<Retained<NSAppleEventDescriptor>> =
        unsafe { objc2::msg_send![event, paramDescriptorForKeyword: PROPERTY_DATA] };
    launched_at_login(Some(id), property.map(|property| property.enumCodeValue()))
}

/// What a reopen of the running app shows: a double-click on it in Finder, a
/// click on its Dock icon, or a launch of it while it runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reopened {
    /// The onboarding wizard, while it is not done: the window it stands for.
    Wizard,
    /// The Findings window (spec section 8.1).
    Window,
}

/// What a reopen shows, with or without the onboarding wizard in hand.
pub fn reopened(wizard_held: bool) -> Reopened {
    match wizard_held {
        true => Reopened::Wizard,
        false => Reopened::Window,
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
    fn a_launch_by_the_user_opens_the_window() {
        let start = Start::of(Vec::<String>::new()).at_login(false);
        assert_eq!(start, Start::Ordinary);
        assert!(start.opens_window(false));
        // While the daemon is not registered the wizard shows in its place.
        assert!(!start.opens_window(true));
        assert!(start.shows_onboarding(true));
    }

    #[test]
    fn a_launch_at_login_opens_no_window() {
        let start = Start::of(Vec::<String>::new()).at_login(true);
        assert_eq!(start, Start::AtLogin);
        assert!(!start.opens_window(false));
        assert!(!start.opens_window(true));
        // The wizard shows at every launch while the daemon is not
        // registered, at login too (spec section 8.3).
        assert!(start.shows_onboarding(true));
        assert!(!start.shows_onboarding(false));
        assert_eq!(start.presence(), Presence::MenuBar);
    }

    #[test]
    fn a_windowless_launch_opens_no_window_whatever_launched_it() {
        for login in [false, true] {
            let start = Start::of(["--windowless"]).at_login(login);
            assert_eq!(start, Start::Windowless);
            assert!(!start.opens_window(false));
            assert!(!start.opens_window(true));
            assert!(!start.shows_onboarding(true));
        }
    }

    #[test]
    fn only_the_open_application_event_marked_as_the_login_item_is_a_launch_at_login() {
        let reopen = u32::from_be_bytes(*b"rapp");
        assert!(launched_at_login(
            Some(OPEN_APPLICATION),
            Some(LAUNCHED_AS_LOGIN_ITEM)
        ));
        assert!(!launched_at_login(Some(OPEN_APPLICATION), None));
        assert!(!launched_at_login(Some(OPEN_APPLICATION), Some(reopen)));
        assert!(!launched_at_login(
            Some(reopen),
            Some(LAUNCHED_AS_LOGIN_ITEM)
        ));
        assert!(!launched_at_login(None, None));
        // The four-character codes AppKit uses.
        assert_eq!(OPEN_APPLICATION, 0x6f61_7070);
        assert_eq!(PROPERTY_DATA, 0x7072_6474);
        assert_eq!(LAUNCHED_AS_LOGIN_ITEM, 0x6c67_6974);
    }

    /// An Apple event of AppKit's own making, with `property` as its
    /// [`PROPERTY_DATA`] parameter when there is one.
    #[cfg(target_os = "macos")]
    fn apple_event(
        id: u32,
        property: Option<u32>,
    ) -> objc2::rc::Retained<objc2_foundation::NSAppleEventDescriptor> {
        use objc2::rc::Retained;
        use objc2_foundation::NSAppleEventDescriptor;

        const CORE_EVENT_CLASS: u32 = u32::from_be_bytes(*b"aevt");
        const AUTO_GENERATE_RETURN_ID: i16 = -1;
        const ANY_TRANSACTION_ID: i32 = 0;
        // SAFETY: the class method and the setter AppKit declares on
        // NSAppleEventDescriptor, with their declared argument types.
        let event: Retained<NSAppleEventDescriptor> = unsafe {
            objc2::msg_send![
                objc2::class!(NSAppleEventDescriptor),
                appleEventWithEventClass: CORE_EVENT_CLASS,
                eventID: id,
                targetDescriptor: None::<&NSAppleEventDescriptor>,
                returnID: AUTO_GENERATE_RETURN_ID,
                transactionID: ANY_TRANSACTION_ID
            ]
        };
        if let Some(value) = property {
            let value = NSAppleEventDescriptor::descriptorWithEnumCode(value);
            let () = unsafe {
                objc2::msg_send![&*event, setParamDescriptor: &*value, forKeyword: PROPERTY_DATA]
            };
        }
        event
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_launch_event_of_the_login_item_is_read_from_appkit() {
        let reopen = u32::from_be_bytes(*b"rapp");
        assert!(says_login_item(&apple_event(
            OPEN_APPLICATION,
            Some(LAUNCHED_AS_LOGIN_ITEM)
        )));
        assert!(!says_login_item(&apple_event(OPEN_APPLICATION, None)));
        assert!(!says_login_item(&apple_event(
            reopen,
            Some(LAUNCHED_AS_LOGIN_ITEM)
        )));
        // A test process has no launch event to look at.
        assert!(!launched_as_login_item());
    }

    #[test]
    fn a_reopen_of_the_running_app_opens_the_window_or_the_wizard_in_hand() {
        assert_eq!(reopened(false), Reopened::Window);
        assert_eq!(reopened(true), Reopened::Wizard);
    }

    #[test]
    fn the_dock_icon_shows_only_while_the_window_is_open() {
        assert_eq!(presence(true), Presence::Regular);
        assert_eq!(presence(false), Presence::MenuBar);
    }
}
