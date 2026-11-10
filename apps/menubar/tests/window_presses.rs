//! How the window's scripts take a press: never disabled for a running
//! Scan, a working line on the Finding pressed before anything is asked,
//! every press named so the app carries it out once, and every part with
//! buttons kept as it is while it shows the same, so a render cannot swallow
//! a click (spec sections 6.4 and 6.6).
//!
//! The suite runs no webview, so this reads the scripts as they ship. That
//! the frame's value for an unchanged Finding stays the same through a Scan,
//! which is what the window keeps a card by, is the frame's own test; that a
//! press delivered twice is carried out once is `tests/presses.rs`. The
//! clicks themselves are a hand check (section 7 of `docs/hand-checks.md`).

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{}", path.display()))
}

/// The text of the function `name` in `script`, up to the next top-level
/// function.
fn function<'a>(script: &'a str, name: &str) -> &'a str {
    let start = script
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("no function {name}"));
    let rest = &script[start..];
    let end = rest[1..]
        .find("\nfunction ")
        .or_else(|| rest[1..].find("\nasync function "))
        .map_or(rest.len(), |at| at + 1);
    &rest[..end]
}

/// A part filled through `keep` is built again only when its key changed:
/// the same key returns before anything is replaced.
#[test]
fn a_part_with_the_same_key_keeps_its_nodes() {
    let keep = read("ui/keep.js");
    let body = function(&keep, "keep");
    let same = body
        .find("built.get(node) === key")
        .expect("the key compared");
    let returned = body[same..].find("return false").expect("returned") + same;
    let replaced = body.find("replaceChildren").expect("filled");
    assert!(same < returned && returned < replaced, "{body}");
}

/// Every part of the window with buttons that a stream event renders again
/// is filled through `keep`, never replaced outright: the selected Finding's
/// detail, the list beside it, the sidebar, the Trusted section, the
/// Ambiguous Items, a banner's buttons and the AI check's engine cards.
#[test]
fn every_part_with_buttons_is_kept_through_a_render() {
    let window = read("ui/window.js");
    for part in [
        "keep(node.querySelector(\".detail\")",
        "keep(node.querySelector(\".list\")",
        "keep($(\"sidebar\")",
        "keep(section.querySelector(\".trusted-list\")",
        "keep(section.querySelector(\".list\")",
    ] {
        assert!(window.contains(part), "window.js: {part}");
    }
    for replaced in [
        "querySelector(\".detail\").replaceChildren",
        "$(\"sidebar\").replaceChildren",
        "querySelector(\".trusted-list\").replaceChildren",
    ] {
        assert!(!window.contains(replaced), "window.js: {replaced}");
    }
    for function_name in ["renderFindingPane", "renderAmbiguousList"] {
        assert!(
            !function(&window, function_name).contains("replaceChildren"),
            "{function_name} fills its lists through keep"
        );
    }
    // The detail's key holds everything the card is built from.
    let pane = function(&window, "renderFindingPane");
    for held in [
        "selected:",
        "answer:",
        "waiting",
        "details:",
        "howTo:",
        "developer",
    ] {
        assert!(pane.contains(held), "the detail's key holds {held}");
    }
    let banner = read("ui/banner.js");
    assert!(banner.contains("keep(part(\"banner-buttons\")"));
    assert!(!banner.contains("part(\"banner-buttons\").replaceChildren"));
    let ai_check = read("ui/ai_check.js");
    assert!(ai_check.contains("keep(place.querySelector(\".cards\")"));
}

/// No action button is disabled because a Scan runs, and the line that said
/// so is gone.
#[test]
fn no_action_waits_greyed_out_for_a_scan() {
    let window = read("ui/window.js");
    for gone in ["actionsWait", "disableActions", "button[data-action]"] {
        assert!(!window.contains(gone), "window.js still has {gone}");
    }
    assert!(!read("ui/window.html").contains("actions-wait"));
    assert!(!read("src/findings.rs").contains("\"actionsWait\":"));
}

/// A press shows its working line at once: the Finding is marked and the
/// window rendered before the request goes, and the mark is taken off with
/// the answer, whatever it was. The pressed Finding shows the app's line in
/// place of its buttons.
#[test]
fn a_press_shows_its_working_line_before_it_is_asked() {
    let window = read("ui/window.js");
    let run = function(&window, "run");
    let marked = run.find("pending.add(id)").expect("marked");
    let rendered = run[marked..].find("render(view)").expect("rendered") + marked;
    let asked = run.find("await invoke(action.command").expect("asked");
    assert!(marked < rendered && rendered < asked, "{run}");
    assert_eq!(run.matches("pending.delete(id)").count(), 2, "{run}");
    let actions = function(&window, "renderActions");
    assert!(actions.contains("if (pending.has(card.id))"));
    assert!(actions.contains("renderWorking()"));
    assert!(function(&window, "renderWorking").contains("view?.working"));
    // A banner button says it is working and waits for its answer.
    let banner = read("ui/banner.js");
    let said = banner
        .find("say(button.working)")
        .expect("the working line");
    assert!(said < banner.find("await invoke(button.command").expect("asked"));
}

/// Every press that asks the daemon for something is named, and every app
/// command it calls takes the name.
#[test]
fn every_press_is_named_and_every_command_takes_the_name() {
    let window = read("ui/window.js");
    assert!(
        function(&window, "run").contains("press: nextPress()"),
        "the actions"
    );
    for command in ["scan_now", "check_now"] {
        assert!(
            window.contains(&format!("invoke(\"{command}\", {{ press: nextPress() }})")),
            "window.js {command}"
        );
    }
    assert!(read("ui/popover.js").contains("invoke(\"scan_now\", { press: nextPress() })"));
    assert!(read("ui/banner.js").contains("invoke(button.command, { press: nextPress() })"));
    assert!(read("ui/ai_check.js").contains("const press = nextPress();"));

    let app = read("src/app.rs");
    for command in [
        "quarantine",
        "restore",
        "trust",
        "acknowledge",
        "fix",
        "re_enable",
        "purge",
        "untrust",
        "check_now",
        "scan_now",
        "start_daemon",
        "start_fresh_record",
        "look_at_records",
        "show_what_changed",
        "scan_again_trusting_nothing",
        "turn_on_claude",
    ] {
        let start = app
            .find(&format!("async fn {command}("))
            .unwrap_or_else(|| panic!("no command {command}"));
        let signature = &app[start..start + app[start..].find('{').expect("a body")];
        assert!(
            signature.contains("press: String"),
            "{command} takes the press: {signature}"
        );
    }
}
