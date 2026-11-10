//! The window's layout as its page, stylesheet and scripts set it: every
//! pane scrolls, the Settings pane is split into tabs that reach every
//! setting, and the two AI fields under Advanced take the pane's width
//! (spec sections 8.1 and 8.10). The rendered result at the smallest window
//! size is a hand check in both Postures.

use std::path::Path;

fn ui(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{}", path.display()))
}

/// The declarations of the one rule whose selector list is exactly
/// `selector`.
fn rule(css: &str, selector: &str) -> String {
    let mut rest = css;
    while let Some(open) = rest.find('{') {
        let head = rest[..open].rsplit(['}', '/']).next().unwrap_or("").trim();
        let close = open + rest[open..].find('}').expect("a closed rule");
        if head == selector {
            return rest[open + 1..close].to_string();
        }
        rest = &rest[close + 1..];
    }
    panic!("no rule for {selector}");
}

/// Overview, Quarantine, Activity and Settings scroll inside their pane, so
/// each reaches its last line at the smallest window size; a list beside its
/// detail keeps room of its own while the pane around it scrolls.
#[test]
fn every_pane_scrolls_to_its_last_line() {
    let css = ui("window.css");
    let pane = rule(&css, ".pane");
    assert!(pane.contains("min-height: 0;"), "{pane}");
    assert!(pane.contains("overflow-y: auto;"), "{pane}");
    let below = rule(&css, ".pane > :not(.split)");
    assert!(below.contains("flex-shrink: 0;"), "{below}");
    let split = rule(&css, ".split");
    assert!(!split.contains("min-height: 0;"), "{split}");
    assert!(split.contains("min-height: 240px;"), "{split}");
    let page = ui("window.html");
    for id in [
        "overview",
        "threats",
        "exposures",
        "quarantine",
        "activity",
        "settings",
    ] {
        assert!(
            page.contains(&format!("<section class=\"pane\" data-pane=\"{id}\"")),
            "{id}"
        );
    }
}
