//! The Finding lists as the window's page, stylesheet and scripts set them
//! (spec sections 8.1, 8.2 and 8.4): the Threat Findings come first and the
//! Ambiguous Items wait below them in a section closed by default, one line
//! each; a title in the list beside a Finding is never cut, and the project
//! or Agent stands under it; and the Settings controls keep their nodes
//! through a render, so a click on one is never swallowed.
//!
//! The suite runs no webview, so this reads the files as they ship. That the
//! frame carries 25 Findings with their place and 90 Ambiguous Items with a
//! one-line Score is the frame's own test
//! (`twenty_five_findings_and_ninety_ambiguous_items`); the rendered result
//! is a hand check in both Postures.

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

/// The Threat Findings pane's markup.
fn threats_pane(page: &str) -> &str {
    let start = page
        .find("<section class=\"pane\" data-pane=\"threats\"")
        .expect("the Threat Findings pane");
    let end = start
        + page[start..]
            .find("<section class=\"pane\" data-pane=\"exposures\"")
            .expect("the next pane");
    &page[start..end]
}

/// With 90 Ambiguous Items the Findings are in sight first: the Ambiguous
/// Items sit below the Findings in a section that is closed until opened and
/// names its count, one compact line per Item.
#[test]
fn the_ambiguous_items_wait_closed_below_the_findings() {
    let page = ui("window.html");
    let pane = threats_pane(&page);
    let split = pane.find("<div class=\"split\">").expect("the Findings");
    let section = pane
        .find("<details class=\"ambiguous-items\"")
        .expect("the Ambiguous Items as a closed section");
    assert!(split < section, "the Findings come first");
    let tag = &pane[section..section + pane[section..].find('>').expect("its tag")];
    assert!(!tag.contains(" open"), "closed by default: {tag}");
    let summary = &pane[section..];
    assert!(
        summary.find("<summary>").expect("a summary")
            < summary.find("class=\"count\"").expect("the count")
    );

    let script = ui("window.js");
    let list = function(&script, "renderAmbiguousList");
    assert!(list.contains("querySelector(\".count\").textContent"));
    assert!(list.contains("items.length"));
    assert!(
        !list.contains(".open ="),
        "the user opens it, never a render"
    );
    let item = function(&script, "renderAmbiguous");
    assert!(item.contains("\"ambiguous-row\""));
    assert!(!item.contains("\"card ambiguous\""), "no card per Item");

    let css = ui("window.css");
    let row = rule(&css, ".ambiguous-row");
    assert!(row.contains("white-space: nowrap;"), "{row}");
    assert!(!css.contains(".card.ambiguous"), "no dashed card is left");
}

/// No title is cut in the list beside a Finding: the list is wider than it
/// was and can be dragged wider, a title wraps whole, and the project or
/// Agent stands under it in small muted text.
#[test]
fn a_title_in_the_list_is_never_cut() {
    let css = ui("window.css");
    let list = rule(&css, ".split > .list");
    assert!(list.contains("width: 40%;"), "{list}");
    assert!(list.contains("min-width: 240px;"), "{list}");
    assert!(list.contains("resize: horizontal;"), "{list}");
    assert!(!css.contains("flex: 0 0 240px;"), "the narrow list is gone");
    let title = rule(&css, ".row .title");
    for cut in ["nowrap", "ellipsis", "overflow: hidden"] {
        assert!(!title.contains(cut), "a title is cut: {title}");
    }
    assert!(title.contains("overflow-wrap: anywhere;"), "{title}");
    let place = rule(&css, ".row .place");
    assert!(place.contains("color: var(--muted);"), "{place}");
    assert!(place.contains("font-size: 11px;"), "{place}");

    let script = ui("window.js");
    let row = function(&script, "renderRow");
    assert!(row.contains("card.simple.place"), "{row}");
    assert!(row.contains("\"place\""), "{row}");
}
