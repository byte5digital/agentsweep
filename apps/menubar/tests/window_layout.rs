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

/// The Settings pane's markup, from its section to the end of the panes.
fn settings_pane(page: &str) -> String {
    let start = page
        .find("<section class=\"pane\" data-pane=\"settings\"")
        .expect("the Settings pane");
    let end = start + page[start..].find("</main>").expect("the end of the panes");
    page[start..end].to_string()
}

/// The value of `attribute` in the opening tag that starts at `tag`.
fn attribute<'a>(tag: &'a str, attribute: &str) -> Option<&'a str> {
    let tag = &tag[..tag.find('>')?];
    let key = format!(" {attribute}=\"");
    let at = tag.find(&key)? + key.len();
    Some(&tag[at..at + tag[at..].find('"')?])
}

/// The tabs as (panel id, label), in their order.
fn tabs(pane: &str) -> Vec<(String, String)> {
    pane.match_indices("role=\"tab\"")
        .map(|(at, _)| {
            let open = pane[..at].rfind('<').expect("the tab's tag");
            let tag = &pane[open..];
            let panel = attribute(tag, "aria-controls").expect("the tab's panel");
            let text = &tag[tag.find('>').expect("its end") + 1..];
            let label = text[..text.find('<').expect("its close")].trim();
            (panel.to_string(), label.to_string())
        })
        .collect()
}

/// Each tab panel's id and the ids of the settings inside it.
fn panels(pane: &str) -> Vec<(String, Vec<String>)> {
    let starts: Vec<usize> = pane
        .match_indices("role=\"tabpanel\"")
        .map(|(at, _)| pane[..at].rfind('<').expect("the panel's tag"))
        .collect();
    starts
        .iter()
        .enumerate()
        .map(|(n, &start)| {
            let end = starts.get(n + 1).copied().unwrap_or(pane.len());
            let inside = &pane[start..end];
            let settings = inside
                .match_indices("class=\"setting\"")
                .map(|(at, _)| {
                    let open = inside[..at].rfind('<').expect("the setting's tag");
                    attribute(&inside[open..], "id")
                        .expect("the setting's id")
                        .to_string()
                })
                .collect();
            let id = attribute(inside, "id").expect("the panel's id");
            (id.to_string(), settings)
        })
        .collect()
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

/// Every setting sits in exactly one tab panel, each panel has its tab with
/// a label of one or two words, and Uninstall has a tab of its own.
#[test]
fn the_settings_tabs_reach_every_setting_uninstall_included() {
    let page = ui("window.html");
    let pane = settings_pane(&page);
    let tabs = tabs(&pane);
    let panels = panels(&pane);
    assert_eq!(
        tabs.iter()
            .map(|(_, label)| label.as_str())
            .collect::<Vec<_>>(),
        ["General", "AI check", "Background", "Advanced", "Uninstall"]
    );
    for (_, label) in &tabs {
        assert!(label.split_whitespace().count() <= 2, "{label}");
    }
    assert_eq!(
        tabs.iter()
            .map(|(panel, _)| panel.clone())
            .collect::<Vec<_>>(),
        panels.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>()
    );
    let first = pane.find("role=\"tabpanel\"").expect("a panel");
    assert!(
        !pane[..first].contains("class=\"setting\""),
        "a setting outside the tabs"
    );
    let mut every: Vec<String> = panels.iter().flat_map(|(_, ids)| ids.clone()).collect();
    every.sort();
    assert_eq!(
        every,
        [
            "settings-advanced",
            "settings-ai-check",
            "settings-background",
            "settings-cli",
            "settings-detail",
            "settings-not-protected",
            "settings-uninstall",
        ]
    );
    let uninstall = panels
        .iter()
        .position(|(_, ids)| ids == &["settings-uninstall"])
        .expect("Uninstall alone in its panel");
    assert_eq!(tabs[uninstall].1, "Uninstall");
    let gate = pane.find("id=\"settings-gate\"").expect("the Gate switch");
    let background = pane.find("id=\"settings-background\"").expect("Background");
    let advanced = pane.find("id=\"settings-advanced\"").expect("Advanced");
    assert!(
        background < gate && gate < advanced,
        "the Gate switch under Background"
    );
    let fields = pane
        .find("id=\"settings-advanced-ai\"")
        .expect("the AI fields");
    let everything = pane
        .find("id=\"settings-everything\"")
        .expect("Full Disk Access");
    assert!(
        advanced < fields && fields < everything,
        "the AI fields under Advanced"
    );
}

/// The window keeps which tab is in sight across views, switches it on a
/// click, and the AI check's tab takes the Posture's title for it.
#[test]
fn the_window_switches_the_settings_tabs() {
    let script = ui("window.js");
    assert!(script.contains("let settingsTab = \"settings-panel-general\";"));
    assert!(script.contains("function renderSettingsTabs()"));
    assert!(script.contains("renderSettingsTabs();"));
    let ai = ui("ai_check.js");
    assert!(ai.contains("$(\"settings-tab-ai\").textContent = view.title;"));
}

/// The Ollama address and, in the Developer Posture, the Claude model id
/// take the pane's width: label above, field beneath at full width, in
/// either Posture.
#[test]
fn the_two_advanced_fields_take_the_pane_width() {
    let css = ui("window.css");
    let advanced = rule(&css, "#settings-advanced");
    assert!(advanced.contains("max-width: none;"), "{advanced}");
    let row = rule(&css, "#settings-advanced-ai .dir");
    assert!(row.contains("flex-direction: column;"), "{row}");
    assert!(row.contains("align-items: stretch;"), "{row}");
    let label = rule(&css, "#settings-advanced-ai .dir .label");
    assert!(label.contains("flex: none;"), "{label}");
    let input = rule(&css, "#settings-advanced-ai .dir input");
    assert!(input.contains("width: 100%;"), "{input}");
    assert!(
        !css.contains("[data-posture"),
        "the layout follows no Posture"
    );
}
