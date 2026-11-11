//! The Simple Posture's layout B as the window's page, stylesheet and
//! scripts set it (spec section 8.4, amended 2026-11-10): a Finding reads in
//! three parts with the Severity chip beside a title that names the thing,
//! the buttons inside What to do, More and the AI explanation folded, and
//! Show technical details and Report false positive as links; the Overview
//! shows the Protection line, four count tiles that open their lists, and
//! one watching line. The Developer Posture's card is the one it was.
//!
//! The suite runs no webview, so this reads the files as they ship. What
//! the parts and the tiles say is the wording's and the frame's own tests
//! (`wording::tests`, `overview::tests`, `frame::tests`); the rendered result
//! is a hand check in both Postures (section 7 of `docs/hand-checks.md`).

use std::path::Path;

fn ui(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui").join(name);
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

/// The position of each needle in `text`, in the order given.
fn positions(text: &str, needles: &[&str]) -> Vec<usize> {
    needles
        .iter()
        .map(|needle| {
            text.find(needle)
                .unwrap_or_else(|| panic!("no {needle} in {text}"))
        })
        .collect()
}

/// A Simple Finding: the chip, then the title that names the thing; What
/// it is, Why it matters and What to do in that order, the buttons inside
/// What to do; the how-to, More and the AI explanation folded; the two links
/// at the foot, Report false positive out of the header.
#[test]
fn a_simple_finding_reads_in_three_parts() {
    let script = ui("window.js");
    let card = function(&script, "renderSimpleCard");
    let order = positions(
        card,
        &[
            "`chip ${simple.chip}`",
            "parts.name",
            "renderPart(\"What it is\", parts.what)",
            "renderPart(\"Why it matters\", parts.why)",
            "renderPart(\"What to do\", parts.todo)",
            "todo.append(actions)",
            "howTo.label",
            "renderFold(`${details} more`, \"More\"",
            "renderFold(`${details} ai`, \"AI explanation\"",
            "renderToggle(details, again)",
            "renderReport(card)",
        ],
    );
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{order:?}");
    for gone in ["renderHeader(", "renderLines(", "simple.title", "addHowTo("] {
        assert!(!card.contains(gone), "{gone} in the Simple card");
    }
    // The AI text is the engine's: set as text, never markup.
    assert!(card.contains("document.createTextNode(parts.ai.text)"));
    assert!(!script.contains("innerHTML"));

    // A fold opens as the user left it when the card is built again.
    let fold = function(&script, "renderFold");
    assert!(fold.contains("fold.open = foldsOpen.has(key);"), "{fold}");
    assert!(fold.contains("\"toggle\""), "{fold}");

    // More lists the further signs and puts the notes under them.
    let more = function(&script, "renderMore");
    assert!(more.contains("\"heuristic\"") && more.contains("\"muted\""));

    // The Quarantine pane hangs its lines under the title of a Simple card.
    let entry = function(&script, "renderQuarantineEntry");
    assert!(entry.contains("node.querySelector(\".head\")"), "{entry}");

    // A Folder Scan's Finding reads the same way in the Simple Posture.
    let folder = function(&script, "renderFolderCard");
    assert!(folder.contains("renderSimpleCard(card, `folder ${card.id}`"));
}

/// The Developer Posture's card is unchanged: its heading with Report false
/// positive beside it, its chips, the body lines, the technical table and
/// the how-to among its buttons.
#[test]
fn the_developer_finding_is_unchanged() {
    let script = ui("window.js");
    let card = function(&script, "renderDeveloperCard");
    for kept in [
        "renderHeader(card, developer.title)",
        "renderLines(node, developer.lines ?? card.simple.lines)",
        "node.append(renderTechnical(card))",
        "addHowTo(card, howTo, actions)",
    ] {
        assert!(card.contains(kept), "{kept}");
    }
    assert!(!card.contains("parts"), "{card}");
    let header = function(&script, "renderHeader");
    assert!(header.contains("renderReport(card)"));
}

/// The parts, the folds and the links are styled; the stylesheet never
/// styles by Posture.
#[test]
fn the_three_parts_are_styled() {
    let css = ui("window.css");
    for selector in [
        ".card .head",
        ".parts",
        ".part + .part",
        ".part.todo",
        ".part-label",
        "details.fold > summary",
        ".links",
        ".statusline::before",
        ".tiles",
        ".tile[data-tone=\"red\"]",
        ".tile[data-tone=\"amber\"]",
    ] {
        assert!(css.contains(&format!("{selector} {{")), "{selector}");
    }
    assert!(!css.contains("[data-posture"));
}

/// The Overview's four tiles stand in the page in their order, Check now on
/// the tile of the projects not checked; the script fills them in place, a
/// Finding tile opens its pane and a project tile its projects.
#[test]
fn the_overview_has_four_tiles_that_open_their_lists() {
    let page = ui("window.html");
    let start = page
        .find("<section class=\"pane\" data-pane=\"overview\"")
        .expect("the Overview");
    let pane = &page[start..start + page[start..].find("</section>").expect("its end")];
    let order = positions(
        pane,
        &[
            "id=\"overview-protection\"",
            "id=\"overview-tiles\"",
            "data-tile=\"threats\"",
            "data-tile=\"exposures\"",
            "data-tile=\"permission\"",
            "id=\"tile-check-now\"",
            "data-tile=\"gate\"",
            "id=\"overview-agents\"",
            "id=\"overview-last-check\"",
            "id=\"overview-scan\"",
        ],
    );
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{order:?}");

    let script = ui("window.js");
    let tiles = function(&script, "renderTiles");
    assert!(
        !tiles.contains("replaceChildren"),
        "filled in place: {tiles}"
    );
    assert!(tiles.contains("tile.label") && tiles.contains("tile.count"));
    assert!(tiles.contains("$(\"tile-check-now\").disabled = !permission.enabled;"));
    assert!(
        script.contains("select(name);"),
        "a Finding tile opens its pane"
    );
    assert!(script.contains("tilesOpen.add(name);"));
    assert!(
        script.contains("$(\"tile-check-now\").addEventListener(\"click\", () => checkNow("),
        "the tile's Check now sends the same request"
    );

    let overview = function(&script, "renderOverview");
    assert!(overview.contains("overview.protection"));
    assert!(overview.contains("[overview.watching, checked]"));
    assert!(overview.contains("`Last check: ${when(overview.lastCheck)}`"));
    let permission = function(&script, "renderPermission");
    assert!(permission.contains("tilesOpen.has(\"permission\")"));
    let gate = function(&script, "renderGateLines");
    assert!(gate.contains("tilesOpen.has(\"gate\")"));
}

/// The first action inside What to do of a Simple Finding is the main
/// button, filled with the window's own colour pair in both themes; on an
/// Exposure with its one-click fix, Take this setting out comes first. The
/// Developer card styles no button as the main one.
#[test]
fn a_simple_finding_has_one_main_button() {
    let script = ui("window.js");
    let card = function(&script, "renderSimpleCard");
    let order = positions(
        card,
        &[
            "renderActions(card, mainFirst(card))",
            "actions.querySelector(\"button\")?.classList.add(\"main\");",
            "todo.append(actions)",
        ],
    );
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{order:?}");
    let first = function(&script, "mainFirst");
    assert!(first.contains("!action.technical"), "{first}");
    assert!(first.contains("action.command === \"fix\""), "{first}");

    for name in ["renderDeveloperCard", "renderFolderCard", "renderActions"] {
        let other = function(&script, name);
        assert!(!other.contains("\"main\""), "{name} styles a main button");
    }

    let css = ui("window.css");
    let rule = css.find("button.main {").expect("the main button");
    let rule = &css[rule..rule + css[rule..].find('}').expect("its end")];
    assert!(rule.contains("background: var(--main-bg);"), "{rule}");
    assert!(rule.contains("border-color: var(--main-bg);"), "{rule}");
    assert!(rule.contains("color: var(--main-fg);"), "{rule}");
    // Later than the hover rule, so a hovered main button stays filled.
    assert!(css.find("button:hover {") < css.find("button.main {"));

    // The pair is set for the light theme and again for the dark one.
    let dark = css
        .find("@media (prefers-color-scheme: dark)")
        .expect("the dark theme");
    for token in ["--main-bg:", "--main-fg:"] {
        let light = css.find(token).expect(token);
        assert!(light < dark, "{token} in the light theme");
        assert!(css[dark..].contains(token), "{token} in the dark theme");
    }
}
