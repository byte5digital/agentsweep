//! The release runbook in the hand checks holds every item of the release
//! checklist with how it is checked and what follows a miss, names the items
//! the release bundle checker covers exactly as the checker does, gives the
//! crates.io order the package check uses, and keeps the release flow in its
//! order (spec sections 9.2 and 9.3).

use std::fs;

use agentsweep_xtask::repo_root;

fn read(relative: &str) -> String {
    fs::read_to_string(repo_root().join(relative)).expect("the file is in the repository")
}

fn hand_checks() -> String {
    read("docs/hand-checks.md")
}

/// The text from `heading` to the next heading of the same or a higher level.
fn section<'a>(text: &'a str, heading: &str) -> &'a str {
    let start = text
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("no section {heading:?}"))
        + 1;
    let level = heading.split(' ').next().expect("a heading has hashes");
    let body = &text[start + heading.len()..];
    let end = body
        .lines()
        .scan(0usize, |offset, line| {
            let here = *offset;
            *offset += line.len() + 1;
            Some((here, line))
        })
        .find(|(_, line)| {
            let hashes = line.split(' ').next().unwrap_or_default();
            !hashes.is_empty()
                && hashes.chars().all(|c| c == '#')
                && hashes.len() <= level.len()
                && line.len() > hashes.len()
        })
        .map_or(body.len(), |(offset, _)| offset);
    &body[..end]
}

/// The numbered entries of a list, by number.
fn numbered(text: &str) -> Vec<(usize, String)> {
    let mut items: Vec<(usize, String)> = Vec::new();
    for line in text.lines() {
        let number = line
            .split_once(". ")
            .and_then(|(number, _)| number.parse::<usize>().ok());
        match number {
            Some(number) => items.push((number, line.to_owned())),
            None => {
                if let Some((_, item)) = items.last_mut() {
                    item.push('\n');
                    item.push_str(line);
                }
            }
        }
    }
    items
}

fn checklist() -> Vec<(usize, String)> {
    let text = hand_checks();
    numbered(section(&text, "### The release checklist, item by item"))
}

#[test]
fn every_item_of_the_release_checklist_says_how_it_is_checked_and_what_a_miss_means() {
    let items = checklist();
    let numbers: Vec<usize> = items.iter().map(|(number, _)| *number).collect();
    assert_eq!(numbers, (1..=18).collect::<Vec<_>>());
    for (number, item) in &items {
        assert!(
            item.contains("Check"),
            "item {number} says how it is checked"
        );
        assert!(
            item.contains("If "),
            "item {number} says what follows a miss"
        );
    }
}

#[test]
fn the_items_marked_for_the_checker_are_the_ones_the_checker_names() {
    let marked: Vec<usize> = checklist()
        .iter()
        .filter(|(_, item)| item.contains("**(checker)"))
        .map(|(number, _)| *number)
        .collect();
    let script = read(".github/scripts/check-bundle-signature.sh");
    assert!(
        script.contains("checklist items 2, 3, 14, 15 and 16"),
        "the checker still names the items it covers"
    );
    assert_eq!(marked, vec![2, 3, 14, 15, 16]);
}

#[test]
fn the_crates_are_published_in_the_order_the_package_check_packages_them() {
    let script = read(".github/scripts/package-check.sh");
    let list = script
        .lines()
        .find_map(|line| line.strip_prefix("crates=\""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("the package check lists its crates");
    let crates: Vec<&str> = list.split_whitespace().collect();
    let item = checklist()
        .into_iter()
        .find(|(number, _)| *number == 17)
        .expect("item 17")
        .1;
    let positions: Vec<usize> = crates
        .iter()
        .map(|name| {
            item.find(&format!("`{name}`"))
                .unwrap_or_else(|| panic!("item 17 names {name}"))
        })
        .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(positions, sorted, "item 17 gives the order {crates:?}");
}

#[test]
fn the_release_flow_runs_from_the_tag_to_the_crates() {
    let text = hand_checks();
    let steps: Vec<String> = numbered(section(&text, "### The release flow, in order"))
        .into_iter()
        .map(|(_, step)| {
            step.split("**")
                .nth(1)
                .expect("each step opens with its name")
                .to_owned()
        })
        .collect();
    assert_eq!(
        steps,
        [
            "Set the version.",
            "Tag.",
            "Watch the workflow.",
            "Approve the `release` environment.",
            "Run the checklist on the draft.",
            "Publish.",
            "Watch the cask bump.",
            "Publish the crates",
        ]
    );
}

#[test]
fn no_hand_check_says_a_release_daemon_admits_nobody() {
    let text = hand_checks();
    for stale in ["admits nobody", "answers nobody", "empty Team ID"] {
        assert!(!text.contains(stale), "the hand checks still say {stale:?}");
    }
}
