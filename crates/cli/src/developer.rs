//! The developer listing: what the Surface Adapters would enumerate for one
//! home directory.
//!
//! This is the one sanctioned way to look at a real machine (`CLAUDE.md`). It
//! exists so that the enumeration of the author's own installation can be
//! compared with the surface inventories in `docs/research`, which is the exit
//! criterion of milestone 1 of the build plan. It is off unless it is asked
//! for by name, it says so in the help text, and it records nothing: no
//! Baseline, no Trust, no Quarantine, not one byte written.
//!
//! It prints identities and facts, never content. A settings value may be a
//! credential and an MCP `env` block certainly is, so what is shown per Item is
//! its id, its kind, its Scope, its Provenance, its Activation and the length
//! of its content. Its output is never committed.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write as _;
use std::path::PathBuf;

use agentsweep_adapter_claude_code::ClaudeCode;
use agentsweep_adapter_codex::Codex;
use agentsweep_adapter_workspace::Workspace;
use agentsweep_core::adapter::{Enumeration, SurfaceAdapter};
use agentsweep_core::host::Host;

/// The root every absolute system path is resolved against on a real machine.
const SYSTEM_ROOT: &str = "/";

/// Lists what the Surface Adapters would enumerate for one home directory.
///
/// The home is the one given, otherwise the one the environment names. The
/// project roots are the ones the Agents' own registries list, which is the
/// Inventory: no folder is crawled to find more.
pub fn list_items(home: Option<PathBuf>) -> Result<String, Box<dyn Error>> {
    let home = match home {
        Some(home) => home,
        None => PathBuf::from(std::env::var("HOME").map_err(|_| "no home directory is named")?),
    };
    if !home.is_dir() {
        return Err(format!("{} is not a folder", home.display()).into());
    }

    // The project roots are pooled across every Agent, so each adapter scans
    // its own Surfaces at every root the other one knows too. That is what the
    // registered flag is about.
    let agents: Vec<Box<dyn SurfaceAdapter>> =
        vec![Box::new(ClaudeCode::new()), Box::new(Codex::new())];
    let inventory = Host::new(home.clone(), Vec::new())
        .with_search_path(search_path())
        .with_system_root(PathBuf::from(SYSTEM_ROOT));
    let mut roots: Vec<PathBuf> = agents
        .iter()
        .flat_map(|agent| agent.projects(&inventory))
        .map(|registration| registration.root)
        .filter(|root| root.is_dir())
        .collect();
    roots.sort();
    roots.dedup();

    let host = Host::new(home.clone(), roots.clone())
        .with_search_path(search_path())
        .with_system_root(PathBuf::from(SYSTEM_ROOT));

    let workspace = Workspace::new();
    let provenances = workspace.provenances(&host, &roots);
    let mut enumeration = Enumeration::default();
    enumeration.extend(workspace.enumerate(&host, &roots));
    for agent in &agents {
        enumeration.extend(agent.enumerate(&host, &roots));
    }
    provenances.stamp(&mut enumeration);

    Ok(render(&agents, &host, &roots, &enumeration))
}

fn search_path() -> Vec<PathBuf> {
    std::env::var("PATH")
        .map(|path| path.split(':').map(PathBuf::from).collect())
        .unwrap_or_default()
}

fn render(
    agents: &[Box<dyn SurfaceAdapter>],
    host: &Host,
    roots: &[PathBuf],
    enumeration: &Enumeration,
) -> String {
    let mut out = String::new();
    for agent in agents {
        let detection = agent.detect(host);
        let _ = writeln!(
            out,
            "{} installed={} version={} config_dir={}",
            agent.descriptor().display_name,
            detection.installed,
            detection.version.as_deref().unwrap_or("unknown"),
            detection
                .config_dir
                .map(|dir| dir.display().to_string())
                .unwrap_or_default()
        );
    }
    let _ = writeln!(out, "project roots: {}", roots.len());
    let _ = writeln!(out);

    for item in &enumeration.items {
        let _ = writeln!(
            out,
            "{} {} {} {} {} registered={} bytes={}",
            item.id,
            item.kind,
            item.shape.as_str(),
            item.provenance.as_str(),
            item.activation.as_str(),
            item.registered,
            item.size
        );
    }

    let _ = writeln!(out);
    let mut counted: BTreeMap<String, usize> = BTreeMap::new();
    for item in &enumeration.items {
        *counted
            .entry(format!(
                "{} {} {}",
                item.agent,
                item.scope.as_str(),
                item.kind
            ))
            .or_default() += 1;
    }
    for (what, how_many) in &counted {
        let _ = writeln!(out, "{how_many:>5}  {what}");
    }
    let _ = writeln!(out, "{:>5}  Items", enumeration.items.len());

    for problem in &enumeration.problems {
        let _ = writeln!(
            out,
            "problem {} {} {:?}",
            problem.surface,
            problem.path.display(),
            problem.reason
        );
    }
    let _ = writeln!(out, "\nNothing was recorded.");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// The listing runs on a home of this test's own, never on the real one.
    #[test]
    fn the_listing_counts_what_it_found_by_scope_and_kind() {
        let home = std::env::temp_dir().join(format!(
            "agentsweep-developer-listing-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".claude")).expect("a fake config directory");
        fs::write(
            home.join(".claude").join("settings.json"),
            b"{\"apiKeyHelper\": \"/opt/example/key\"}",
        )
        .expect("a fake settings file");
        fs::write(home.join(".claude.json"), b"{\"projects\": {}}").expect("a fake registry");

        let listed = list_items(Some(home.clone())).expect("the listing runs");

        assert!(listed.contains("Claude Code installed=true"), "{listed}");
        // Whether Codex is installed depends on the machine the suite runs
        // on; that its line is there and that it found nothing in this fake
        // home does not.
        assert!(listed.contains("Codex installed="), "{listed}");
        assert!(!listed.contains("codex/"), "{listed}");
        assert!(listed.contains("project roots: 0"), "{listed}");
        assert!(
            listed.contains("claude-code user SettingsEntry"),
            "{listed}"
        );
        assert!(listed.contains("1  Items"), "{listed}");
        assert!(listed.contains("Nothing was recorded."), "{listed}");
        assert!(
            !listed.contains("/opt/example/key"),
            "a value never reaches the listing: {listed}"
        );

        fs::remove_dir_all(&home).expect("the fake home goes away");
    }

    #[test]
    fn a_home_that_is_not_a_folder_is_an_error_rather_than_an_empty_listing() {
        assert!(list_items(Some(PathBuf::from("/nowhere/agentsweep"))).is_err());
    }
}
