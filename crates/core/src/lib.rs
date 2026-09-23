//! The AgentSweep core.
//!
//! The core owns the Item model, the Surface Adapter contract, the detection
//! ladder, the quarantine store, the Event Log, the Baseline and every Finding
//! decision. Surface Adapters are in-tree crates beside this one and never see
//! a Tier or a Rule.
//!
//! What is here so far is the first end-to-end path: the Item, the Host, the
//! read side of the Surface Adapter contract, the view globals of the rule
//! contract, the bundled Rule Pack, the Rule tier that runs it and the
//! Heuristic tier that scores what it left undecided. The stores,
//! the Baseline and AI Judgement arrive with their milestones.

#![warn(missing_docs)]

pub mod adapter;
pub mod allowlist;
pub mod chain;
pub mod derived;
pub mod enforcement;
pub mod envelope;
pub mod eventlog;
pub mod finding;
pub mod heuristics;
pub mod host;
pub mod item;
pub mod keychain;
pub mod pack;
pub mod paths;
pub mod provenance;
pub mod quarantine;
pub mod rules;
pub mod scan;
pub mod user_rules;
pub mod views;

/// The machine-readable name of the product. AgentSweep in prose and UI,
/// `agentsweep` in every name a machine reads.
pub const NAME: &str = "agentsweep";

/// The bundle identifier of the application.
pub const BUNDLE_ID: &str = "de.byte5.agentsweep";

/// The launch agent label and signing identifier of the daemon. Frozen: the
/// Keychain key that protects the Event Log is bound to it.
pub const DAEMON_LABEL: &str = "de.byte5.agentsweep.daemon";

/// The version of AgentSweep. Application, daemon and CLI share it; the Rule
/// Pack carries its own version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_daemon_label_extends_the_bundle_id() {
        assert_eq!(DAEMON_LABEL, format!("{BUNDLE_ID}.daemon"));
    }

    #[test]
    fn the_machine_readable_name_is_the_bundle_id_suffix() {
        assert!(BUNDLE_ID.ends_with(NAME));
    }

    /// The rule engine must stay on Wasmtime's interpreter. Turning the
    /// default features of `yara-x` back on would bring the just-in-time
    /// compiler with them, and the notarized bundle runs under the hardened
    /// runtime without a JIT entitlement (ADR 0004).
    #[test]
    fn the_rule_engine_is_built_without_a_just_in_time_compiler() {
        let manifest = include_str!("../Cargo.toml");
        let line = manifest
            .lines()
            .find(|line| line.starts_with("yara-x"))
            .expect("the core depends on yara-x");
        assert!(line.contains("default-features = false"), "{line}");
        assert!(line.contains("\"pulley\""), "{line}");
    }
}
