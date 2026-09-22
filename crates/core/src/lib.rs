//! The AgentSweep core.
//!
//! The core owns the Item model, the Surface Adapter contract, the detection
//! ladder, the quarantine store, the Event Log, the Baseline and every Finding
//! decision. Surface Adapters are in-tree crates beside this one and never see
//! a Tier or a Rule.
//!
//! The crate is a scaffold. The types arrive with milestone 1 of the build
//! plan; only the frozen names live here so far.

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
}
