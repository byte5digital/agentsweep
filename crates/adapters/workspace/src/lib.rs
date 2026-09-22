//! The built-in workspace Surface Adapter.
//!
//! It yields the Agent-neutral kinds Repository Metadata and env file for every
//! pooled project root and every marketplace clone, and computes Repository
//! Provenance by reading the git files in process. It never executes git, and
//! it is the reference adapter for the conformance suite.
//!
//! The crate is a scaffold; the adapter arrives with milestone 1 of the build
//! plan.

/// The Agent id this adapter declares. It names no Agent: the Surfaces it reads
/// belong to the project, not to Claude Code or Codex.
pub const AGENT_ID: &str = "workspace";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_id_is_machine_readable() {
        assert!(!AGENT_ID.is_empty());
        assert!(AGENT_ID.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }
}
