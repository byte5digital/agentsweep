//! The Surface Adapter conformance suite.
//!
//! It runs every adapter against sanitised fixture trees and checks the
//! enumeration snapshots, the stability of Item ids across two runs, that every
//! watch root maps back to at least one Item, that every declared enforcement
//! capability works on a temporary copy, and that every parsed view validates.
//! It never runs against the real home directory.
//!
//! The crate is a scaffold; the checks arrive with milestone 1 of the build
//! plan.

/// The Agent ids of the adapters v1 ships, in the order the suite runs them:
/// the workspace adapter first, because it is the reference adapter.
pub fn agent_ids() -> [&'static str; 3] {
    [
        agentsweep_adapter_workspace::AGENT_ID,
        agentsweep_adapter_claude_code::AGENT_ID,
        agentsweep_adapter_codex::AGENT_ID,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_adapter_declares_its_own_agent_id() {
        let ids = agent_ids();
        for (index, id) in ids.iter().enumerate() {
            assert!(!ids[index + 1..].contains(id), "duplicate agent id {id}");
        }
    }
}
