//! The Codex Surface Adapter.
//!
//! It knows where Codex reads instructions and executable configuration from,
//! enumerates the Items on those Surfaces and enforces the primitives its
//! descriptor declares. It never executes the Agent binary: presence comes from
//! the config directory or a stat on `PATH`, and the version from on-disk
//! metadata.
//!
//! The crate is a scaffold; the adapter arrives with milestone 1 of the build
//! plan.

/// The Agent id this adapter declares.
pub const AGENT_ID: &str = "codex";

/// The name shown to a person.
pub const DISPLAY_NAME: &str = "Codex";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_id_is_machine_readable() {
        assert!(!AGENT_ID.is_empty());
        assert!(AGENT_ID.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }
}
