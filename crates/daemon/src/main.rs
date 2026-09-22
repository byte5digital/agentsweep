//! The AgentSweep daemon, binary `agentsweepd`.
//!
//! It runs as a user-level launch agent, watches the Surfaces, runs the three
//! Scan kinds and is the only process that writes the Event Log, the Baseline,
//! the verdict cache and the state file, and the only one that touches the
//! Keychain. It arrives with milestone 6 of the build plan.

fn main() {
    println!(
        "{} {}",
        agentsweep_core::DAEMON_LABEL,
        agentsweep_core::VERSION
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_binary_name_is_the_machine_readable_product_name_with_a_d() {
        assert_eq!(
            env!("CARGO_BIN_NAME"),
            format!("{}d", agentsweep_core::NAME)
        );
    }
}
