//! The AgentSweep command line interface, binary `agentsweep`.
//!
//! In the bundle it is a client of the daemon; built from crates.io it is an
//! on-demand scanner. The commands arrive with milestone 7 of the build plan.

fn main() {
    println!("{} {}", agentsweep_core::NAME, agentsweep_core::VERSION);
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_binary_name_is_the_machine_readable_product_name() {
        assert_eq!(env!("CARGO_BIN_NAME"), agentsweep_core::NAME);
    }
}
