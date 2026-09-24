//! The AgentSweep inter-process vocabulary.
//!
//! The daemon owns everything that protects; the application and the in-bundle
//! command line interface are clients of it (spec section 6.2). What they say
//! to each other is here: the socket, the length-prefixed JSON frame, the
//! `hello` handshake that refuses a version mismatch or an unsigned peer, the
//! closed list of requests and their answers, and the one stream of state
//! events.
//!
//! The crate sits beside the daemon rather than inside it on purpose. A client
//! must be able to speak this vocabulary without linking the daemon, which
//! holds the write side of both chains and the Keychain; the command line
//! interface has a test that says so.

#![warn(missing_docs)]

pub mod client;
pub mod frame;
pub mod peer;
pub mod protocol;
pub mod socket;

pub use client::{Client, ClientError, Subscription};
pub use frame::{MAX_FRAME, read_frame, write_frame};
pub use peer::{Nobody, Peer, PeerCheck, SameUser};
pub use protocol::{
    Hello, Message, RESTART_AGENTSWEEP, Refusal, Request, RequestError, Role, StateEvent, Status,
    check_version, welcome,
};
pub use socket::{Connection, SOCKET_NAME, SocketListener, connect, default_socket_path};

#[cfg(test)]
mod tests {
    /// One name, one place. The socket is named after the bundle, as every
    /// machine-readable name in AgentSweep is.
    #[test]
    fn the_socket_is_named_after_the_bundle() {
        assert!(super::SOCKET_NAME.starts_with(agentsweep_core::BUNDLE_ID));
    }
}
