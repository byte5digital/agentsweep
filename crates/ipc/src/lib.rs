//! The AgentSweep inter-process vocabulary.
//!
//! The daemon owns everything that protects; the application and the in-bundle
//! command line interface are clients of it (spec section 6.2). What they say
//! to each other is here: the socket, the length-prefixed JSON frame, the
//! `hello` handshake that refuses a version mismatch or an unsigned peer, the
//! closed list of requests and their answers (the actions among them, each
//! addressing a Finding, Item or Receipt id), and the one stream of state
//! events.
//!
//! The crate sits beside the daemon rather than inside it on purpose. A client
//! must be able to speak this vocabulary without linking the daemon, which
//! holds the write side of both chains and the Keychain; the command line
//! interface has a test that says so.

#![warn(missing_docs)]

pub mod client;
pub mod engine;
pub mod frame;
pub mod gate;
pub mod integrity;
pub mod judge;
pub mod notifications;
pub mod peer;
pub mod preview;
pub mod protocol;
pub mod settings;
pub mod socket;

pub use client::{Client, ClientError, Subscription};
pub use frame::{MAX_FRAME, read_frame, write_frame};
pub use integrity::{ChainRecords, IntegrityAnswer, RECORDS_PAGE, RecordLine};
pub use notifications::{NotificationClass, Unnotified, WINDOWLESS};
pub use peer::{Nobody, Peer, PeerCheck, SameUser};
pub use protocol::{
    ActionReport, AgentSessions, DO_NOT_OPEN_YET, EngineChange, EngineState, FolderFinding,
    FolderScanResult, GateEvent, GateReason, GateRequest, GateTool, GateVerdict, Hello,
    McpServerRef, Message, NOTHING_RECORDED, Offer, RESTART_AGENTSWEEP, Refusal, Request,
    RequestError, RevealedReceipt, Role, SAFE_TO_OPEN, Sessions, SettingsChange, SettingsState,
    StateEvent, Status, check_version, offers, welcome,
};
pub use socket::{Connection, Liveness, SOCKET_NAME, SocketListener, connect, default_socket_path};

#[cfg(test)]
mod tests {
    /// One name, one place. The socket is named after the bundle, as every
    /// machine-readable name in AgentSweep is.
    #[test]
    fn the_socket_is_named_after_the_bundle() {
        assert!(super::SOCKET_NAME.starts_with(agentsweep_core::BUNDLE_ID));
    }
}
