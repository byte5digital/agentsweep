//! Who is on the other end of the socket, and whether the daemon answers them.
//!
//! The daemon holds the file access the operating system attributed to
//! AgentSweep, the Keychain key behind both chains and the only write path into
//! the quarantine store. Any local process that can reach the socket could
//! otherwise ask it to read or rewrite what the caller itself may not touch, so
//! ADR 0008 admits a peer only when it runs as the same user **and** carries
//! AgentSweep's own code signature.
//!
//! The check is a trait, for two reasons. The signature check is a macOS
//! Security framework call that no test can satisfy without a signed binary,
//! and the peer facts it needs, the process id and the audit token, are read
//! here where the socket is. What a build actually admits is the daemon's to
//! choose: a debug build takes any peer of the same user, and a release build
//! takes only the Team ID.

use std::fmt;

use crate::protocol::Refusal;

/// What the daemon knows about the process on the other end.
///
/// The audit token is what a signature check should ask about: a process id
/// can be reused between the moment it is read and the moment it is looked up,
/// and an audit token cannot. It is absent where the operating system did not
/// give one, and then the process id is all there is.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Peer {
    /// The peer's effective user id.
    pub uid: u32,
    /// The peer's process id, absent when the socket did not answer.
    pub pid: Option<i32>,
    /// The peer's audit token, absent when the socket did not answer.
    pub audit_token: Option<[u32; 8]>,
}

impl Peer {
    /// A peer known by its user alone, which is what a test builds.
    pub fn of_user(uid: u32) -> Peer {
        Peer {
            uid,
            ..Peer::default()
        }
    }

    /// The same peer with a process id.
    pub fn with_pid(mut self, pid: i32) -> Peer {
        self.pid = Some(pid);
        self
    }

    /// The same peer with an audit token.
    pub fn with_audit_token(mut self, token: [u32; 8]) -> Peer {
        self.audit_token = Some(token);
        self
    }

    /// True when the peer runs as the user this process does.
    pub fn is_same_user(&self) -> bool {
        self.uid == this_user()
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pid {
            Some(pid) => write!(f, "uid {} pid {pid}", self.uid),
            None => write!(f, "uid {}", self.uid),
        }
    }
}

/// The effective user id of this process.
pub fn this_user() -> u32 {
    // Safety: `geteuid` reads one field of the running process and cannot
    // fail. It is here rather than in the standard library because the
    // standard library does not expose it.
    unsafe { libc::geteuid() }
}

/// Whether the daemon answers a peer.
///
/// One implementation reaches the macOS Security framework and lives in the
/// daemon, where the dependency belongs. The ones here exist so that both
/// branches of the decision are exercised without a signed binary.
pub trait PeerCheck: Send + Sync {
    /// Admits the peer, or says why not.
    fn admits(&self, peer: &Peer) -> Result<(), Refusal>;

    /// What this check is, for the daemon's own log. Never a value, never a
    /// path: a log line says which check ran, not what it read.
    fn describe(&self) -> String;
}

/// Admits any peer running as the same user.
///
/// This is what a debug build uses: a developer's `agentsweepd` and
/// `agentsweep` are not signed, and refusing them would mean no build could be
/// run by hand. It is never what a release build uses, because every process
/// the user runs has the user's own uid, including an Agent that has been
/// prompt-injected (ADR 0008).
#[derive(Clone, Copy, Debug, Default)]
pub struct SameUser;

impl PeerCheck for SameUser {
    fn admits(&self, peer: &Peer) -> Result<(), Refusal> {
        if peer.is_same_user() {
            return Ok(());
        }
        Err(Refusal::UnsignedPeer {
            detail: format!("the peer runs as another user ({peer})"),
        })
    }

    fn describe(&self) -> String {
        "the same user".to_string()
    }
}

/// Admits nobody at all, with a reason.
///
/// A release build whose Team ID constant was never filled in refuses every
/// peer through this rather than falling back to the user check, because a
/// build that cannot tell its own programs apart from anything else on the
/// machine must not answer (ADR 0008).
#[derive(Clone, Debug)]
pub struct Nobody {
    reason: String,
}

impl Nobody {
    /// A check that refuses everyone, saying why.
    pub fn because(reason: impl Into<String>) -> Nobody {
        Nobody {
            reason: reason.into(),
        }
    }
}

impl PeerCheck for Nobody {
    fn admits(&self, _peer: &Peer) -> Result<(), Refusal> {
        Err(Refusal::UnsignedPeer {
            detail: self.reason.clone(),
        })
    }

    fn describe(&self) -> String {
        format!("nobody: {}", self.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_user_check_admits_this_process_and_nobody_else() {
        let check = SameUser;
        assert!(check.admits(&Peer::of_user(this_user())).is_ok());

        let other = Peer::of_user(this_user().wrapping_add(1)).with_pid(4242);
        let refusal = check.admits(&other).expect_err("another user is refused");
        assert_eq!(refusal.reason(), "unsigned-peer");
        assert!(refusal.message().contains("another user"), "{refusal}");
    }

    /// The reason a peer was refused is a fact about the peer, never a value
    /// read off the machine.
    #[test]
    fn a_refusal_names_the_peer_by_its_user_and_process_and_nothing_else() {
        let peer = Peer::of_user(501).with_pid(99).with_audit_token([1; 8]);
        assert_eq!(peer.to_string(), "uid 501 pid 99");
    }

    #[test]
    fn a_build_that_cannot_identify_its_own_programs_answers_nobody() {
        let check = Nobody::because("no Team ID is built in");
        let refusal = check
            .admits(&Peer::of_user(this_user()))
            .expect_err("nobody means nobody");
        assert_eq!(refusal.reason(), "unsigned-peer");
        assert!(check.describe().contains("Team ID"));
    }
}
