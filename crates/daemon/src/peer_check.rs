//! Who the daemon answers: a peer of the same user carrying byte5's signature.
//!
//! The daemon holds the file access macOS attributed to AgentSweep, the
//! Keychain key behind both chains and the only write path into the quarantine
//! store, so a uid check alone is not enough: every process the user runs has
//! the user's uid, including an Agent that has been prompt-injected. ADR 0008
//! settles it: same user **and** a code signature from the Team ID, checked on
//! the audit token, and everything else refused at the handshake.
//!
//! A debug build cannot do that. Nothing a developer builds is signed, so
//! refusing an unsigned peer would mean no build could be run by hand, and the
//! decision is made once, here, by which build this is: a debug build admits
//! any peer of the same user, and a release build admits the Team ID or
//! nobody.

use std::sync::Arc;

use agentsweep_ipc::peer::{Nobody, Peer, PeerCheck, SameUser};
use agentsweep_ipc::protocol::Refusal;

/// byte5's Apple Developer Team ID, which the release milestone fills in.
///
/// It is empty until then, and a release build that finds it empty answers
/// nobody rather than falling back to the user check: a build that cannot tell
/// its own programs from anything else on the machine must not answer at all.
pub const TEAM_ID: &str = "";

/// The check this build makes.
pub fn for_this_build() -> Arc<dyn PeerCheck> {
    if cfg!(debug_assertions) {
        return Arc::new(SameUser);
    }
    release_check(TEAM_ID)
}

/// The check a release build makes, given the Team ID compiled into it.
pub fn release_check(team_id: &str) -> Arc<dyn PeerCheck> {
    if team_id.is_empty() {
        return Arc::new(Nobody::because(
            "this build carries no Team ID, so it cannot tell its own programs apart",
        ));
    }
    Arc::new(SignedByTeam::of(team_id))
}

/// The code signing requirement one Team ID stands for.
///
/// `anchor apple generic` is what a Developer ID certificate chains to, and
/// the leaf's organisational unit is the Team ID. It is the shape the
/// designated requirement of every AgentSweep binary has
/// (`docs/research/macos-first-run-permissions.md` section 6).
pub fn requirement_for(team_id: &str) -> String {
    format!("anchor apple generic and certificate leaf[subject.OU] = \"{team_id}\"")
}

/// Admits a peer of the same user that satisfies the Team ID requirement.
#[derive(Clone, Debug)]
pub struct SignedByTeam {
    team_id: String,
    requirement: String,
}

impl SignedByTeam {
    /// The check for one Team ID.
    pub fn of(team_id: &str) -> SignedByTeam {
        SignedByTeam {
            team_id: team_id.to_string(),
            requirement: requirement_for(team_id),
        }
    }

    /// The requirement this check evaluates.
    pub fn requirement(&self) -> &str {
        &self.requirement
    }
}

impl PeerCheck for SignedByTeam {
    fn admits(&self, peer: &Peer) -> Result<(), Refusal> {
        // The user check first: it is cheap, and a peer of another user is
        // refused whatever it is signed with.
        SameUser.admits(peer)?;
        signature::satisfies(peer, &self.requirement)
    }

    fn describe(&self) -> String {
        format!("signed by Team ID {}", self.team_id)
    }
}

/// Asking the operating system whether the peer satisfies a requirement.
#[cfg(target_os = "macos")]
mod signature {
    use super::{Peer, Refusal};

    use core_foundation::base::{CFRelease, CFType, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use security_framework_sys::code_signing::{
        SecCodeCheckValidity, SecCodeCopyGuestWithAttributes, SecCodeRef,
        SecRequirementCreateWithString, SecRequirementRef, kSecGuestAttributeAudit,
        kSecGuestAttributePid,
    };

    /// The default flags: no extra validation beyond the requirement.
    const NO_FLAGS: u32 = 0;

    /// `errSecSuccess`.
    const SUCCESS: i32 = 0;

    /// A Core Foundation object this code owns and must release.
    struct Owned<T>(*mut T);

    impl<T> Drop for Owned<T> {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // Safety: the pointer came from a `Copy` or `Create` function,
                // so this code owns one reference to it and releases it once.
                unsafe { CFRelease(self.0.cast()) };
            }
        }
    }

    /// True when the peer's running code satisfies the requirement.
    ///
    /// The audit token is asked about first, because a process id can be
    /// reused between being read off the socket and being looked up while an
    /// audit token cannot. A peer the socket named no token for falls back to
    /// the process id, and a peer it named neither for is refused: an
    /// unidentifiable peer is not one to answer.
    pub fn satisfies(peer: &Peer, requirement: &str) -> Result<(), Refusal> {
        let attributes = match (peer.audit_token, peer.pid) {
            (Some(token), _) => audit_attributes(&token),
            (None, Some(pid)) => pid_attributes(pid),
            (None, None) => {
                return Err(Refusal::UnsignedPeer {
                    detail: "the socket did not say which process is on the other end".to_string(),
                });
            }
        };

        let mut guest: SecCodeRef = std::ptr::null_mut();
        // Safety: a null host asks the kernel about the guest the attributes
        // name; the out pointer is written only when the call succeeds.
        let found = unsafe {
            SecCodeCopyGuestWithAttributes(
                std::ptr::null_mut(),
                attributes.as_concrete_TypeRef(),
                NO_FLAGS,
                &raw mut guest,
            )
        };
        if found != SUCCESS || guest.is_null() {
            return Err(Refusal::UnsignedPeer {
                detail: format!("the peer has no code signature ({found})"),
            });
        }
        let guest = Owned(guest);

        let text = CFString::new(requirement);
        let mut wanted: SecRequirementRef = std::ptr::null_mut();
        // Safety: the string outlives the call, and the out pointer is written
        // only when the call succeeds.
        let compiled = unsafe {
            SecRequirementCreateWithString(text.as_concrete_TypeRef(), NO_FLAGS, &raw mut wanted)
        };
        if compiled != SUCCESS || wanted.is_null() {
            return Err(Refusal::UnsignedPeer {
                detail: format!("the requirement could not be compiled ({compiled})"),
            });
        }
        let wanted = Owned(wanted);

        // Safety: both references are alive for the length of the call.
        let valid = unsafe { SecCodeCheckValidity(guest.0, NO_FLAGS, wanted.0) };
        if valid != SUCCESS {
            return Err(Refusal::UnsignedPeer {
                detail: format!("the peer's signature is not AgentSweep's ({valid})"),
            });
        }
        Ok(())
    }

    /// The guest attributes that name a peer by its audit token.
    fn audit_attributes(token: &[u32; 8]) -> CFDictionary<CFString, CFType> {
        let bytes: Vec<u8> = token.iter().flat_map(|word| word.to_ne_bytes()).collect();
        // Safety: the constant is a Core Foundation string the framework owns,
        // and `wrap_under_get_rule` retains it for as long as this value lives.
        let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributeAudit) };
        CFDictionary::from_CFType_pairs(&[(key, CFData::from_buffer(&bytes).as_CFType())])
    }

    /// The guest attributes that name a peer by its process id.
    fn pid_attributes(pid: i32) -> CFDictionary<CFString, CFType> {
        // Safety: as above.
        let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) };
        CFDictionary::from_CFType_pairs(&[(key, CFNumber::from(pid).as_CFType())])
    }
}

/// Asking the operating system whether the peer satisfies a requirement.
///
/// There is no such operating system here. The signature check is macOS's, and
/// the integration layer for the other platforms is a later effort (spec
/// section 6.1), so until then nothing off macOS is admitted.
#[cfg(not(target_os = "macos"))]
mod signature {
    use super::{Peer, Refusal};

    pub fn satisfies(_peer: &Peer, _requirement: &str) -> Result<(), Refusal> {
        Err(Refusal::UnsignedPeer {
            detail: "this platform has no code signature to check".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_ipc::peer::this_user;

    /// The requirement is the shape a Developer ID designated requirement has:
    /// the Apple anchor, and the Team ID as the leaf's organisational unit.
    #[test]
    fn the_requirement_names_the_apple_anchor_and_the_team_id() {
        let requirement = requirement_for("ABCDE12345");
        assert_eq!(
            requirement,
            "anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\""
        );
    }

    /// A release build whose Team ID was never filled in answers nobody. It
    /// must not fall back to the user check: that is the confused deputy ADR
    /// 0008 is about.
    #[test]
    fn a_release_build_without_a_team_id_admits_nobody() {
        let check = release_check("");
        let refusal = check
            .admits(&Peer::of_user(this_user()))
            .expect_err("nobody is admitted");
        assert_eq!(refusal.reason(), "unsigned-peer");
        assert!(check.describe().contains("nobody"), "{}", check.describe());
    }

    /// A peer of another user is refused before the signature is looked at,
    /// so the refusal is about the user and not about the signature.
    #[test]
    fn a_peer_of_another_user_is_refused_by_the_team_check_too() {
        let check = SignedByTeam::of("ABCDE12345");
        let other = Peer::of_user(this_user().wrapping_add(1)).with_pid(4242);
        let refusal = check.admits(&other).expect_err("another user is refused");
        assert!(refusal.message().contains("another user"), "{refusal}");
    }

    /// The suite runs against unsigned binaries, so this is what the release
    /// check answers about a test process: refused, with a reason, rather than
    /// admitted for want of a signature to look at.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_unsigned_peer_of_this_user_is_refused_by_the_team_check() {
        let check = SignedByTeam::of("ABCDE12345");
        let me = Peer::of_user(this_user()).with_pid(std::process::id() as i32);
        let refusal = check.admits(&me).expect_err("this build is not byte5's");
        assert_eq!(refusal.reason(), "unsigned-peer");
    }

    /// A peer the socket could not name is refused rather than admitted: an
    /// unidentifiable peer is not one to answer.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_peer_with_neither_a_process_nor_a_token_is_refused() {
        let check = SignedByTeam::of("ABCDE12345");
        let nameless = Peer::of_user(this_user());
        let refusal = check.admits(&nameless).expect_err("a nameless peer");
        assert!(
            refusal.message().contains("which process"),
            "{}",
            refusal.message()
        );
    }

    /// A debug build admits the developer's own unsigned programs, and says
    /// so, so nobody mistakes it for the check a release makes.
    #[test]
    fn this_build_admits_what_its_kind_of_build_admits() {
        let check = for_this_build();
        if cfg!(debug_assertions) {
            assert_eq!(check.describe(), "the same user");
            assert!(check.admits(&Peer::of_user(this_user())).is_ok());
        } else {
            assert!(check.admits(&Peer::of_user(this_user())).is_err());
        }
    }
}
