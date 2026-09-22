//! The key that protects both chains, and where it comes from.
//!
//! The Event Log and the Baseline are authenticated with one 32-byte key held
//! in the login Keychain under the daemon's identity (ADR 0003). The daemon is
//! the only process that touches the Keychain; the application and the CLI ask
//! the daemon over its socket and never read the item themselves (spec section
//! 6.2, `docs/research/macos-first-run-permissions.md` section 7).
//!
//! The chain logic never reaches for the Keychain itself. It takes a
//! [`KeySource`], so a test holds its key in memory and the real Keychain is
//! touched by exactly one implementation, [`LoginKeychain`], which the crate
//! compiles only with the `daemon` feature the daemon crate turns on. No file
//! ever holds the key.

use std::fmt;

use crate::DAEMON_LABEL;

/// The length of the key, in bytes. HMAC-SHA256 under a key of one block.
pub const KEY_LENGTH: usize = 32;

/// The 32-byte key both chains are authenticated with.
///
/// It is never printed, never logged and never written to a file. The bytes
/// are wiped when the value is dropped.
pub struct ChainKey([u8; KEY_LENGTH]);

impl ChainKey {
    /// Takes a key that is already known, which is how a [`KeySource`] returns
    /// what it read.
    pub fn from_bytes(bytes: [u8; KEY_LENGTH]) -> ChainKey {
        ChainKey(bytes)
    }

    /// A fresh key from the operating system's random source.
    pub fn generate() -> Result<ChainKey, KeyError> {
        let mut bytes = [0u8; KEY_LENGTH];
        getrandom::fill(&mut bytes)
            .map_err(|error| KeyError::Unavailable(format!("no random source: {error}")))?;
        Ok(ChainKey(bytes))
    }

    /// The bytes, for the one caller that computes a MAC with them.
    pub(crate) fn bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }
}

impl Drop for ChainKey {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // A volatile write is not elided by the optimiser, so the key does
            // not linger in the freed stack slot.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl fmt::Debug for ChainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChainKey(redacted, {KEY_LENGTH} bytes)")
    }
}

/// Why a key could not be read or stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyError {
    /// The store could not be reached at all.
    Unavailable(String),
    /// A key is there but is not the 32 bytes a [`ChainKey`] is.
    Malformed(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Unavailable(detail) => write!(f, "the key store is unavailable: {detail}"),
            KeyError::Malformed(detail) => write!(f, "the stored key is malformed: {detail}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// Where the chain key comes from.
///
/// One implementation reaches the login Keychain; the others exist so that a
/// test never does. Returning `Ok(None)` from [`KeySource::load`] is the
/// key-missing state of ADR 0003: a migrated Mac, a reset Keychain or a
/// restored backup, not an attack.
pub trait KeySource {
    /// The key the store holds, or `None` when it holds none.
    fn load(&self) -> Result<Option<ChainKey>, KeyError>;

    /// Generates a fresh key, stores it in place of any key held, and returns
    /// it. Called once on first use and again whenever the key went missing.
    fn renew(&self) -> Result<ChainKey, KeyError>;

    /// Removes the key from the store. Uninstall does this; nothing else does.
    fn forget(&self) -> Result<(), KeyError>;
}

/// A key that lives only as long as the process. For tests and for nothing
/// else: the shipped daemon reads [`LoginKeychain`].
#[derive(Debug, Default)]
pub struct MemoryKeySource {
    held: std::sync::Mutex<Option<[u8; KEY_LENGTH]>>,
}

impl MemoryKeySource {
    /// An empty store, as a Mac that has never run AgentSweep would have.
    pub fn empty() -> MemoryKeySource {
        MemoryKeySource::default()
    }

    /// A store already holding a key, which is how a test stands in for a
    /// daemon that has run before.
    pub fn holding(key: ChainKey) -> MemoryKeySource {
        MemoryKeySource {
            held: std::sync::Mutex::new(Some(*key.bytes())),
        }
    }
}

impl KeySource for MemoryKeySource {
    fn load(&self) -> Result<Option<ChainKey>, KeyError> {
        let held = self
            .held
            .lock()
            .map_err(|_| KeyError::Unavailable("the key store was poisoned".to_string()))?;
        Ok(held.map(ChainKey::from_bytes))
    }

    fn renew(&self) -> Result<ChainKey, KeyError> {
        let fresh = ChainKey::generate()?;
        let mut held = self
            .held
            .lock()
            .map_err(|_| KeyError::Unavailable("the key store was poisoned".to_string()))?;
        *held = Some(*fresh.bytes());
        Ok(fresh)
    }

    fn forget(&self) -> Result<(), KeyError> {
        let mut held = self
            .held
            .lock()
            .map_err(|_| KeyError::Unavailable("the key store was poisoned".to_string()))?;
        *held = None;
        Ok(())
    }
}

/// The service the Keychain item is filed under: the daemon's identity, which
/// is the bundle id with the daemon suffix.
pub const KEYCHAIN_SERVICE: &str = DAEMON_LABEL;

/// The account of the Keychain item. One key protects both chains.
pub const KEYCHAIN_ACCOUNT: &str = "chain-key";

#[cfg(all(feature = "daemon", target_os = "macos"))]
mod login_keychain {
    use super::{ChainKey, KEY_LENGTH, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE, KeyError, KeySource};

    use security_framework::passwords::{
        PasswordOptions, delete_generic_password, generic_password, set_generic_password,
    };

    /// `errSecItemNotFound`: the item is not in the Keychain. It is the
    /// key-missing state, never an error.
    const ITEM_NOT_FOUND: i32 = -25300;

    /// The key in the user's login Keychain, reached through `SecItem`.
    ///
    /// This is the only type in AgentSweep that touches the Keychain, and it
    /// exists only in a build with the `daemon` feature, so the application
    /// and the CLI cannot compile a call to it. A file-based item is used on
    /// purpose: the data protection Keychain needs an entitlement a Developer
    /// ID build has no provisioning profile for.
    #[derive(Debug, Default)]
    pub struct LoginKeychain {
        service: String,
        account: String,
    }

    impl LoginKeychain {
        /// The item the daemon owns.
        pub fn for_the_daemon() -> LoginKeychain {
            LoginKeychain {
                service: KEYCHAIN_SERVICE.to_string(),
                account: KEYCHAIN_ACCOUNT.to_string(),
            }
        }

        /// An item under a name of the caller's choosing. The one sanctioned
        /// use is a test that must not go near the daemon's own item.
        pub fn named(service: &str, account: &str) -> LoginKeychain {
            LoginKeychain {
                service: service.to_string(),
                account: account.to_string(),
            }
        }
    }

    impl KeySource for LoginKeychain {
        fn load(&self) -> Result<Option<ChainKey>, KeyError> {
            let options = PasswordOptions::new_generic_password(&self.service, &self.account);
            match generic_password(options) {
                Ok(bytes) => {
                    let bytes: [u8; KEY_LENGTH] = bytes.as_slice().try_into().map_err(|_| {
                        KeyError::Malformed(format!(
                            "the Keychain item holds {} bytes, not {KEY_LENGTH}",
                            bytes.len()
                        ))
                    })?;
                    Ok(Some(ChainKey::from_bytes(bytes)))
                }
                Err(error) if error.code() == ITEM_NOT_FOUND => Ok(None),
                Err(error) => Err(KeyError::Unavailable(format!(
                    "the login Keychain refused the read: {error}"
                ))),
            }
        }

        fn renew(&self) -> Result<ChainKey, KeyError> {
            let fresh = ChainKey::generate()?;
            set_generic_password(&self.service, &self.account, fresh.bytes()).map_err(|error| {
                KeyError::Unavailable(format!("the login Keychain refused the write: {error}"))
            })?;
            Ok(fresh)
        }

        fn forget(&self) -> Result<(), KeyError> {
            match delete_generic_password(&self.service, &self.account) {
                Ok(()) => Ok(()),
                Err(error) if error.code() == ITEM_NOT_FOUND => Ok(()),
                Err(error) => Err(KeyError::Unavailable(format!(
                    "the login Keychain refused the delete: {error}"
                ))),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Touches the real login Keychain, so it never runs by itself. Run it
        /// by hand with `cargo test -p agentsweep-core --features daemon --
        /// --ignored the_login_keychain`, which leaves no item behind: the
        /// test removes what it wrote.
        #[test]
        #[ignore = "writes to the developer's own login Keychain"]
        fn the_login_keychain_holds_and_returns_the_key() {
            let keychain =
                LoginKeychain::named("de.byte5.agentsweep.daemon.test", "chain-key-test");
            keychain.forget().expect("a clean start");
            assert!(keychain.load().expect("a readable Keychain").is_none());

            let written = keychain.renew().expect("the Keychain takes the key");
            let read = keychain
                .load()
                .expect("a readable Keychain")
                .expect("the key is there");
            assert_eq!(written.bytes(), read.bytes());

            keychain.forget().expect("the item goes away");
            assert!(keychain.load().expect("a readable Keychain").is_none());
        }
    }
}

#[cfg(all(feature = "daemon", target_os = "macos"))]
pub use login_keychain::LoginKeychain;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_is_thirty_two_bytes_and_not_all_zero() {
        let key = ChainKey::generate().expect("a random source");
        assert_eq!(key.bytes().len(), KEY_LENGTH);
        assert!(key.bytes().iter().any(|byte| *byte != 0));
    }

    #[test]
    fn two_generated_keys_differ() {
        let one = ChainKey::generate().expect("a random source");
        let other = ChainKey::generate().expect("a random source");
        assert_ne!(one.bytes(), other.bytes());
    }

    #[test]
    fn a_key_never_prints_its_bytes() {
        let key = ChainKey::from_bytes([7u8; KEY_LENGTH]);
        let printed = format!("{key:?}");
        assert_eq!(printed, "ChainKey(redacted, 32 bytes)");
        assert!(!printed.contains('7'));
    }

    #[test]
    fn an_empty_store_holds_no_key_until_it_is_renewed() {
        let source = MemoryKeySource::empty();
        assert!(source.load().expect("a readable store").is_none());

        let fresh = source.renew().expect("a fresh key");
        let read = source
            .load()
            .expect("a readable store")
            .expect("the key is there");
        assert_eq!(fresh.bytes(), read.bytes());
    }

    #[test]
    fn forgetting_the_key_leaves_the_store_empty() {
        let source = MemoryKeySource::holding(ChainKey::from_bytes([3u8; KEY_LENGTH]));
        assert!(source.load().expect("a readable store").is_some());
        source.forget().expect("the key goes away");
        assert!(source.load().expect("a readable store").is_none());
    }

    #[test]
    fn the_keychain_item_is_named_after_the_daemon() {
        assert_eq!(KEYCHAIN_SERVICE, "de.byte5.agentsweep.daemon");
        assert!(KEYCHAIN_SERVICE.starts_with(crate::BUNDLE_ID));
        assert_eq!(KEYCHAIN_ACCOUNT, "chain-key");
    }
}
