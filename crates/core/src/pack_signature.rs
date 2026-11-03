//! The detached signature over a Rule Pack's manifest, and the keys this
//! binary trusts to make it.
//!
//! A Rule Pack from the Rule Feed is accepted only when its `manifest.json`
//! carries a valid minisign (Ed25519) signature from one of the public keys
//! pinned here (spec section 9.4, ADR 0006). Two keys are pinned: the active
//! key the release workflow signs with, and a standby key generated offline
//! that every client in the field already trusts, so a leaked active key can
//! be retired within the hour. A pack signed by either is accepted; during a
//! rotation a pack carries both signatures.
//!
//! Each signature is a detached file beside the manifest named by the key id
//! that made it, `<KEY ID>.minisig`, where the key id is the one minisign
//! prints for the key: sixteen upper-case hex digits. The id is read off the
//! pinned key itself, never written down separately, so it cannot drift from
//! the key it names.
//!
//! Verification is offline and uses `minisign-verify`, which has no
//! dependencies. Only pre-hashed signatures are accepted, which is what
//! minisign has written by default since 0.8; the legacy mode signs the raw
//! bytes and is refused.
//!
//! **Which keys a build pins.** A build without the test-only
//! `development-keys` feature, which is every shipped binary, pins byte5's
//! two Rule Pack public keys, [`RELEASE_KEYS`] (spec section 9.8, item 2),
//! whose secret halves never enter the repository. A test build turns the
//! feature on and pins the development pairs instead, whose secret halves are
//! committed under `crates/core/development-keys/` so the tests can sign;
//! such a build trusts no release key, and no build without the feature can
//! trust a development key, because the development table is not compiled
//! into it at all. The release bundle checker reads the daemon and the CLI of
//! a bundle and refuses one that carries a development public key.

use std::collections::BTreeMap;
use std::fmt;

use minisign_verify::{PublicKey, Signature};

/// Which of the two pinned keys a key is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRole {
    /// The key the release workflow signs with.
    Active,
    /// The key generated offline and never uploaded, which signs from the
    /// hour the active key is known to have leaked.
    Standby,
}

impl KeyRole {
    /// The spelling a log line carries.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyRole::Active => "active",
            KeyRole::Standby => "standby",
        }
    }
}

impl fmt::Display for KeyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One Rule Pack public key this binary trusts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedKey {
    /// Active or standby.
    pub role: KeyRole,
    /// The public key as minisign writes it on the second line of a `.pub`
    /// file: base64 of the algorithm, the key id and the Ed25519 key.
    pub public_key: &'static str,
    /// True while the key is a development key whose secret half is in the
    /// repository. A release build pins no such key.
    pub development: bool,
}

impl PinnedKey {
    /// The key id, as minisign prints it and as the signature file is named.
    pub fn key_id(&self) -> String {
        key_id_of(self.public_key).unwrap_or_default()
    }

    /// The name of the detached signature this key makes over a manifest.
    pub fn signature_file(&self) -> String {
        signature_file(&self.key_id())
    }
}

/// The Rule Pack public keys this binary trusts: active first, standby
/// second.
///
/// A shipped binary pins [`RELEASE_KEYS`]. Only a build with the test-only
/// `development-keys` feature pins the development pairs of
/// `development::KEYS` instead, and then it pins nothing else.
#[cfg(not(feature = "development-keys"))]
pub const PINNED_KEYS: [PinnedKey; 2] = RELEASE_KEYS;

/// The Rule Pack public keys this binary trusts: active first, standby
/// second.
///
/// This is a test build: the `development-keys` feature is on, so the
/// development pairs of [`development::KEYS`] are pinned in place of
/// [`RELEASE_KEYS`], and the tests sign with their committed secret halves.
#[cfg(feature = "development-keys")]
pub const PINNED_KEYS: [PinnedKey; 2] = development::KEYS;

/// byte5's Rule Pack public keys, which every shipped binary pins: the active
/// key the release workflow signs with (key id `5DDA49F105939297`) and the
/// standby key generated offline (key id `EA33B324921AC1B3`). Their secret
/// halves never enter the repository. A rotation changes this table in an
/// app release (ADR 0006).
pub const RELEASE_KEYS: [PinnedKey; 2] = [
    PinnedKey {
        role: KeyRole::Active,
        public_key: "RWSXkpMF8UnaXfCLhUIS/VYdBBYCYBTezI6UjTQ7uZLJ+AUyjyoEeGMy",
        development: false,
    },
    PinnedKey {
        role: KeyRole::Standby,
        public_key: "RWSzwRqSJLMz6nWd521dwCELV2stAyN2a0cR/5ThTsTK2l/1B6QYPiam",
        development: false,
    },
];

/// The file extension of a detached signature.
pub const SIGNATURE_EXTENSION: &str = "minisig";

/// The name of the detached signature a key of this id makes over a
/// manifest: `<KEY ID>.minisig`, beside `manifest.json`.
pub fn signature_file(key_id: &str) -> String {
    format!("{key_id}.{SIGNATURE_EXTENSION}")
}

/// The key id of a minisign public key: bytes 2 to 9 of the decoded key,
/// read as a little-endian integer and printed as sixteen upper-case hex
/// digits, which is how minisign itself names a key.
pub fn key_id_of(public_key: &str) -> Option<String> {
    let bytes = base64_decode(public_key.trim())?;
    if bytes.len() != 42 {
        return None;
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[2..10]);
    Some(format!("{:016X}", u64::from_le_bytes(id)))
}

/// Why a manifest's signatures were not accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// No signature by any pinned key was offered at all.
    Unsigned,
    /// Signatures by pinned keys were offered and none of them verifies. The
    /// strings say what was wrong with each, by key id.
    Invalid(Vec<String>),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::Unsigned => f.write_str("no pinned key signed the manifest"),
            SignatureError::Invalid(why) => {
                write!(
                    f,
                    "no signature over the manifest verifies: {}",
                    why.join("; ")
                )
            }
        }
    }
}

impl std::error::Error for SignatureError {}

/// Verifies a manifest against the keys pinned in this binary. The signatures
/// are the texts of the detached files, by the key id their file is named
/// after. Answers with the pinned key whose signature verified.
pub fn verify(
    manifest: &[u8],
    signatures: &BTreeMap<String, String>,
) -> Result<PinnedKey, SignatureError> {
    verify_with(&PINNED_KEYS, manifest, signatures)
}

/// The same against a set of keys of the caller's choosing, which is how a
/// test proves that a key nobody pinned is refused.
pub fn verify_with(
    keys: &[PinnedKey],
    manifest: &[u8],
    signatures: &BTreeMap<String, String>,
) -> Result<PinnedKey, SignatureError> {
    let mut problems = Vec::new();
    for key in keys {
        let id = key.key_id();
        let Some(text) = signatures.get(&id) else {
            continue;
        };
        let checked = PublicKey::from_base64(key.public_key)
            .map_err(|error| format!("{id}: the pinned key does not read: {error}"))
            .and_then(|public| {
                let signature = Signature::decode(text)
                    .map_err(|error| format!("{id}: not a signature: {error}"))?;
                public
                    .verify(manifest, &signature, false)
                    .map_err(|error| format!("{id}: {error}"))
            });
        match checked {
            Ok(()) => return Ok(*key),
            Err(problem) => problems.push(problem),
        }
    }
    match problems.is_empty() {
        true => Err(SignatureError::Unsigned),
        false => Err(SignatureError::Invalid(problems)),
    }
}

/// Standard base64 with padding, which is what minisign writes. Nothing when
/// the text is not that.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| -> Option<u32> {
        Some(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index == bytes.len() / 4 - 1;
        let padding = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 || (padding > 0 && !last) {
            return None;
        }
        let mut word = 0u32;
        for byte in &chunk[..4 - padding] {
            word = (word << 6) | value(*byte)?;
        }
        word <<= 6 * padding as u32;
        let decoded = [(word >> 16) as u8, (word >> 8) as u8, word as u8];
        out.extend_from_slice(&decoded[..3 - padding]);
    }
    Some(out)
}

/// Signing with the development key pairs, for tests alone.
///
/// Compiled only with the `development-keys` feature, which only a test build
/// turns on: a shipped binary verifies and never signs, and does not even
/// carry the development public keys. The secret halves are named as
/// development keys, are unencrypted on purpose, and protect nothing real;
/// nothing but a test build, which pins `KEYS` in place of the release
/// keys, trusts them.
///
/// The feature builds inside the repository alone: the core published to
/// crates.io leaves the secret halves out of its package, so turning the
/// feature on for that crate does not compile.
#[cfg(feature = "development-keys")]
pub mod development {
    use super::{KeyRole, PINNED_KEYS, PinnedKey};

    /// The development Rule Pack public keys, active first, standby second,
    /// which a test build pins in place of the release keys. The release
    /// bundle checker knows them too, and refuses a bundle whose daemon or
    /// CLI carries either.
    pub const KEYS: [PinnedKey; 2] = [
        PinnedKey {
            role: KeyRole::Active,
            public_key: "RWTZoZrRXs0kE+haygvOOKaRDbtDUSc8L5YKr/o+X3VsI5peZv07AXaL",
            development: true,
        },
        PinnedKey {
            role: KeyRole::Standby,
            public_key: "RWRNqibQ4kJKgnptbB11DaW4nFmh3O4rwaSlLf76s9ut12aQ3XX7o9KL",
            development: true,
        },
    ];

    /// The secret half of the development active key.
    pub const ACTIVE_SECRET: &str =
        include_str!("../development-keys/rule-pack-development-active.secret");

    /// The secret half of the development standby key.
    pub const STANDBY_SECRET: &str =
        include_str!("../development-keys/rule-pack-development-standby.secret");

    /// The pinned key of one role.
    pub fn pinned(role: KeyRole) -> PinnedKey {
        *PINNED_KEYS
            .iter()
            .find(|key| key.role == role)
            .expect("both roles are pinned")
    }

    /// Signs a manifest with the development key of one role. Answers with the
    /// key id and the text of the detached signature file.
    pub fn sign(role: KeyRole, manifest: &[u8]) -> (String, String) {
        let secret = match role {
            KeyRole::Active => ACTIVE_SECRET,
            KeyRole::Standby => STANDBY_SECRET,
        };
        let secret = minisign::SecretKeyBox::from_string(secret)
            .and_then(minisign::SecretKey::from_unencrypted_box)
            .expect("the development secret key reads");
        let signature = minisign::sign(
            None,
            &secret,
            manifest,
            Some("agentsweep rule pack, development key"),
            None,
        )
        .expect("the development key signs");
        (pinned(role).key_id(), signature.to_string())
    }

    /// Signs a manifest with a key pair made on the spot, which nothing pins.
    /// Answers with that key's id and the signature.
    pub fn sign_with_an_unpinned_key(manifest: &[u8]) -> (String, String) {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().expect("a throwaway key pair");
        let id = super::key_id_of(&pair.pk.to_base64()).expect("a key id");
        let signature =
            minisign::sign(None, &pair.sk, manifest, None, None).expect("the throwaway key signs");
        (id, signature.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::development::{pinned, sign, sign_with_an_unpinned_key};
    use super::*;

    const MANIFEST: &[u8] = b"{\"pack_version\": 2}\n";

    fn one(signed: (String, String)) -> BTreeMap<String, String> {
        BTreeMap::from([signed])
    }

    #[test]
    fn two_keys_are_pinned_one_active_and_one_standby_with_distinct_ids() {
        assert_eq!(PINNED_KEYS[0].role, KeyRole::Active);
        assert_eq!(PINNED_KEYS[1].role, KeyRole::Standby);
        let ids: Vec<String> = PINNED_KEYS.iter().map(PinnedKey::key_id).collect();
        assert!(ids.iter().all(|id| id.len() == 16), "{ids:?}");
        assert_ne!(ids[0], ids[1]);
        assert_eq!(
            PINNED_KEYS[0].signature_file(),
            format!("{}.minisig", ids[0])
        );
    }

    /// The key id is minisign's own: the one `minisign -G` prints and the one
    /// a signature carries, so the file a release writes is found by name.
    #[test]
    fn the_key_id_is_the_one_minisign_puts_in_a_signature() {
        let (id, text) = sign(KeyRole::Active, MANIFEST);
        assert_eq!(id, pinned(KeyRole::Active).key_id());
        let decoded = minisign::SignatureBox::from_string(&text).expect("a signature");
        let carried = u64::from_le_bytes(decoded.keynum().try_into().expect("eight bytes"));
        assert_eq!(format!("{carried:016X}"), id);
    }

    #[test]
    fn a_signature_by_either_pinned_key_is_accepted() {
        for role in [KeyRole::Active, KeyRole::Standby] {
            let verified = verify(MANIFEST, &one(sign(role, MANIFEST))).expect("it verifies");
            assert_eq!(verified.role, role);
        }
    }

    /// During a rotation a pack carries both signatures; one good one is
    /// enough, and a broken one beside it does not spoil it.
    #[test]
    fn one_good_signature_among_several_is_enough() {
        let mut both = one(sign(KeyRole::Active, b"another manifest"));
        both.extend(one(sign(KeyRole::Standby, MANIFEST)));
        assert_eq!(
            verify(MANIFEST, &both)
                .expect("the standby signature verifies")
                .role,
            KeyRole::Standby
        );
    }

    #[test]
    fn a_changed_manifest_does_not_verify() {
        let signed = one(sign(KeyRole::Active, MANIFEST));
        let error = verify(b"{\"pack_version\": 9}\n", &signed).expect_err("refused");
        assert!(matches!(error, SignatureError::Invalid(_)), "{error}");
    }

    #[test]
    fn a_key_nobody_pinned_is_not_trusted() {
        let signed = one(sign_with_an_unpinned_key(MANIFEST));
        assert_eq!(verify(MANIFEST, &signed), Err(SignatureError::Unsigned));

        // Nor does naming the file after a pinned key help: the signature
        // carries the id of the key that made it.
        let (_, text) = sign_with_an_unpinned_key(MANIFEST);
        let posing = BTreeMap::from([(pinned(KeyRole::Active).key_id(), text)]);
        assert!(matches!(
            verify(MANIFEST, &posing),
            Err(SignatureError::Invalid(_))
        ));
    }

    #[test]
    fn no_signature_at_all_is_unsigned() {
        assert_eq!(
            verify(MANIFEST, &BTreeMap::new()),
            Err(SignatureError::Unsigned)
        );
        let garbage = BTreeMap::from([(pinned(KeyRole::Active).key_id(), "hello".to_string())]);
        assert!(matches!(
            verify(MANIFEST, &garbage),
            Err(SignatureError::Invalid(_))
        ));
    }

    /// A test build pins the development pairs and nothing else, and the
    /// secret halves in the repository are the pairs of exactly those keys.
    #[test]
    fn a_test_build_pins_the_development_pairs_and_no_release_key() {
        assert_eq!(PINNED_KEYS, super::development::KEYS);
        for key in PINNED_KEYS {
            assert!(key.development, "{} is a development key", key.role);
            let (id, text) = sign(key.role, MANIFEST);
            assert_eq!(id, key.key_id());
            assert!(verify_with(&[key], MANIFEST, &one((id, text))).is_ok());
        }
        for release in RELEASE_KEYS {
            assert!(
                !PINNED_KEYS.contains(&release),
                "{} is pinned",
                release.role
            );
        }
        assert!(super::development::ACTIVE_SECRET.contains("DEVELOPMENT"));
        assert!(super::development::STANDBY_SECRET.contains("DEVELOPMENT"));
    }

    /// The table a shipped binary pins holds byte5's active and standby keys,
    /// neither marked as a development key, under the key ids the owner noted
    /// when the pairs were generated.
    #[test]
    fn the_release_table_holds_the_owners_active_and_standby_keys() {
        assert_eq!(RELEASE_KEYS[0].role, KeyRole::Active);
        assert_eq!(RELEASE_KEYS[0].key_id(), "5DDA49F105939297");
        assert_eq!(RELEASE_KEYS[1].role, KeyRole::Standby);
        assert_eq!(RELEASE_KEYS[1].key_id(), "EA33B324921AC1B3");
        for key in RELEASE_KEYS {
            assert!(!key.development, "{} is a development key", key.role);
            assert!(PublicKey::from_base64(key.public_key).is_ok());
        }
        for development in super::development::KEYS {
            assert!(
                RELEASE_KEYS
                    .iter()
                    .all(|key| key.public_key != development.public_key),
                "the development {} key is in the release table",
                development.role
            );
        }
    }

    /// What a build without the test-only feature pins refuses a manifest
    /// signed with either development key: no release key made the
    /// signature, whatever its file is named.
    #[test]
    fn a_manifest_signed_with_a_development_key_is_refused_by_the_release_table() {
        for role in [KeyRole::Active, KeyRole::Standby] {
            assert_eq!(
                verify_with(&RELEASE_KEYS, MANIFEST, &one(sign(role, MANIFEST))),
                Err(SignatureError::Unsigned)
            );
            let (_, text) = sign(role, MANIFEST);
            let posing = BTreeMap::from([(RELEASE_KEYS[0].key_id(), text)]);
            assert!(matches!(
                verify_with(&RELEASE_KEYS, MANIFEST, &posing),
                Err(SignatureError::Invalid(_))
            ));
        }
    }

    #[test]
    fn base64_reads_what_minisign_writes_and_nothing_else() {
        assert_eq!(base64_decode("aGVsbG8="), Some(b"hello".to_vec()));
        assert_eq!(base64_decode("aGk="), Some(b"hi".to_vec()));
        assert_eq!(base64_decode("aGVs"), Some(b"hel".to_vec()));
        assert_eq!(base64_decode("aGVsbG8"), None);
        assert_eq!(base64_decode("aG=sbG8="), None);
        assert_eq!(base64_decode("a!Vs"), None);
        assert_eq!(key_id_of("not a key"), None);
    }
}
