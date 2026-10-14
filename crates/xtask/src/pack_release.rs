//! A Rule Pack release, from the tag to the feed index (spec section 9.4).
//!
//! The Rule Pack release workflow runs these steps one after another, each as
//! a command of the build tool, so that a local dry run and the tests go
//! through exactly what the workflow goes through:
//!
//! 1. The version gate: the tag `rules-v<N>` names a pack version strictly
//!    greater than both the bundled pack's and the one the feed index holds.
//! 2. The pack build (the `pack` command): `manifest.json` and `pack.tar`.
//! 3. Signing: one detached, prehashed minisign signature over the manifest
//!    per Rule Pack secret key present in the environment, named
//!    `<KEY ID>.minisig`. During a planned rotation two keys are present and
//!    the release carries both signatures (ADR 0006).
//! 4. Verification with the core's own verifier against the keys pinned in
//!    the commit the release was built from, so a pack the shipped client
//!    would refuse is never published.
//! 5. The feed index, `rules/latest.json` on the `feed` branch, holding only
//!    the pack version. The workflow commits it after the release exists.
//!
//! Secret keys are read from the environment and held in memory only. No
//! message of this module carries a secret key or its password.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use agentsweep_core::pack::{MANIFEST_FILE, Manifest, engine_satisfies};
use agentsweep_core::pack_archive::{self, ARCHIVE_FILE};
use agentsweep_core::pack_signature::{self, PinnedKey, SIGNATURE_EXTENSION};
use agentsweep_core::packs::{SignedManifest, compile_tree};

/// What every Rule Pack release tag starts with.
pub const TAG_PREFIX: &str = "rules-v";

/// The feed index's file name, under `rules/` on the `feed` branch.
pub const INDEX_FILE: &str = "latest.json";

/// The environment variables a Rule Pack secret key and its password are read
/// from: the active key, and during a planned rotation the next key. A key
/// whose variable is unset or empty is not present. A password variable that
/// is unset or empty means the key is not encrypted.
pub const KEY_VARIABLES: [(&str, &str); 2] = [
    ("RULE_PACK_SECRET_KEY", "RULE_PACK_SECRET_KEY_PASSWORD"),
    (
        "RULE_PACK_NEXT_SECRET_KEY",
        "RULE_PACK_NEXT_SECRET_KEY_PASSWORD",
    ),
];

/// The pack version a release tag names: `rules-v<N>`, with N written the
/// way the client asks for it, so `rules-v07` is refused rather than
/// published where no client looks.
pub fn tag_version(tag: &str) -> Result<u64, String> {
    let refused = || {
        format!(
            "`{tag}` is not a Rule Pack release tag: it is `{TAG_PREFIX}` followed by the pack version, a whole number without leading zeros"
        )
    };
    let digits = tag.strip_prefix(TAG_PREFIX).ok_or_else(refused)?;
    let version: u64 = digits.parse().map_err(|_| refused())?;
    if version.to_string() != digits {
        return Err(refused());
    }
    Ok(version)
}

/// The version gate. Answers with N when the tag names a pack version
/// strictly greater than the bundled pack's and than the one the feed index
/// holds, and with a sentence saying which it is not otherwise.
///
/// One release is let through at the bundled version itself: the first one,
/// while no feed index exists yet. It publishes the bundled pack as it stands
/// so the first index has a release to point at, and no client sees anything
/// newer than what it carries (the owner's decision 103 of 2026-10-14).
pub fn gate(tag: &str, bundled: u64, index: Option<u64>) -> Result<u64, String> {
    let version = tag_version(tag)?;
    let first_release = index.is_none() && version == bundled;
    if version <= bundled && !first_release {
        return Err(format!(
            "{tag} is refused: Rule Pack {version} is not newer than the bundled Rule Pack, version {bundled}"
        ));
    }
    if let Some(indexed) = index
        && version <= indexed
    {
        return Err(format!(
            "{tag} is refused: Rule Pack {version} is not newer than the pack version {indexed} the feed index holds"
        ));
    }
    Ok(version)
}

/// The pack version a feed index holds.
pub fn read_index(text: &str) -> Result<u64, String> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|error| format!("the feed index is not JSON: {error}"))?;
    value
        .get("pack_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "the feed index holds no whole-number `pack_version`".to_string())
}

/// The feed index pointing at one pack version, and nothing else.
pub fn index_json(pack_version: u64) -> String {
    format!("{{\"pack_version\": {pack_version}}}\n")
}

/// Writes the feed index into a directory as `latest.json`.
pub fn write_index(out: &Path, pack_version: u64) -> Result<PathBuf, String> {
    fs::create_dir_all(out).map_err(|error| format!("{}: {error}", out.display()))?;
    let path = out.join(INDEX_FILE);
    fs::write(&path, index_json(pack_version))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

/// Writes the release of one pack root: the manifest and the archive of both
/// trees, into `out`. Answers with both paths.
pub fn write_release(
    root: &Path,
    manifest: &Manifest,
    out: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    fs::create_dir_all(out).map_err(|error| format!("{}: {error}", out.display()))?;
    let manifest_path = manifest.write(out).map_err(|error| error.to_string())?;
    let archive = pack_archive::write(root, manifest).map_err(|error| error.to_string())?;
    let archive_path = out.join(ARCHIVE_FILE);
    fs::write(&archive_path, archive)
        .map_err(|error| format!("{}: {error}", archive_path.display()))?;
    Ok((manifest_path, archive_path))
}

/// One Rule Pack secret key, decrypted and held in memory.
pub struct SigningKey {
    secret: minisign::SecretKey,
    key_id: String,
}

impl fmt::Debug for SigningKey {
    /// Names the key by its id and never shows the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({})", self.key_id)
    }
}

impl SigningKey {
    /// Reads a minisign secret key: the text of a `.key` file, or its second
    /// line alone, with the password when the key is encrypted. `source`
    /// names where the key came from in a refusal, which never quotes it.
    pub fn read(text: &str, password: Option<&str>, source: &str) -> Result<SigningKey, String> {
        let text = text.trim();
        let boxed = if text.lines().count() == 1 {
            format!("untrusted comment: {source}\n{text}\n")
        } else {
            format!("{text}\n")
        };
        let sk_box = minisign::SecretKeyBox::from_string(&boxed)
            .map_err(|_| format!("{source} is not a minisign secret key"))?;
        let secret = match password {
            Some(password) => {
                minisign::SecretKey::from_box(sk_box, Some(password.to_string())).map_err(|_| {
                    format!("{source} does not open with its password, or is not encrypted")
                })?
            }
            None => minisign::SecretKey::from_unencrypted_box(sk_box).map_err(|_| {
                format!("{source} is not a readable unencrypted key; an encrypted key needs its password")
            })?,
        };
        let key_id = key_id_of_keynum(secret.keynum())
            .ok_or_else(|| format!("{source} carries no key id"))?;
        Ok(SigningKey { secret, key_id })
    }

    /// The key id, as minisign prints it and as the signature file is named.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The public half, base64 as on the second line of a `.pub` file.
    pub fn public_key(&self) -> Result<String, String> {
        minisign::PublicKey::from_secret_key(&self.secret)
            .map(|public| public.to_base64())
            .map_err(|_| format!("the key {} holds no public half", self.key_id))
    }
}

/// Reads every Rule Pack secret key present in an environment, looked up by
/// `lookup`, in the order of [`KEY_VARIABLES`]. At least one must be present.
pub fn keys_from(lookup: impl Fn(&str) -> Option<String>) -> Result<Vec<SigningKey>, String> {
    let present = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
    let mut keys = Vec::new();
    for (key_variable, password_variable) in KEY_VARIABLES {
        let Some(text) = present(key_variable) else {
            continue;
        };
        let password = present(password_variable);
        keys.push(SigningKey::read(&text, password.as_deref(), key_variable)?);
    }
    if keys.is_empty() {
        let names: Vec<&str> = KEY_VARIABLES.iter().map(|(key, _)| *key).collect();
        return Err(format!(
            "no Rule Pack secret key is present: set {}",
            names.join(" or ")
        ));
    }
    Ok(keys)
}

/// Signs the manifest of a release with every key, writing one detached,
/// prehashed signature per key as `<KEY ID>.minisig` beside it. Answers with
/// the key ids in the order signed.
pub fn sign(release: &Path, keys: &[SigningKey]) -> Result<Vec<String>, String> {
    let manifest_path = release.join(MANIFEST_FILE);
    let manifest = fs::read(&manifest_path)
        .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    let pack_version = Manifest::parse(&String::from_utf8_lossy(&manifest))
        .map_err(|error| format!("{}: {error}", manifest_path.display()))?
        .pack_version;
    let mut signed = Vec::new();
    for key in keys {
        if signed.iter().any(|id| id == key.key_id()) {
            return Err(format!("the key {} is present twice", key.key_id()));
        }
        let public = minisign::PublicKey::from_secret_key(&key.secret)
            .map_err(|_| format!("the key {} holds no public half", key.key_id()))?;
        let trusted = format!(
            "timestamp:{}\tfile:{MANIFEST_FILE}\thashed",
            agentsweep_core::envelope::Timestamp::now().as_unix_ms() / 1000
        );
        let untrusted = format!("signature of AgentSweep Rule Pack {pack_version}");
        let signature = minisign::sign(
            Some(&public),
            &key.secret,
            manifest.as_slice(),
            Some(&trusted),
            Some(&untrusted),
        )
        .map_err(|_| format!("the key {} did not sign the manifest", key.key_id()))?;
        let path = release.join(pack_signature::signature_file(key.key_id()));
        fs::write(&path, signature.to_string())
            .map_err(|error| format!("{}: {error}", path.display()))?;
        signed.push(key.key_id().to_string());
    }
    Ok(signed)
}

/// What a signed release verified as.
#[derive(Debug)]
pub struct Verified {
    /// What the release's manifest states.
    pub manifest: Manifest,
    /// The pinned keys whose signature over the manifest verified.
    pub signed_by: Vec<PinnedKey>,
    /// The ids of keys that signed and that this commit does not pin, which
    /// is the old key during a planned rotation.
    pub unpinned: Vec<String>,
}

impl Verified {
    /// The report the verification command prints.
    pub fn report(&self) -> String {
        let mut report = format!(
            "Rule Pack {} for engine {} and up, released {}, {} files\n",
            self.manifest.pack_version,
            self.manifest.minimum_engine_version,
            self.manifest.released_at,
            self.manifest.files.len()
        );
        for key in &self.signed_by {
            let development = if key.development {
                " (a development key)"
            } else {
                ""
            };
            report.push_str(&format!(
                "signed by the pinned {} key {}{development}\n",
                key.role,
                key.key_id()
            ));
        }
        for id in &self.unpinned {
            report.push_str(&format!(
                "also signed by the key {id}, which this commit does not pin\n"
            ));
        }
        report
    }
}

/// Verifies a signed release the way the shipped client verifies a fetched
/// one, against `keys`: the release holds exactly `manifest.json`, one
/// `<KEY ID>.minisig` per signing key and `pack.tar`; every signature file is
/// a prehashed minisign signature by the key it is named after; at least one
/// pinned key signed the manifest and no signature by a pinned key fails;
/// the manifest asks for no newer engine than this one; and the archive
/// unpacks into exactly the files the manifest lists, whose Rules compile.
pub fn verify(release: &Path, keys: &[PinnedKey]) -> Result<Verified, String> {
    let signatures = read_layout(release)?;
    let manifest_bytes = fs::read(release.join(MANIFEST_FILE))
        .map_err(|error| format!("{}: {error}", release.display()))?;

    let mut signed_by = Vec::new();
    let mut problems = Vec::new();
    for key in keys {
        let id = key.key_id();
        let Some(text) = signatures.get(&id) else {
            continue;
        };
        let one = BTreeMap::from([(id.clone(), text.clone())]);
        match pack_signature::verify_with(&[*key], &manifest_bytes, &one) {
            Ok(_) => signed_by.push(*key),
            Err(error) => problems.push(format!("the {} key {id}: {error}", key.role)),
        }
    }
    if !problems.is_empty() {
        return Err(format!(
            "refused: a signature by a pinned key does not verify: {}",
            problems.join("; ")
        ));
    }
    if signed_by.is_empty() {
        let pinned: Vec<String> = keys.iter().map(PinnedKey::key_id).collect();
        return Err(format!(
            "refused: no key this commit pins signed the manifest (pinned: {})",
            pinned.join(", ")
        ));
    }
    let unpinned: Vec<String> = signatures
        .keys()
        .filter(|id| !keys.iter().any(|key| &key.key_id() == *id))
        .cloned()
        .collect();

    let signed = SignedManifest::verify_with(keys, manifest_bytes, signatures)
        .map_err(|error| format!("refused: {error}"))?;
    let engine = agentsweep_core::VERSION;
    if !engine_satisfies(&signed.manifest.minimum_engine_version, engine) {
        return Err(format!(
            "refused: the manifest asks for engine {}, newer than this commit's {engine}",
            signed.manifest.minimum_engine_version
        ));
    }
    let archive = fs::read(release.join(ARCHIVE_FILE))
        .map_err(|error| format!("{}: {error}", release.display()))?;
    let scratch = Scratch::new()?;
    pack_archive::unpack(&archive, &signed.manifest, scratch.path())
        .map_err(|error| format!("refused: the archive: {error}"))?;
    signed
        .manifest
        .check_files(scratch.path())
        .map_err(|error| format!("refused: the archive: {error}"))?;
    compile_tree(scratch.path()).map_err(|error| format!("refused: the Rules: {error}"))?;

    Ok(Verified {
        manifest: signed.manifest,
        signed_by,
        unpinned,
    })
}

/// Holds a release directory to its layout and reads its signature files by
/// key id, each checked to be a prehashed signature by the key it is named
/// after.
fn read_layout(release: &Path) -> Result<BTreeMap<String, String>, String> {
    let entries =
        fs::read_dir(release).map_err(|error| format!("{}: {error}", release.display()))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", release.display()))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();

    let mut signatures = BTreeMap::new();
    let mut stray = Vec::new();
    for name in &names {
        if name == MANIFEST_FILE || name == ARCHIVE_FILE {
            if !release.join(name).is_file() {
                stray.push(name.clone());
            }
            continue;
        }
        let Some(id) = name
            .strip_suffix(SIGNATURE_EXTENSION)
            .and_then(|stem| stem.strip_suffix('.'))
            .filter(|id| is_key_id(id))
        else {
            stray.push(name.clone());
            continue;
        };
        let text =
            fs::read_to_string(release.join(name)).map_err(|error| format!("{name}: {error}"))?;
        let signature = minisign::SignatureBox::from_string(&text)
            .map_err(|_| format!("refused: {name} is not a minisign signature"))?;
        if !signature.is_prehashed() {
            return Err(format!(
                "refused: {name} is a legacy signature, and only prehashed ones are accepted"
            ));
        }
        let made_by = key_id_of_keynum(signature.keynum()).unwrap_or_default();
        if made_by != id {
            return Err(format!(
                "refused: {name} is named after the key {id} and was made by the key {made_by}"
            ));
        }
        signatures.insert(id.to_string(), text);
    }
    for required in [MANIFEST_FILE, ARCHIVE_FILE] {
        if !names.iter().any(|name| name == required) {
            return Err(format!("refused: the release has no {required}"));
        }
    }
    if !stray.is_empty() {
        return Err(format!(
            "refused: a release holds only {MANIFEST_FILE}, <KEY ID>.{SIGNATURE_EXTENSION} and {ARCHIVE_FILE}, and this one also holds {}",
            stray.join(", ")
        ));
    }
    if signatures.is_empty() {
        return Err("refused: the release carries no signature".to_string());
    }
    Ok(signatures)
}

/// Sixteen upper-case hex digits, which is how minisign prints a key id.
fn is_key_id(text: &str) -> bool {
    text.len() == 16
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

/// The key id of an eight-byte key number, as minisign prints it.
fn key_id_of_keynum(keynum: &[u8]) -> Option<String> {
    let bytes: [u8; 8] = keynum.try_into().ok()?;
    Some(format!("{:016X}", u64::from_le_bytes(bytes)))
}

/// A directory under the system's temporary directory that is removed when
/// dropped, for the archive a verification unpacks.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Scratch, String> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "agentsweep-pack-verify-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        Ok(Scratch(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_id_is_sixteen_upper_case_hex_digits() {
        assert!(is_key_id("E413CD5ED19AA1D9"));
        assert!(!is_key_id("e413cd5ed19aa1d9"));
        assert!(!is_key_id("E413CD5ED19AA1D"));
        assert!(!is_key_id("E413CD5ED19AA1DG"));
        assert_eq!(
            key_id_of_keynum(&[1, 0, 0, 0, 0, 0, 0, 0xAB]).as_deref(),
            Some("AB00000000000001")
        );
        assert_eq!(key_id_of_keynum(&[1, 2]), None);
    }

    #[test]
    fn the_feed_index_holds_only_the_pack_version() {
        assert_eq!(index_json(7), "{\"pack_version\": 7}\n");
        let value: serde_json::Value = serde_json::from_str(&index_json(7)).expect("JSON");
        assert_eq!(value.as_object().expect("an object").len(), 1);
        assert_eq!(read_index(&index_json(12)), Ok(12));
        assert!(read_index("{\"pack_version\": \"3\"}").is_err());
        assert!(read_index("not json").is_err());
    }

    #[test]
    fn no_key_in_the_environment_is_refused_and_names_the_variables() {
        let error = keys_from(|_| None).expect_err("refused");
        assert!(error.contains("RULE_PACK_SECRET_KEY"), "{error}");
        let error = keys_from(|_| Some("  ".to_string())).expect_err("refused");
        assert!(error.contains("no Rule Pack secret key"), "{error}");
    }

    #[test]
    fn a_key_that_does_not_read_is_refused_without_quoting_it() {
        let text = "untrusted comment: x\nRWQnotakeyatall\n";
        let error = SigningKey::read(text, None, "RULE_PACK_SECRET_KEY").expect_err("refused");
        assert!(!error.contains("RWQnotakeyatall"), "{error}");
        assert!(error.contains("RULE_PACK_SECRET_KEY"), "{error}");
    }
}
