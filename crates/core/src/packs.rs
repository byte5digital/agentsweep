//! Which Rule Pack is in force: the bundled one, or a newer one the Rule Feed
//! delivered and this binary verified.
//!
//! A fetched pack replaces the bundled one wholesale (spec section 4.2,
//! "Rule Packs"): every Rule, every Indicator List and both Band thresholds
//! come from it, and nothing merges Rule by Rule. It is accepted when three
//! things hold (spec section 9.4, ADR 0006):
//!
//! - its manifest carries a valid signature from a pinned key
//!   ([`crate::pack_signature`]);
//! - its version is strictly greater than the one in use;
//! - its minimum engine version is not newer than this binary.
//!
//! The version compared is always the one in the signed manifest, never the
//! one an unsigned index claims, so a forged index can freeze a client but
//! never downgrade it.
//!
//! An accepted pack lives in the data directory under `rules/`: the two trees,
//! `manifest.json` and the signature files beside it. At every start it is
//! verified again, signature and files, and compiled; a pack that no longer
//! verifies is discarded rather than trusted, and the bundled pack is in force
//! until the Rule Feed delivers another.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::pack::{MANIFEST_FILE, Manifest, ManifestError, engine_satisfies};
use crate::pack_signature::{self, PINNED_KEYS, PinnedKey, SignatureError};
use crate::paths::DataDirectory;
use crate::rules::{PackTrust, RuleError, RulePack, RuleSource};

/// Where the Rule Pack in force came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackOrigin {
    /// The pack embedded in this binary.
    Bundled,
    /// A newer pack from the Rule Feed, verified against a pinned key.
    Fetched,
}

impl PackOrigin {
    /// The spelling the status carries.
    pub fn as_str(self) -> &'static str {
        match self {
            PackOrigin::Bundled => "bundled",
            PackOrigin::Fetched => "fetched",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<PackOrigin> {
        match text {
            "bundled" => Some(PackOrigin::Bundled),
            "fetched" => Some(PackOrigin::Fetched),
            _ => None,
        }
    }
}

impl fmt::Display for PackOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A compiled Rule Pack with what it states about itself.
pub struct LoadedPack {
    /// The compiled Rules and Heuristics. Compiled once and shared by every
    /// Scan that runs while the pack is in force.
    pub rules: Arc<RulePack>,
    /// The manifest: version, minimum engine, Bands, release moment.
    pub manifest: Manifest,
    /// Bundled or fetched.
    pub origin: PackOrigin,
}

impl fmt::Debug for LoadedPack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedPack")
            .field("pack_version", &self.manifest.pack_version)
            .field("origin", &self.origin)
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl LoadedPack {
    /// The pack embedded in this binary.
    pub fn bundled() -> Result<LoadedPack, RuleError> {
        Ok(LoadedPack::bundled_as(Arc::new(RulePack::bundled()?)))
    }

    /// The bundled manifest around rules the caller compiled, which is how a
    /// test stands a pack with one Rule flipped to stable in for the bundled
    /// one: no bundled Rule is ever flipped in place.
    pub fn bundled_as(rules: Arc<RulePack>) -> LoadedPack {
        LoadedPack {
            rules,
            manifest: Manifest::bundled(),
            origin: PackOrigin::Bundled,
        }
    }
}

/// What the acceptance conditions say about a verified manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Newer than the pack in use, and loadable by this binary.
    Accept,
    /// Not newer than the pack in use: a replay, a stale mirror or a forged
    /// index. Nothing changes.
    NotNewer {
        /// The version the pack states.
        offered: u64,
        /// The version in use.
        in_use: u64,
    },
    /// Newer, but it needs a newer AgentSweep. Ignored with a visible notice.
    NeedsNewerEngine {
        /// The version the pack states.
        offered: u64,
        /// The engine it asks for.
        minimum: String,
    },
}

/// Holds a verified manifest to the two conditions that are not the
/// signature: strictly newer than the pack in use, and not asking for a newer
/// engine than this one.
pub fn judge(manifest: &Manifest, in_use: u64, engine: &str) -> Verdict {
    if manifest.pack_version <= in_use {
        return Verdict::NotNewer {
            offered: manifest.pack_version,
            in_use,
        };
    }
    if !engine_satisfies(&manifest.minimum_engine_version, engine) {
        return Verdict::NeedsNewerEngine {
            offered: manifest.pack_version,
            minimum: manifest.minimum_engine_version.clone(),
        };
    }
    Verdict::Accept
}

/// Why a pack was not taken.
#[derive(Debug)]
pub enum PackError {
    /// A file could not be read or written.
    Io(io::Error),
    /// No pinned key's signature verifies over the manifest.
    Signature(SignatureError),
    /// The manifest, or the pack held to it, is not what it should be.
    Manifest(ManifestError),
    /// The archive the pack came in was refused.
    Archive(crate::pack_archive::ArchiveError),
    /// The Rules did not compile.
    Rules(RuleError),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackError::Io(error) => write!(f, "{error}"),
            PackError::Signature(error) => write!(f, "{error}"),
            PackError::Manifest(error) => write!(f, "{error}"),
            PackError::Archive(error) => write!(f, "{error}"),
            PackError::Rules(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PackError {}

impl From<io::Error> for PackError {
    fn from(error: io::Error) -> PackError {
        PackError::Io(error)
    }
}

impl From<SignatureError> for PackError {
    fn from(error: SignatureError) -> PackError {
        PackError::Signature(error)
    }
}

impl From<ManifestError> for PackError {
    fn from(error: ManifestError) -> PackError {
        PackError::Manifest(error)
    }
}

impl From<crate::pack_archive::ArchiveError> for PackError {
    fn from(error: crate::pack_archive::ArchiveError) -> PackError {
        PackError::Archive(error)
    }
}

impl From<RuleError> for PackError {
    fn from(error: RuleError) -> PackError {
        PackError::Rules(error)
    }
}

/// A manifest whose signature verified, with the signatures that vouch for
/// it, before anything else of the pack has been looked at.
#[derive(Clone, Debug)]
pub struct SignedManifest {
    /// The manifest's exact bytes, which is what the signature covers and
    /// what is written beside the trees.
    pub bytes: Vec<u8>,
    /// What it states.
    pub manifest: Manifest,
    /// The texts of the signature files, by key id.
    pub signatures: BTreeMap<String, String>,
    /// The pinned key whose signature verified.
    pub signed_by: PinnedKey,
}

impl SignedManifest {
    /// Verifies a manifest's signatures against the pinned keys, then reads
    /// it. The signature comes first: an unsigned manifest is never parsed.
    pub fn verify(
        bytes: Vec<u8>,
        signatures: BTreeMap<String, String>,
    ) -> Result<SignedManifest, PackError> {
        SignedManifest::verify_with(&PINNED_KEYS, bytes, signatures)
    }

    /// The same against keys of the caller's choosing.
    pub fn verify_with(
        keys: &[PinnedKey],
        bytes: Vec<u8>,
        signatures: BTreeMap<String, String>,
    ) -> Result<SignedManifest, PackError> {
        let signed_by = pack_signature::verify_with(keys, &bytes, &signatures)?;
        let text = String::from_utf8(bytes.clone())
            .map_err(|_| ManifestError::Field("manifest".to_string()))?;
        let manifest = Manifest::parse(&text)?;
        Ok(SignedManifest {
            bytes,
            manifest,
            signatures,
            signed_by,
        })
    }
}

/// The accepted pack in the data directory, and the one place it is written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackStore {
    root: PathBuf,
    incoming: PathBuf,
}

impl PackStore {
    /// The store of one data directory: `rules/`, with `rules.incoming/`
    /// beside it on the same volume for a pack being unpacked, so the swap is
    /// one rename.
    pub fn in_data_directory(directory: &DataDirectory) -> PackStore {
        PackStore {
            root: directory.rules(),
            incoming: directory.root().join("rules.incoming"),
        }
    }

    /// Where the accepted pack lives.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// True when a pack is stored, verified or not.
    pub fn holds_a_pack(&self) -> bool {
        self.root.join(MANIFEST_FILE).exists()
    }

    /// Reads the stored pack back, verifying it as if it had just arrived:
    /// the signature over the manifest, every file against the manifest, and
    /// the Rules compiled. Nothing when no pack is stored.
    pub fn read(&self) -> Result<Option<LoadedPack>, PackError> {
        if !self.holds_a_pack() {
            return Ok(None);
        }
        read_root(&self.root).map(Some)
    }

    /// Takes a pack whose signed manifest has been judged acceptable: the
    /// archive is unpacked against it into the incoming directory, the
    /// manifest and its signatures are written beside the trees, the whole
    /// is read back exactly as a start reads it, and only then does it
    /// replace the stored pack, in one rename. Answers with the compiled
    /// pack.
    pub fn install(
        &self,
        signed: &SignedManifest,
        archive: &[u8],
    ) -> Result<LoadedPack, PackError> {
        let _ = fs::remove_dir_all(&self.incoming);
        let result = self.stage(signed, archive);
        let loaded = match result {
            Ok(loaded) => loaded,
            Err(error) => {
                let _ = fs::remove_dir_all(&self.incoming);
                return Err(error);
            }
        };
        let old = self.root.with_extension("old");
        let _ = fs::remove_dir_all(&old);
        if self.root.exists() {
            fs::rename(&self.root, &old)?;
        }
        if let Err(error) = fs::rename(&self.incoming, &self.root) {
            // Put the previous pack back rather than leave none.
            let _ = fs::rename(&old, &self.root);
            return Err(PackError::Io(error));
        }
        let _ = fs::remove_dir_all(&old);
        Ok(loaded)
    }

    fn stage(&self, signed: &SignedManifest, archive: &[u8]) -> Result<LoadedPack, PackError> {
        crate::pack_archive::unpack(archive, &signed.manifest, &self.incoming)?;
        fs::write(self.incoming.join(MANIFEST_FILE), &signed.bytes)?;
        for (id, text) in &signed.signatures {
            // A key id names a file, so it is held to what a key id is.
            if id.len() == 16 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                fs::write(self.incoming.join(pack_signature::signature_file(id)), text)?;
            }
        }
        read_root(&self.incoming)
    }

    /// Throws the stored pack away, which is what happens to one that no
    /// longer verifies: it is never trusted, and the bundled pack is in force
    /// until the Rule Feed delivers another.
    pub fn discard(&self) -> io::Result<()> {
        match fs::remove_dir_all(&self.root) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

/// Reads one pack root: verifies the signature over its manifest with the
/// signature files beside it, holds its trees to the manifest and compiles
/// its Rules.
fn read_root(root: &Path) -> Result<LoadedPack, PackError> {
    let bytes = fs::read(root.join(MANIFEST_FILE))?;
    let mut signatures = BTreeMap::new();
    for key in PINNED_KEYS {
        let path = root.join(key.signature_file());
        match fs::read_to_string(&path) {
            Ok(text) => {
                signatures.insert(key.key_id(), text);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(PackError::Io(error)),
        }
    }
    let signed = SignedManifest::verify(bytes, signatures)?;
    signed.manifest.check_files(root)?;
    let rules = compile_tree(root)?;
    Ok(LoadedPack {
        rules: Arc::new(rules),
        manifest: signed.manifest,
        origin: PackOrigin::Fetched,
    })
}

/// Compiles the Rules of a pack root: one `rule.yar` per directory under
/// `rules/`, each with the origin the bundled pack gives it, so a Rule's id
/// is held to its directory exactly as in the bundled pack.
pub fn compile_tree(root: &Path) -> Result<RulePack, PackError> {
    let mut directories: Vec<PathBuf> = fs::read_dir(root.join("rules"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, io::Error>>()?;
    directories.sort();
    let mut sources: Vec<(String, String)> = Vec::new();
    for directory in directories {
        let rule = directory.join("rule.yar");
        if !rule.is_file() {
            continue;
        }
        let Some(name) = directory.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        sources.push((format!("{name}/rule.yar"), fs::read_to_string(&rule)?));
    }
    let borrowed: Vec<RuleSource<'_>> = sources
        .iter()
        .map(|(origin, source)| RuleSource { origin, source })
        .collect();
    Ok(RulePack::compile_with(&borrowed, PackTrust::Signed)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pack::Bands;
    use crate::pack_signature::KeyRole;
    use crate::pack_signature::development::{sign, sign_with_an_unpinned_key};

    /// The repository's own `rules/` and `iocs/` trees, which are the bundled
    /// pack's sources.
    fn repository() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// A copy of the repository's pack at a version of the caller's choosing,
    /// signed by one development key, with its archive.
    fn a_release(version: u64, minimum: &str) -> (tempfile::TempDir, SignedManifest, Vec<u8>) {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        for tree in crate::pack::PACK_TREES {
            copy_tree(&repository().join(tree), &temporary.path().join(tree));
        }
        let manifest = Manifest::of_pack(
            temporary.path(),
            version,
            minimum,
            Bands::V1,
            "2026-10-01T09:30:00Z",
        )
        .expect("a manifest");
        let bytes = manifest.to_json().into_bytes();
        let signatures = BTreeMap::from([sign(KeyRole::Active, &bytes)]);
        let archive = crate::pack_archive::write(temporary.path(), &manifest).expect("an archive");
        let signed = SignedManifest::verify(bytes, signatures).expect("it verifies");
        (temporary, signed, archive)
    }

    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).expect("a directory");
        for entry in fs::read_dir(from).expect("a readable tree") {
            let entry = entry.expect("an entry");
            let target = to.join(entry.file_name());
            if entry.file_name() == ".DS_Store" {
                continue;
            }
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), &target).expect("a copy");
            }
        }
    }

    #[test]
    fn a_newer_pack_for_this_engine_is_accepted_and_nothing_else_is() {
        let manifest = |version: u64, minimum: &str| Manifest {
            pack_version: version,
            minimum_engine_version: minimum.to_string(),
            bands: Bands::V1,
            released_at: "2026-10-01T09:30:00Z".to_string(),
            files: BTreeMap::new(),
        };
        assert_eq!(judge(&manifest(2, "0.1.0"), 1, "0.1.0"), Verdict::Accept);
        assert_eq!(
            judge(&manifest(1, "0.1.0"), 1, "0.1.0"),
            Verdict::NotNewer {
                offered: 1,
                in_use: 1
            },
            "strictly greater"
        );
        assert_eq!(
            judge(&manifest(1, "0.1.0"), 3, "0.1.0"),
            Verdict::NotNewer {
                offered: 1,
                in_use: 3
            }
        );
        assert_eq!(
            judge(&manifest(4, "9.0.0"), 3, "0.1.0"),
            Verdict::NeedsNewerEngine {
                offered: 4,
                minimum: "9.0.0".to_string()
            }
        );
    }

    /// A stored pack is verified again at every read, and its Rules replace
    /// the bundled ones wholesale.
    #[test]
    fn an_installed_pack_reads_back_verified_and_compiled() {
        let (_release, signed, archive) = a_release(2, "0.1.0");
        let data = tempfile::tempdir().expect("a data directory");
        let store = PackStore::in_data_directory(&DataDirectory::at(data.path()));
        assert!(store.read().expect("an empty store").is_none());

        let installed = store.install(&signed, &archive).expect("it installs");
        assert_eq!(installed.manifest.pack_version, 2);
        assert_eq!(installed.origin, PackOrigin::Fetched);
        assert_eq!(
            installed.rules.len(),
            RulePack::bundled().expect("bundled").len()
        );

        let read = store.read().expect("it verifies").expect("a stored pack");
        assert_eq!(read.manifest, installed.manifest);
        assert!(!data.path().join("rules.incoming").exists());
    }

    /// A stored pack whose Rule was edited after it was installed no longer
    /// verifies, and neither does one whose signature was swapped.
    #[test]
    fn a_stored_pack_that_was_tampered_with_does_not_read_back() {
        let (_release, signed, archive) = a_release(2, "0.1.0");
        let data = tempfile::tempdir().expect("a data directory");
        let store = PackStore::in_data_directory(&DataDirectory::at(data.path()));
        store.install(&signed, &archive).expect("it installs");

        let rule = store.root().join("rules/0001-decode-pipe-exec/rule.yar");
        let text = fs::read_to_string(&rule).expect("a rule");
        fs::write(&rule, text.replace("probation", "stable")).expect("an edit");
        assert!(matches!(
            store.read(),
            Err(PackError::Manifest(ManifestError::Mismatch(_)))
        ));
        store.discard().expect("discarded");
        assert!(store.read().expect("an empty store").is_none());

        store.install(&signed, &archive).expect("it installs again");
        let active = store.root().join(signed.signed_by.signature_file());
        let (_, forged) = sign_with_an_unpinned_key(&signed.bytes);
        fs::write(&active, forged).expect("a swapped signature");
        assert!(matches!(store.read(), Err(PackError::Signature(_))));
    }

    #[test]
    fn a_manifest_no_pinned_key_signed_is_never_read() {
        let (_release, signed, _) = a_release(2, "0.1.0");
        let unsigned = SignedManifest::verify(
            signed.bytes.clone(),
            BTreeMap::from([sign_with_an_unpinned_key(&signed.bytes)]),
        );
        assert!(matches!(unsigned, Err(PackError::Signature(_))));
    }

    /// An archive that does not match the signed manifest leaves the stored
    /// pack exactly as it was.
    #[test]
    fn a_refused_archive_changes_nothing() {
        let (_one, first, first_archive) = a_release(2, "0.1.0");
        let (_two, second, _) = a_release(3, "0.1.0");
        let data = tempfile::tempdir().expect("a data directory");
        let store = PackStore::in_data_directory(&DataDirectory::at(data.path()));
        store.install(&first, &first_archive).expect("it installs");

        let mut lying = second.clone();
        lying
            .manifest
            .files
            .insert("iocs/hosts.txt".to_string(), "0".repeat(64));
        assert!(store.install(&lying, &first_archive).is_err());
        let read = store.read().expect("it verifies").expect("a stored pack");
        assert_eq!(read.manifest.pack_version, 2);
        assert!(!data.path().join("rules.incoming").exists());
    }
}
