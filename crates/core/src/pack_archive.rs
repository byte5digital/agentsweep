//! The archive a Rule Pack travels in from the Rule Feed.
//!
//! A release of a pack is three kinds of asset side by side (spec section
//! 9.4): `manifest.json`, one detached signature over it per key that signed
//! it, and `pack.tar`, a plain tar of the `rules/` and `iocs/` trees. The
//! signature covers the manifest, and the manifest names the sha256 of every
//! file of the trees, so the archive needs no signature of its own: it is
//! unpacked only against a manifest that has already verified, and every entry
//! is held to it.
//!
//! Unpacking is deliberately narrow. An entry is a regular file or a
//! directory, at a path the manifest lists, inside one of the two trees, read
//! into memory, hashed, and only then written. A link, a device, a path that
//! climbs out, a file the manifest does not list, a file listed twice and a
//! file whose bytes are not the ones the manifest states each refuse the whole
//! archive. The tar crate never writes a byte itself.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use crate::item::sha256_hex;
use crate::pack::{Manifest, is_pack_path};

/// The name of the archive asset of a pack release.
pub const ARCHIVE_FILE: &str = "pack.tar";

/// The largest single file a pack may carry. The biggest file of the v1 pack
/// is a few kilobytes; this is room for growth, not a target.
pub const LARGEST_FILE: u64 = 4 * 1024 * 1024;

/// The largest pack, all files together.
pub const LARGEST_PACK: u64 = 64 * 1024 * 1024;

/// Why an archive was refused.
#[derive(Debug)]
pub enum ArchiveError {
    /// The archive could not be read or a file could not be written.
    Io(io::Error),
    /// An entry the archive may not carry.
    Refused {
        /// The entry's path as the archive names it.
        path: String,
        /// What is wrong with it.
        why: &'static str,
    },
    /// A file the manifest lists is not in the archive.
    Missing(String),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveError::Io(error) => write!(f, "the archive could not be read: {error}"),
            ArchiveError::Refused { path, why } => write!(f, "{path}: {why}"),
            ArchiveError::Missing(path) => {
                write!(f, "{path} is listed in the manifest and not in the archive")
            }
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> ArchiveError {
        ArchiveError::Io(error)
    }
}

/// Writes the archive of one pack root: every file the manifest lists, in the
/// manifest's order, with a fixed mode, owner and time, so the same pack
/// always makes the same bytes.
pub fn write(root: &Path, manifest: &Manifest) -> Result<Vec<u8>, ArchiveError> {
    let mut builder = tar::Builder::new(Vec::new());
    for path in manifest.files.keys() {
        let bytes = fs::read(root.join(path))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, path, bytes.as_slice())?;
    }
    Ok(builder.into_inner()?)
}

/// Unpacks an archive into `into`, holding every entry to a manifest that has
/// already verified. `into` is created and is expected to be empty; on any
/// refusal the caller throws it away, since part of the archive may be in it.
pub fn unpack(archive: &[u8], manifest: &Manifest, into: &Path) -> Result<(), ArchiveError> {
    fs::create_dir_all(into)?;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut total = 0u64;
    let mut reader = tar::Archive::new(archive);
    for entry in reader.entries()? {
        let mut entry = entry?;
        let path = String::from_utf8(entry.path_bytes().into_owned()).map_err(|_| {
            ArchiveError::Refused {
                path: "?".to_string(),
                why: "the path is not UTF-8",
            }
        })?;
        let refuse = |why: &'static str| ArchiveError::Refused {
            path: path.clone(),
            why,
        };
        let entry_type = entry.header().entry_type();
        let trimmed = path.trim_end_matches('/');
        if entry_type.is_dir() {
            if !is_pack_path(&format!("{trimmed}/x")) {
                return Err(refuse("a directory outside the two trees"));
            }
            continue;
        }
        if !entry_type.is_file() {
            return Err(refuse("not a regular file"));
        }
        if !is_pack_path(&path) {
            return Err(refuse("a path outside the two trees"));
        }
        let Some(expected) = manifest.files.get(&path) else {
            return Err(refuse("not listed in the manifest"));
        };
        if !seen.insert(path.clone()) {
            return Err(refuse("in the archive twice"));
        }
        let size = entry.header().size()?;
        total = total.saturating_add(size);
        if size > LARGEST_FILE || total > LARGEST_PACK {
            return Err(refuse("larger than a pack may be"));
        }
        let mut bytes = Vec::with_capacity(size as usize);
        (&mut entry)
            .take(LARGEST_FILE + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != size {
            return Err(refuse("shorter or longer than its header says"));
        }
        if &sha256_hex(&bytes) != expected {
            return Err(refuse("not the file the manifest states"));
        }
        let target = into.join(&path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &bytes)?;
    }
    if let Some(missing) = manifest.files.keys().find(|path| !seen.contains(*path)) {
        return Err(ArchiveError::Missing(missing.clone()));
    }
    // Both trees exist even when one of them is empty, because a pack root
    // is held to having them.
    for tree in crate::pack::PACK_TREES {
        fs::create_dir_all(into.join(tree))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use crate::pack::Bands;

    /// A small pack root with one rule and one list, and its manifest.
    fn a_pack() -> (tempfile::TempDir, Manifest) {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let root = temporary.path();
        fs::create_dir_all(root.join("iocs")).expect("iocs");
        fs::create_dir_all(root.join("rules/0001-x/good/one")).expect("rules");
        fs::write(root.join("iocs/hosts.txt"), "x.example.invalid\n").expect("a list");
        fs::write(
            root.join("rules/0001-x/rule.yar"),
            "rule a { condition: false }\n",
        )
        .expect("a rule");
        fs::write(
            root.join("rules/0001-x/good/one/content"),
            "a long enough name that the path passes one hundred bytes in a tar header, \
             which is where the GNU long name entry comes in\n",
        )
        .expect("a fixture");
        let manifest = Manifest::of_pack(root, 2, "0.1.0", Bands::V1, "2026-09-25T08:00:00Z")
            .expect("a manifest");
        (temporary, manifest)
    }

    #[test]
    fn an_archive_unpacks_into_what_the_manifest_states() {
        let (pack, manifest) = a_pack();
        let archive = write(pack.path(), &manifest).expect("an archive");
        let out = tempfile::tempdir().expect("a temporary directory");
        unpack(&archive, &manifest, out.path()).expect("it unpacks");
        manifest
            .check_files(out.path())
            .expect("the unpacked root is the pack");
    }

    #[test]
    fn the_same_pack_makes_the_same_archive() {
        let (pack, manifest) = a_pack();
        assert_eq!(
            write(pack.path(), &manifest).expect("an archive"),
            write(pack.path(), &manifest).expect("an archive")
        );
    }

    /// An archive that holds a file the signed manifest does not state, byte
    /// for byte, is refused whole.
    #[test]
    fn a_file_that_is_not_what_the_manifest_states_is_refused() {
        let (pack, manifest) = a_pack();
        fs::write(pack.path().join("iocs/hosts.txt"), "evil.example.invalid\n").expect("a swap");
        let mut stated = manifest.clone();
        stated.files.insert(
            "iocs/hosts.txt".to_string(),
            sha256_hex(b"x.example.invalid\n"),
        );
        let archive = write(pack.path(), &stated).expect("an archive");
        let out = tempfile::tempdir().expect("a temporary directory");
        let error = unpack(&archive, &stated, out.path()).expect_err("refused");
        assert!(error.to_string().contains("not the file"), "{error}");
    }

    #[test]
    fn a_file_the_manifest_does_not_list_is_refused() {
        let (pack, manifest) = a_pack();
        let archive = write(pack.path(), &manifest).expect("an archive");
        let mut fewer = manifest.clone();
        fewer.files.remove("iocs/hosts.txt");
        let out = tempfile::tempdir().expect("a temporary directory");
        let error = unpack(&archive, &fewer, out.path()).expect_err("refused");
        assert!(error.to_string().contains("not listed"), "{error}");
    }

    #[test]
    fn a_listed_file_the_archive_lacks_is_refused() {
        let (pack, manifest) = a_pack();
        let mut fewer = manifest.clone();
        fewer.files.remove("iocs/hosts.txt");
        let archive = write(pack.path(), &fewer).expect("an archive");
        let out = tempfile::tempdir().expect("a temporary directory");
        assert!(matches!(
            unpack(&archive, &manifest, out.path()),
            Err(ArchiveError::Missing(path)) if path == "iocs/hosts.txt"
        ));
    }

    /// A link is refused whatever it points at, and so is a path that climbs
    /// out of the pack, before anything is written.
    #[test]
    fn links_and_climbing_paths_are_refused() {
        let manifest = Manifest {
            pack_version: 2,
            minimum_engine_version: "0.1.0".to_string(),
            bands: Bands::V1,
            released_at: "2026-09-25T08:00:00Z".to_string(),
            files: BTreeMap::new(),
        };

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        builder
            .append_link(&mut header, "rules/escape", "/etc")
            .expect("a link entry");
        let linked = builder.into_inner().expect("an archive");
        let out = tempfile::tempdir().expect("a temporary directory");
        let error = unpack(&linked, &manifest, out.path()).expect_err("refused");
        assert!(error.to_string().contains("not a regular file"), "{error}");

        // The tar crate refuses to write `..` itself, so the header is made by
        // hand, as an attacker would.
        let mut header = tar::Header::new_old();
        header.as_old_mut().name[..16].copy_from_slice(b"rules/../../evil");
        header.set_size(1);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        let mut climbing = header.as_bytes().to_vec();
        climbing.extend_from_slice(b"x");
        climbing.resize(climbing.len() + 511, 0);
        climbing.resize(climbing.len() + 1024, 0);
        let error = unpack(&climbing, &manifest, out.path()).expect_err("refused");
        assert!(
            error.to_string().contains("outside the two trees"),
            "{error}"
        );
        assert!(!out.path().join("../evil").exists());
    }
}
