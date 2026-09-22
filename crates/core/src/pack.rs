//! The Rule Pack manifest.
//!
//! A Rule Pack is the `rules/` and `iocs/` trees plus `manifest.json` and a
//! detached signature (spec section 4.2, "Rule Packs"). The manifest carries
//! the pack version, the minimum engine version, the sha256 of every file in
//! the pack and the two Band thresholds, so a pack release can retune the
//! Bands without an app release.
//!
//! The signature is the distribution ticket's work and nothing here reads or
//! writes one; the same goes for the signed release timestamp. What this
//! module fixes is the shape both the pack build and the Rule Feed client
//! agree on.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::item::sha256_hex;

/// The two trees a Rule Pack is made of, relative to the pack root.
pub const PACK_TREES: [&str; 2] = ["iocs", "rules"];

/// The name the manifest carries inside the pack.
pub const MANIFEST_FILE: &str = "manifest.json";

/// The one file name a pack never carries: macOS writes it into any directory
/// the Finder has looked at, and it is not pack content.
const NEVER_PACKED: &str = ".DS_Store";

/// The Score thresholds that place an Item in a Band. Below `ambiguous_at` an
/// Item is Clear, from `ambiguous_at` to one below `suspicious_at` it is
/// Ambiguous, and from `suspicious_at` up it is Suspicious.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bands {
    /// Where the Ambiguous Band starts.
    pub ambiguous_at: i64,
    /// Where the Suspicious Band starts.
    pub suspicious_at: i64,
}

impl Bands {
    /// The v1 thresholds, as `rules/README.md` fixes them.
    pub const V1: Bands = Bands {
        ambiguous_at: 2,
        suspicious_at: 4,
    };
}

impl Default for Bands {
    fn default() -> Bands {
        Bands::V1
    }
}

/// What went wrong while reading a manifest.
#[derive(Debug)]
pub enum ManifestError {
    /// The pack could not be read.
    Io(io::Error),
    /// The manifest is not JSON.
    Json(serde_json::Error),
    /// The manifest is JSON but not a manifest.
    Field(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::Io(error) => write!(f, "the pack could not be read: {error}"),
            ManifestError::Json(error) => write!(f, "the manifest is not JSON: {error}"),
            ManifestError::Field(field) => write!(f, "the manifest has no usable `{field}`"),
        }
    }
}

impl Error for ManifestError {}

impl From<io::Error> for ManifestError {
    fn from(error: io::Error) -> ManifestError {
        ManifestError::Io(error)
    }
}

impl From<serde_json::Error> for ManifestError {
    fn from(error: serde_json::Error) -> ManifestError {
        ManifestError::Json(error)
    }
}

/// What a Rule Pack states about itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    /// The pack version, a monotonic integer. A fetched pack replaces the
    /// bundled one only when this is higher.
    pub pack_version: u64,
    /// The lowest AgentSweep version that may load the pack. A client below it
    /// ignores the pack with a visible notice.
    pub minimum_engine_version: String,
    /// The Band thresholds of this pack.
    pub bands: Bands,
    /// The sha256 of every file of the pack, by path relative to the pack
    /// root, lower-case hex.
    pub files: BTreeMap<String, String>,
}

impl Manifest {
    /// Reads a pack root and states what is in it. The manifest itself and any
    /// detached signature beside it are not pack content and are left out.
    pub fn of_pack(
        root: &Path,
        pack_version: u64,
        minimum_engine_version: &str,
        bands: Bands,
    ) -> Result<Manifest, ManifestError> {
        let mut files = BTreeMap::new();
        for tree in PACK_TREES {
            let dir = root.join(tree);
            if !dir.is_dir() {
                return Err(ManifestError::Field(tree.to_string()));
            }
            hash_tree(&dir, tree, &mut files)?;
        }
        Ok(Manifest {
            pack_version,
            minimum_engine_version: minimum_engine_version.to_string(),
            bands,
            files,
        })
    }

    /// The manifest as the bytes that go into the pack, newline terminated so
    /// a committed manifest diffs line by line.
    pub fn to_json(&self) -> String {
        let files: Value = Value::Object(
            self.files
                .iter()
                .map(|(path, hash)| (path.clone(), Value::String(hash.clone())))
                .collect(),
        );
        let manifest = json!({
            "pack_version": self.pack_version,
            "minimum_engine_version": self.minimum_engine_version,
            "heuristics": {
                "ambiguous_at": self.bands.ambiguous_at,
                "suspicious_at": self.bands.suspicious_at,
            },
            "files": files,
        });
        let mut text = serde_json::to_string_pretty(&manifest).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Reads a manifest back.
    pub fn parse(json: &str) -> Result<Manifest, ManifestError> {
        let value: Value = serde_json::from_str(json)?;
        let field = |name: &str| ManifestError::Field(name.to_string());

        let pack_version = value
            .get("pack_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| field("pack_version"))?;
        let minimum_engine_version = value
            .get("minimum_engine_version")
            .and_then(Value::as_str)
            .ok_or_else(|| field("minimum_engine_version"))?
            .to_string();
        let heuristics = value.get("heuristics").ok_or_else(|| field("heuristics"))?;
        let bands = Bands {
            ambiguous_at: heuristics
                .get("ambiguous_at")
                .and_then(Value::as_i64)
                .ok_or_else(|| field("heuristics.ambiguous_at"))?,
            suspicious_at: heuristics
                .get("suspicious_at")
                .and_then(Value::as_i64)
                .ok_or_else(|| field("heuristics.suspicious_at"))?,
        };

        let mut files = BTreeMap::new();
        let listed = value
            .get("files")
            .and_then(Value::as_object)
            .ok_or_else(|| field("files"))?;
        for (path, hash) in listed {
            let hash = hash.as_str().ok_or_else(|| field("files"))?;
            files.insert(path.clone(), hash.to_string());
        }

        Ok(Manifest {
            pack_version,
            minimum_engine_version,
            bands,
            files,
        })
    }

    /// Writes the manifest into a pack root and returns where it landed.
    pub fn write(&self, root: &Path) -> Result<PathBuf, ManifestError> {
        let path = root.join(MANIFEST_FILE);
        fs::write(&path, self.to_json())?;
        Ok(path)
    }
}

/// Hashes every regular file of one tree, keyed by its path relative to the
/// pack root with forward slashes, whatever the platform.
fn hash_tree(
    dir: &Path,
    prefix: &str,
    files: &mut BTreeMap<String, String>,
) -> Result<(), ManifestError> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, io::Error>>()?;
    entries.sort();

    for entry in entries {
        let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name == NEVER_PACKED {
            continue;
        }
        let relative = format!("{prefix}/{name}");
        if entry.is_dir() {
            hash_tree(&entry, &relative, files)?;
        } else {
            files.insert(relative, sha256_hex(&fs::read(&entry)?));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_manifest() -> Manifest {
        Manifest {
            pack_version: 7,
            minimum_engine_version: "0.1.0".to_string(),
            bands: Bands::V1,
            files: BTreeMap::from([
                ("iocs/hosts.txt".to_string(), sha256_hex(b"a host\n")),
                ("rules/0001-x/rule.yar".to_string(), sha256_hex(b"a rule\n")),
            ]),
        }
    }

    #[test]
    fn the_v1_bands_are_two_and_four() {
        assert_eq!(Bands::default(), Bands::V1);
        assert_eq!(Bands::V1.ambiguous_at, 2);
        assert_eq!(Bands::V1.suspicious_at, 4);
    }

    #[test]
    fn a_manifest_round_trips_through_its_json() {
        let manifest = a_manifest();
        assert_eq!(
            Manifest::parse(&manifest.to_json()).expect("the manifest reads back"),
            manifest
        );
    }

    #[test]
    fn the_json_names_the_band_thresholds_under_heuristics() {
        let json: Value = serde_json::from_str(&a_manifest().to_json()).expect("JSON");
        assert_eq!(json["heuristics"]["ambiguous_at"], json!(2));
        assert_eq!(json["heuristics"]["suspicious_at"], json!(4));
        assert_eq!(json["pack_version"], json!(7));
        assert_eq!(json["minimum_engine_version"], json!("0.1.0"));
        assert!(json["files"]["iocs/hosts.txt"].is_string());
    }

    #[test]
    fn a_manifest_without_its_thresholds_is_refused() {
        let error = Manifest::parse(r#"{"pack_version":1,"minimum_engine_version":"0.1.0"}"#)
            .expect_err("a manifest states its Bands");
        assert!(error.to_string().contains("heuristics"), "{error}");
    }
}
