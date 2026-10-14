//! The Rule Pack manifest.
//!
//! A Rule Pack is the `rules/` and `iocs/` trees plus `manifest.json` and a
//! detached signature (spec section 4.2, "Rule Packs"). The manifest carries
//! the pack version, the minimum engine version, the sha256 of every file in
//! the pack, the two Band thresholds, so a pack release can retune the Bands
//! without an app release, and the moment the pack was released. The
//! signature is over the manifest's bytes, so everything it states is signed:
//! the version a client compares, and the date "Rules updated" shows.
//!
//! What this module fixes is the shape both the pack build and the Rule Feed
//! client agree on. The signature itself is [`crate::pack_signature`]'s, the
//! archive a pack travels in is [`crate::pack_archive`]'s, and deciding which
//! pack is in force is [`crate::packs`]'.

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

/// The name of the pack's own statement at the pack root.
pub const STATEMENT_FILE: &str = "pack.json";

/// What the bundled Rule Pack states about itself: its version, the lowest
/// engine version that may load it and the two Band thresholds. It is a
/// manifest with an empty `files` map, because the bundled pack travels inside
/// the binary and the code signature is what stands behind its bytes; the pack
/// build fills the map in for a pack that leaves the machine.
///
/// Embedding it here is what puts the thresholds in the binary. Nothing in the
/// core reads a threshold from code: the Heuristic tier takes its [`Bands`]
/// from a [`Manifest`], and a fetched pack brings its own.
///
/// It is read through the `pack.json` link beside the crate's manifest, which
/// points at the repository's statement and is a copy of it inside the
/// packaged crate.
pub const BUNDLED_STATEMENT: &str = include_str!("../pack.json");

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
    /// A file the manifest lists is not in the pack.
    Missing(String),
    /// A file of the pack is not what the manifest says it is.
    Mismatch(String),
    /// The pack holds a file the manifest does not list, or something that is
    /// not a plain file.
    Unlisted(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::Io(error) => write!(f, "the pack could not be read: {error}"),
            ManifestError::Json(error) => write!(f, "the manifest is not JSON: {error}"),
            ManifestError::Field(field) => write!(f, "the manifest has no usable `{field}`"),
            ManifestError::Missing(path) => write!(f, "{path} is listed and not in the pack"),
            ManifestError::Mismatch(path) => {
                write!(f, "{path} does not have the hash the manifest states")
            }
            ManifestError::Unlisted(path) => write!(f, "{path} is in the pack and not listed"),
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
    /// When the pack was released, in RFC 3339. It is inside the signed
    /// manifest, so the "Rules updated <date>" line a client shows is as
    /// trustworthy as the Rules themselves.
    pub released_at: String,
    /// The sha256 of every file of the pack, by path relative to the pack
    /// root, lower-case hex.
    pub files: BTreeMap<String, String>,
}

impl Manifest {
    /// The manifest of the Rule Pack bundled in this binary, read back from
    /// [`BUNDLED_STATEMENT`]. This is where the running process gets its Band
    /// thresholds from until a newer pack arrives from the Rule Feed.
    ///
    /// Panics when the embedded statement is not a manifest, which a test in
    /// this module catches long before a binary is built.
    pub fn bundled() -> Manifest {
        Manifest::parse(BUNDLED_STATEMENT)
            .expect("the bundled pack statement is a manifest; see pack.json")
    }

    /// Reads a pack root and states what is in it. The manifest itself and any
    /// detached signature beside it are not pack content and are left out.
    pub fn of_pack(
        root: &Path,
        pack_version: u64,
        minimum_engine_version: &str,
        bands: Bands,
        released_at: &str,
    ) -> Result<Manifest, ManifestError> {
        if released_day(released_at).is_none() {
            return Err(ManifestError::Field("released_at".to_string()));
        }
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
            released_at: released_at.to_string(),
            files,
        })
    }

    /// The civil date the pack was released on, `YYYY-MM-DD`, which is what
    /// "Rules updated <date>" shows.
    pub fn released_on(&self) -> String {
        released_day(&self.released_at).unwrap_or_default()
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
            "released_at": self.released_at,
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
    ///
    /// A manifest from the Rule Feed is read only after its signature has
    /// verified, and it is still held to its shape here: every listed path is
    /// a plain relative path inside one of the two trees, and every hash is a
    /// sha256. A path that climbs out of the pack is refused before anything
    /// is written anywhere.
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
            .filter(|version| engine_version(version).is_some())
            .ok_or_else(|| field("minimum_engine_version"))?
            .to_string();
        let released_at = value
            .get("released_at")
            .and_then(Value::as_str)
            .filter(|released| released_day(released).is_some())
            .ok_or_else(|| field("released_at"))?
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
            let hash = hash
                .as_str()
                .filter(|hash| is_sha256_hex(hash))
                .ok_or_else(|| field("files"))?;
            if !is_pack_path(path) {
                return Err(ManifestError::Field(format!("files.{path}")));
            }
            files.insert(path.clone(), hash.to_string());
        }

        Ok(Manifest {
            pack_version,
            minimum_engine_version,
            bands,
            released_at,
            files,
        })
    }

    /// Writes the manifest into a pack root and returns where it landed.
    pub fn write(&self, root: &Path) -> Result<PathBuf, ManifestError> {
        let path = root.join(MANIFEST_FILE);
        fs::write(&path, self.to_json())?;
        Ok(path)
    }

    /// Holds a pack root to this manifest: every file it lists is there with
    /// the hash it states, and nothing else is in either tree. A symbolic link
    /// anywhere in the trees is refused rather than followed.
    ///
    /// This is what binds the Rules a client compiles to the signature over
    /// the manifest: a file that was swapped, added or taken away after the
    /// pack was signed fails here.
    pub fn check_files(&self, root: &Path) -> Result<(), ManifestError> {
        let mut found = BTreeMap::new();
        for tree in PACK_TREES {
            let dir = root.join(tree);
            let metadata =
                fs::symlink_metadata(&dir).map_err(|_| ManifestError::Field(tree.to_string()))?;
            if !metadata.is_dir() {
                return Err(ManifestError::Field(tree.to_string()));
            }
            hash_plain_tree(&dir, tree, &mut found)?;
        }
        for (path, hash) in &self.files {
            match found.remove(path) {
                Some(actual) if &actual == hash => {}
                Some(_) => return Err(ManifestError::Mismatch(path.clone())),
                None => return Err(ManifestError::Missing(path.clone())),
            }
        }
        if let Some(extra) = found.into_keys().next() {
            return Err(ManifestError::Unlisted(extra));
        }
        Ok(())
    }
}

/// True when `path` is one a pack may list: forward slashes, inside one of
/// [`PACK_TREES`], and nothing but plain names between them. No `..`, no `.`,
/// no empty segment, no absolute path and no backslash.
pub fn is_pack_path(path: &str) -> bool {
    let mut segments = path.split('/');
    let Some(tree) = segments.next() else {
        return false;
    };
    if !PACK_TREES.contains(&tree) || path.contains('\\') || path.contains('\0') {
        return false;
    }
    let rest: Vec<&str> = segments.collect();
    !rest.is_empty()
        && rest
            .iter()
            .all(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
}

/// True for 64 lower-case hex digits.
fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The civil date of an RFC 3339 date-time, `YYYY-MM-DD`, or nothing when the
/// text is not one. Accepts `Z` or a numeric offset and optional fractions of
/// a second, which is what `date -u +%Y-%m-%dT%H:%M:%SZ` and every RFC 3339
/// writer produce.
pub fn released_day(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !matches!(bytes[10], b'T' | b't') || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let digits = |from: usize, to: usize| -> Option<u32> {
        let part = text.get(from..to)?;
        part.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    let month = digits(5, 7)?;
    let day = digits(8, 10)?;
    digits(0, 4)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if digits(11, 13)? > 23 || digits(14, 16)? > 59 || digits(17, 19)? > 60 {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let length = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if length == 0 {
            return None;
        }
        rest = &fraction[length..];
    }
    let zone_ok = match rest {
        "Z" | "z" => true,
        offset => {
            let offset = offset.as_bytes();
            offset.len() == 6
                && matches!(offset[0], b'+' | b'-')
                && offset[3] == b':'
                && [1, 2, 4, 5].iter().all(|at| offset[*at].is_ascii_digit())
        }
    };
    zone_ok.then(|| text[..10].to_string())
}

/// An engine version as numbers: `0.1.0` is `[0, 1, 0]`. A pre-release or
/// build suffix after `-` or `+` is dropped, so `0.2.0-beta.1` reads as
/// `0.2.0`. Nothing when the text has a part that is not a number.
fn engine_version(text: &str) -> Option<Vec<u64>> {
    let core = text.split(['-', '+']).next()?;
    if core.is_empty() {
        return None;
    }
    core.split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect()
}

/// True when an engine of version `engine` may load a pack that asks for at
/// least `minimum`. Missing parts count as zero, so `0.2` asks for `0.2.0`.
///
/// A minimum this build cannot read is never satisfied: a pack whose
/// requirement cannot be understood is one this client must not load.
pub fn engine_satisfies(minimum: &str, engine: &str) -> bool {
    let (Some(minimum), Some(engine)) = (engine_version(minimum), engine_version(engine)) else {
        return false;
    };
    let length = minimum.len().max(engine.len());
    let at = |parts: &[u64], index: usize| parts.get(index).copied().unwrap_or(0);
    for index in 0..length {
        let (asked, have) = (at(&minimum, index), at(&engine, index));
        if have != asked {
            return have > asked;
        }
    }
    true
}

/// Hashes every file of one tree as [`hash_tree`] does, refusing a symbolic
/// link or anything else that is neither a directory nor a regular file,
/// which a pack root held to its manifest may not carry.
fn hash_plain_tree(
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
            return Err(ManifestError::Unlisted(format!("{prefix}/?")));
        };
        let relative = format!("{prefix}/{name}");
        let metadata = fs::symlink_metadata(&entry)?;
        if metadata.is_dir() {
            hash_plain_tree(&entry, &relative, files)?;
        } else if metadata.is_file() {
            files.insert(relative, sha256_hex(&fs::read(&entry)?));
        } else {
            return Err(ManifestError::Unlisted(relative));
        }
    }
    Ok(())
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
            released_at: "2026-09-25T08:00:00Z".to_string(),
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
    fn the_bundled_statement_is_a_manifest_and_carries_the_v1_bands() {
        let bundled = Manifest::bundled();
        assert_eq!(bundled.bands, Bands::V1);
        assert_eq!(bundled.pack_version, 1);
        assert!(!bundled.minimum_engine_version.is_empty());
        assert!(
            engine_satisfies(&bundled.minimum_engine_version, crate::VERSION),
            "the bundled pack loads in the binary it is bundled with"
        );
        assert_eq!(bundled.released_on().len(), 10, "{}", bundled.released_at);
        assert!(
            bundled.files.is_empty(),
            "the bundled pack travels inside the binary, so it lists no hashes"
        );
    }

    /// The thresholds reach the running process through the manifest, never
    /// through a number in the code. A pack that says something else says it
    /// here, and the Heuristic tier follows.
    #[test]
    fn a_manifest_may_state_thresholds_other_than_the_v1_pair() {
        let retuned = Manifest::parse(
            r#"{"pack_version":9,"minimum_engine_version":"0.1.0",
                "released_at":"2026-09-25T08:00:00Z",
                "heuristics":{"ambiguous_at":3,"suspicious_at":6},"files":{}}"#,
        )
        .expect("a retuned manifest reads back");
        assert_eq!(
            retuned.bands,
            Bands {
                ambiguous_at: 3,
                suspicious_at: 6
            }
        );
        assert_ne!(retuned.bands, Bands::V1);
    }

    #[test]
    fn a_manifest_without_its_thresholds_is_refused() {
        let error = Manifest::parse(
            r#"{"pack_version":1,"minimum_engine_version":"0.1.0",
                "released_at":"2026-09-25T08:00:00Z"}"#,
        )
        .expect_err("a manifest states its Bands");
        assert!(error.to_string().contains("heuristics"), "{error}");
    }

    /// The date "Rules updated <date>" shows is read off the signed manifest,
    /// and a manifest without one is not a manifest.
    #[test]
    fn the_release_moment_is_part_of_the_manifest_and_reads_as_a_date() {
        let json: Value = serde_json::from_str(&a_manifest().to_json()).expect("JSON");
        assert_eq!(json["released_at"], json!("2026-09-25T08:00:00Z"));
        assert_eq!(a_manifest().released_on(), "2026-09-25");

        let undated = a_manifest()
            .to_json()
            .replace("\"released_at\": \"2026-09-25T08:00:00Z\",", "");
        let error = Manifest::parse(&undated).expect_err("a manifest states its release");
        assert!(error.to_string().contains("released_at"), "{error}");
    }

    #[test]
    fn a_release_moment_is_rfc_3339_or_nothing() {
        for good in [
            "2026-09-25T08:00:00Z",
            "2026-09-25T08:00:00.123Z",
            "2026-09-25T08:00:00+02:00",
            "2026-09-25t08:00:00z",
        ] {
            assert_eq!(released_day(good).as_deref(), Some("2026-09-25"), "{good}");
        }
        for bad in [
            "",
            "2026-09-25",
            "2026-13-25T08:00:00Z",
            "2026-09-25T08:00:00",
            "2026-09-25 08:00:00Z",
            "2026-09-25T08:00:00.Z",
            "yesterday at noon, give or take",
        ] {
            assert_eq!(released_day(bad), None, "{bad}");
        }
    }

    /// A pack asks for a minimum engine; a client below it may not load it.
    #[test]
    fn the_minimum_engine_version_compares_part_by_part() {
        assert!(engine_satisfies("0.1.0", "0.1.0"));
        assert!(engine_satisfies("0.1.0", "0.2.0"));
        assert!(engine_satisfies("0.9.0", "0.10.0"));
        assert!(engine_satisfies("0.2", "0.2.0"));
        assert!(engine_satisfies("1.0.0", "1.0.0-rc.1"));
        assert!(!engine_satisfies("0.2.0", "0.1.9"));
        assert!(!engine_satisfies("1.0.0", "0.99.99"));
        assert!(!engine_satisfies("0.1.1", "0.1"));
        assert!(
            !engine_satisfies("zero point two", "0.1.0"),
            "a requirement this build cannot read is never met"
        );
    }

    #[test]
    fn a_listed_path_stays_inside_the_two_trees() {
        for good in ["rules/0001-x/rule.yar", "iocs/hosts.txt", "rules/README.md"] {
            assert!(is_pack_path(good), "{good}");
        }
        for bad in [
            "manifest.json",
            "rules",
            "rules/",
            "rules//x",
            "rules/../state.json",
            "rules/./x",
            "/rules/x",
            "other/x",
            "rules\\..\\x",
        ] {
            assert!(!is_pack_path(bad), "{bad}");
        }
        let climbing = a_manifest()
            .to_json()
            .replace("rules/0001-x/rule.yar", "rules/../../state.json");
        assert!(Manifest::parse(&climbing).is_err());
    }

    /// A pack root is held to its manifest file by file: a changed file, a
    /// missing one and an unlisted one are each refused.
    #[test]
    fn a_pack_root_is_held_to_its_manifest() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let root = temporary.path();
        fs::create_dir_all(root.join("iocs")).expect("iocs");
        fs::create_dir_all(root.join("rules/0001-x")).expect("rules");
        fs::write(root.join("iocs/hosts.txt"), "a host\n").expect("a list");
        fs::write(root.join("rules/0001-x/rule.yar"), "a rule\n").expect("a rule");
        let manifest = a_manifest();
        manifest
            .check_files(root)
            .expect("the pack is what it says");

        fs::write(root.join("rules/extra.yar"), "x").expect("an extra file");
        assert!(matches!(
            manifest.check_files(root),
            Err(ManifestError::Unlisted(path)) if path == "rules/extra.yar"
        ));
        fs::remove_file(root.join("rules/extra.yar")).expect("gone again");

        fs::write(root.join("iocs/hosts.txt"), "another host\n").expect("a swap");
        assert!(matches!(
            manifest.check_files(root),
            Err(ManifestError::Mismatch(path)) if path == "iocs/hosts.txt"
        ));
        fs::remove_file(root.join("iocs/hosts.txt")).expect("gone");
        assert!(matches!(
            manifest.check_files(root),
            Err(ManifestError::Missing(path)) if path == "iocs/hosts.txt"
        ));

        fs::write(root.join("iocs/hosts.txt"), "a host\n").expect("back");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hosts", root.join("iocs/linked.txt")).expect("a link");
            assert!(matches!(
                manifest.check_files(root),
                Err(ManifestError::Unlisted(path)) if path == "iocs/linked.txt"
            ));
        }
    }
}
