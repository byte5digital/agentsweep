//! The quarantine store, Receipts and Restore for files and trees.
//!
//! Taking a flagged Item out of its Surface has to be undoable exactly, so
//! every Quarantine writes a [`Receipt`]: an ordered list of steps, even for
//! one step, which Restore replays in reverse (spec section 5.3). The steps
//! are the [`ReceiptStep`]s the Event Log records, so a Receipt can be rebuilt
//! from the log alone and nothing keeps a second copy of what is in the store.
//!
//! The core owns MoveOut and the store; a Surface Adapter decides what to move
//! and in what order and asks the [`Store`] to do it (spec section 3.2). The
//! only implementation of [`Store`] that writes is [`QuarantineStore`], which
//! exists only in a build with the `daemon` feature: the daemon is the one
//! process that writes the store and the Event Log (spec section 6.2), and an
//! in-process Scan in the command line interface cannot so much as name the
//! type.
//!
//! What MoveOut promises:
//!
//! - the payload lands at `quarantine/<receipt id>/payload` with the
//!   executable bits of its files stripped, and the original name and path
//!   appear only in the Event Log;
//! - it is an atomic rename while the Item and the store share a volume, and a
//!   copy, a hash check and only then a delete when they do not;
//! - before every write the content is hashed again and compared with the hash
//!   the enumeration saw, once more after re-reading it, and the action fails
//!   with "file is changing" rather than acting on content no Finding was
//!   raised on;
//! - a symbolic link is moved as a link. The target is left where it is and
//!   named in the Receipt.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::adapter::Primitive;
use crate::derived::QuarantineEntry;
use crate::eventlog::{Outcome, ReceiptStep};
use crate::host::Host;
use crate::item::{Item, ItemId, Kind, Shape, Tree, TreeCaps, sha256_hex};

/// The prefix of every Receipt id.
const RECEIPT_PREFIX: &str = "q-";

/// How many hex characters of randomness a Receipt id carries.
const RECEIPT_DIGITS: usize = 32;

/// The identity of one Quarantine, which is also the name of its directory in
/// the store.
///
/// It says nothing about what was quarantined: legibility comes from the Event
/// Log and the user interface, never from the filename (spec section 5.1).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReceiptId(String);

impl ReceiptId {
    /// A fresh id from the operating system's random source.
    pub fn generate() -> Result<ReceiptId, EnforcementError> {
        use std::fmt::Write as _;
        let mut bytes = [0u8; RECEIPT_DIGITS / 2];
        getrandom::fill(&mut bytes).map_err(|error| {
            EnforcementError::Store(io::Error::other(format!("no random source: {error}")))
        })?;
        let mut id = RECEIPT_PREFIX.to_string();
        for byte in bytes {
            let _ = write!(id, "{byte:02x}");
        }
        Ok(ReceiptId(id))
    }

    /// Reads back the id a record carries, refusing anything that is not one.
    ///
    /// A Receipt id names a directory in the store, so it is checked rather
    /// than trusted: nothing a record holds can reach outside the store.
    pub fn parse(text: &str) -> Option<ReceiptId> {
        let digits = text.strip_prefix(RECEIPT_PREFIX)?;
        let hex = digits.len() == RECEIPT_DIGITS
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        hex.then(|| ReceiptId(text.to_string()))
    }

    /// The id as one string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReceiptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The ordered record of what one Quarantine physically did to one Item.
///
/// One Quarantine, one Receipt, whatever the primitive table says the kind
/// takes: a composite kind yields one Receipt with a step per primitive, in
/// the order they were carried out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Which Quarantine this is, and where its payload sits in the store.
    pub id: ReceiptId,
    /// The Item that was taken out.
    pub item_id: ItemId,
    /// Its Surface kind.
    pub kind: Kind,
    /// The content hash it was taken out on.
    pub content_hash: String,
    /// The steps, in the order they were taken.
    pub steps: Vec<ReceiptStep>,
}

impl Receipt {
    /// An empty Receipt for one Item.
    pub fn new(id: ReceiptId, item: &Item) -> Receipt {
        Receipt {
            id,
            item_id: item.id.clone(),
            kind: item.kind,
            content_hash: item.content_hash.clone(),
            steps: Vec::new(),
        }
    }

    /// The same Receipt with one more step at the end.
    pub fn with(mut self, step: ReceiptStep) -> Receipt {
        self.steps.push(step);
        self
    }

    /// The Receipt one entry of the quarantine manifest describes, which is
    /// how a Receipt comes back from the Event Log alone.
    pub fn from_entry(entry: &QuarantineEntry) -> Option<Receipt> {
        Some(Receipt {
            id: ReceiptId::parse(&entry.receipt_id)?,
            item_id: entry.item_id.clone(),
            kind: entry.kind?,
            content_hash: entry.content_hash.clone(),
            steps: entry.steps.clone(),
        })
    }

    /// How the Quarantine or the Restore came out as a whole: failed when any
    /// step failed, skipped when every step was skipped, ok otherwise.
    pub fn result(&self) -> Outcome {
        outcome_of(&self.steps)
    }
}

/// How the steps of one action came out as a whole.
pub fn outcome_of(steps: &[ReceiptStep]) -> Outcome {
    if steps.iter().any(|step| step.outcome == Outcome::Failed) {
        return Outcome::Failed;
    }
    if steps.iter().any(|step| step.outcome == Outcome::Ok) {
        return Outcome::Ok;
    }
    Outcome::Skipped
}

/// What Restore does when the original path is no longer free.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Conflict {
    /// Refuse and say so, which is what happens until the user picks one of
    /// the two alternatives (spec section 5.4).
    #[default]
    Refuse,
    /// Put the quarantined content back and lose what took its place.
    Replace,
    /// Put it back beside what took its place, as `<name>.restored`.
    Beside,
}

/// Why an enforcement or a Restore could not be carried out.
#[derive(Debug)]
pub enum EnforcementError {
    /// The content at the path is not the content the Finding was raised on,
    /// and it was still not after one more read.
    FileIsChanging {
        /// Where the content that keeps moving sits.
        path: PathBuf,
    },
    /// There is nothing at the path any more.
    Missing {
        /// The path that holds nothing.
        path: PathBuf,
    },
    /// The adapter does not carry out this primitive on this kind.
    Unsupported {
        /// The kind that was asked for.
        kind: Kind,
        /// The primitive that was asked for.
        primitive: Primitive,
    },
    /// Nothing may quarantine this Item on this Finding.
    NotEligible {
        /// The one sentence that says why.
        reason: String,
    },
    /// The store itself could not be written.
    Store(io::Error),
}

impl fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnforcementError::FileIsChanging { path } => {
                write!(f, "file is changing: {}", path.display())
            }
            EnforcementError::Missing { path } => {
                write!(f, "nothing is at {} any more", path.display())
            }
            EnforcementError::Unsupported { kind, primitive } => {
                write!(f, "{kind} cannot be {} by this adapter", primitive.as_str())
            }
            EnforcementError::NotEligible { reason } => f.write_str(reason),
            EnforcementError::Store(error) => write!(f, "the quarantine store: {error}"),
        }
    }
}

impl std::error::Error for EnforcementError {}

impl From<io::Error> for EnforcementError {
    fn from(error: io::Error) -> EnforcementError {
        EnforcementError::Store(error)
    }
}

/// One MoveOut an adapter asks the store for.
///
/// The source and the contents are two paths because a symlinked skill is
/// moved as a link: the identity and the thing that moves are the link's own
/// place on the Surface, and the bytes the enumeration hashed came from the
/// target (spec sections 3.3 and 5.2).
#[derive(Clone, Debug)]
pub struct MoveOutPlan<'a> {
    /// What moves into the store.
    pub source: &'a Path,
    /// Where the content the hash was taken over is read from. The same as
    /// the source unless the source is a symbolic link.
    pub contents: &'a Path,
    /// Whether the content is one file or a whole tree.
    pub shape: Shape,
    /// The content hash the enumeration saw, which the content still has to
    /// have.
    pub expected_hash: &'a str,
    /// The caps the tree was read under, so that it is hashed the same way
    /// twice.
    pub caps: TreeCaps,
    /// One line for the Activity, free of content and of sensitive values.
    pub detail: String,
}

/// The quarantine store, as a Surface Adapter may use it.
///
/// Only [`QuarantineStore`] implements it, and only a build with the `daemon`
/// feature has that type, so an adapter's enforcement path compiles
/// everywhere and can be reached only by the one process allowed to write.
pub trait Store {
    /// A fresh Receipt id. Nothing is written until a step writes it.
    fn begin(&self) -> Result<ReceiptId, EnforcementError>;

    /// Where the payload of one Receipt sits.
    fn payload_of(&self, receipt: &ReceiptId) -> PathBuf;

    /// Moves one file, tree or symbolic link into the store under the Receipt,
    /// after checking that the content is still the content the Finding was
    /// raised on.
    fn move_out(
        &self,
        host: &Host,
        receipt: &ReceiptId,
        plan: &MoveOutPlan<'_>,
    ) -> Result<ReceiptStep, EnforcementError>;

    /// Puts one payload back where the step it came from says it was, with the
    /// permission bits it had. The step it returns carries the outcome.
    fn move_back(&self, receipt: &ReceiptId, step: &ReceiptStep, conflict: Conflict)
    -> ReceiptStep;
}

/// The hash the content at a path has right now, taken the way the enumeration
/// took it: the bytes for a file, the sorted manifest for a tree.
pub fn current_hash(
    host: &Host,
    contents: &Path,
    shape: Shape,
    caps: TreeCaps,
) -> Result<String, EnforcementError> {
    match shape {
        Shape::Tree => Ok(sha256_hex(&Tree::of(host, contents, caps).manifest())),
        Shape::File => match host.read(contents) {
            Ok(bytes) => Ok(sha256_hex(&bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err(EnforcementError::Missing {
                    path: contents.to_path_buf(),
                })
            }
            Err(error) => Err(EnforcementError::Store(error)),
        },
        Shape::Entry => Err(EnforcementError::Unsupported {
            kind: Kind::Generic,
            primitive: Primitive::MoveOut,
        }),
    }
}

/// The compare-and-swap of spec section 5.3: the content has to hash to what
/// the enumeration saw, and a mismatch is read once more before the action
/// gives up with "file is changing".
///
/// Reading twice is what tells a file caught halfway through somebody else's
/// write from a file that really is not what the Finding was about. Content
/// that settled on something else is never quarantined: the Finding belongs to
/// the content it was raised on.
pub fn compare_and_swap(host: &Host, plan: &MoveOutPlan<'_>) -> Result<(), EnforcementError> {
    for _ in 0..2 {
        if current_hash(host, plan.contents, plan.shape, plan.caps)? == plan.expected_hash {
            return Ok(());
        }
    }
    Err(EnforcementError::FileIsChanging {
        path: plan.contents.to_path_buf(),
    })
}

/// Moves one Item out of its Surface, whatever its shape.
///
/// Both Agent adapters use this: what a MoveOut of a file or a tree does is
/// the core's, and what an adapter knows is which Items take one and in what
/// order relative to the other steps of a composite.
pub fn move_out_item(
    host: &Host,
    store: &dyn Store,
    receipt: &ReceiptId,
    item: &Item,
    caps: TreeCaps,
) -> Result<ReceiptStep, EnforcementError> {
    if item.shape == Shape::Entry {
        return Err(EnforcementError::Unsupported {
            kind: item.kind,
            primitive: Primitive::MoveOut,
        });
    }
    let contents = match item.is_symlink && !item.link_target.is_empty() {
        true => PathBuf::from(&item.link_target),
        false => item.path.clone(),
    };
    let detail = match item.is_symlink {
        // A target outside every Surface is named here and nowhere else, so
        // the user can see what the link pointed at without the store holding
        // it (spec section 5.2).
        true => format!("the link was moved, its target {} stayed", item.link_target),
        false => String::new(),
    };
    store.move_out(
        host,
        receipt,
        &MoveOutPlan {
            source: &item.path,
            contents: &contents,
            shape: item.shape,
            expected_hash: &item.content_hash,
            caps,
            detail,
        },
    )
}

/// What one Restore did, step by reversed step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreReport {
    /// The steps as they were replayed, in reverse order, each with its own
    /// outcome: ok, skipped when its precondition was gone, failed on a
    /// conflict.
    pub steps: Vec<ReceiptStep>,
    /// How the Restore came out as a whole.
    pub result: Outcome,
    /// True when something else holds a path a step wanted, which is what the
    /// two alternatives are offered for.
    pub conflicted: bool,
}

impl RestoreReport {
    /// The report these replayed steps make.
    pub fn of(steps: Vec<ReceiptStep>) -> RestoreReport {
        RestoreReport {
            result: outcome_of(&steps),
            conflicted: steps
                .iter()
                .any(|step| step.outcome == Outcome::Failed && step.detail.contains("is at")),
            steps,
        }
    }

    /// True when every step did what it said.
    pub fn is_complete(&self) -> bool {
        self.result == Outcome::Ok && self.steps.iter().all(|step| step.outcome == Outcome::Ok)
    }
}

/// Replays a Receipt in reverse, asking the store to put every payload back.
///
/// A step of a primitive this does not know is reported failed rather than
/// silently dropped: a partial Restore says per step what happened, and the
/// user interface says what to do about the ones that did not.
pub fn replay_in_reverse(
    store: &dyn Store,
    receipt: &Receipt,
    conflict: Conflict,
) -> RestoreReport {
    let mut steps = Vec::with_capacity(receipt.steps.len());
    for step in receipt.steps.iter().rev() {
        let replayed = match step.primitive {
            crate::eventlog::Primitive::MoveOut => store.move_back(&receipt.id, step, conflict),
            _ => ReceiptStep {
                outcome: Outcome::Failed,
                detail: "this step cannot be put back yet".to_string(),
                ..step.clone()
            },
        };
        steps.push(replayed);
    }
    RestoreReport::of(steps)
}

/// What MoveOut and Restore do to the file system, and the names the store
/// writes.
///
/// Only the daemon writes the quarantine store (spec section 6.2), so nothing
/// here is compiled into a build without the `daemon` feature: the command
/// line interface carries no code that could move a file out of a Surface.
#[cfg(feature = "daemon")]
mod disk {
    use std::io;
    use std::path::{Path, PathBuf};

    use serde_json::{Map, Value};

    /// The file beside a payload that remembers the permission bits the
    /// payload had on the Surface.
    ///
    /// The bytes of a quarantined Item live in the store rather than in the
    /// Event Log, and so do the modes: they are part of putting the Item back
    /// exactly, not part of the record of what was done. The Event Log still
    /// holds the Receipt, which is what says that the move happened at all.
    pub(super) const MODES_FILE: &str = "modes";

    /// The name of the payload inside a Receipt's directory.
    pub(super) const PAYLOAD: &str = "payload";

    /// The suffix Restore puts on a payload it was told to put beside content
    /// that took the original path.
    pub(super) const BESIDE_SUFFIX: &str = ".restored";

    /// The permission bits of everything below one path, by path relative to it,
    /// the path itself under the empty name.
    ///
    /// Symbolic links carry no bits of their own that anything reads, and changing
    /// them would change the target's, so they are left out.
    pub(super) fn modes_below(root: &Path) -> io::Result<Map<String, Value>> {
        let mut modes = Map::new();
        let mut stack = vec![(root.to_path_buf(), String::new())];
        while let Some((path, relative)) = stack.pop() {
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            modes.insert(relative.clone(), Value::from(mode_of(&metadata)));
            if !metadata.is_dir() {
                continue;
            }
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&path)?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect();
            entries.sort();
            for entry in entries {
                let name = entry
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let below = match relative.is_empty() {
                    true => name,
                    false => format!("{relative}/{name}"),
                };
                stack.push((entry, below));
            }
        }
        Ok(modes)
    }

    /// Puts the recorded permission bits back on a restored payload.
    pub(super) fn apply_modes(root: &Path, modes: &Map<String, Value>) {
        for (relative, mode) in modes {
            let Some(mode) = mode.as_u64() else {
                continue;
            };
            let path = match relative.is_empty() {
                true => root.to_path_buf(),
                false => root.join(relative),
            };
            set_mode(&path, mode as u32);
        }
    }

    #[cfg(unix)]
    pub(super) fn mode_of(metadata: &std::fs::Metadata) -> u64 {
        use std::os::unix::fs::PermissionsExt;
        u64::from(metadata.permissions().mode() & 0o7777)
    }

    #[cfg(not(unix))]
    pub(super) fn mode_of(metadata: &std::fs::Metadata) -> u64 {
        u64::from(metadata.permissions().readonly())
    }

    #[cfg(unix)]
    pub(super) fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        // A link is never chmodded: the call would follow it and change the
        // target's bits, and the target is the one thing a MoveOut of a link
        // leaves alone.
        if std::fs::symlink_metadata(path).is_ok_and(|found| found.file_type().is_symlink()) {
            return;
        }
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }

    #[cfg(not(unix))]
    pub(super) fn set_mode(_path: &Path, _mode: u32) {}

    /// Takes the executable bits off every regular file of a payload.
    ///
    /// Directories keep theirs: a directory nobody may enter is a payload nobody
    /// can restore, and a directory is not a thing the operating system runs.
    #[cfg(unix)]
    pub(super) fn strip_executable_bits(root: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                for entry in std::fs::read_dir(&path)?.filter_map(Result::ok) {
                    stack.push(entry.path());
                }
                continue;
            }
            let mode = metadata.permissions().mode() & !0o111;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(super) fn strip_executable_bits(_root: &Path) -> io::Result<()> {
        Ok(())
    }

    /// True when the two paths are on different volumes, which is the one rename
    /// failure MoveOut answers with a copy.
    pub(super) fn crosses_volumes(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::CrossesDevices || error.raw_os_error() == Some(18)
    }

    /// Copies one file, directory or symbolic link, keeping the permission bits
    /// and never following a link.
    pub(super) fn copy_across(source: &Path, destination: &Path) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(source)?;
        if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(source)?;
            return symlink_to(&target, destination);
        }
        if !metadata.is_dir() {
            std::fs::copy(source, destination)?;
            return Ok(());
        }
        std::fs::create_dir_all(destination)?;
        let mut entries: Vec<PathBuf> = std::fs::read_dir(source)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        entries.sort();
        for entry in entries {
            let name = entry.file_name().unwrap_or_default().to_os_string();
            copy_across(&entry, &destination.join(name))?;
        }
        set_mode(destination, mode_of(&metadata) as u32);
        Ok(())
    }

    #[cfg(unix)]
    pub(super) fn symlink_to(target: &Path, destination: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, destination)
    }

    #[cfg(not(unix))]
    pub(super) fn symlink_to(_target: &Path, _destination: &Path) -> io::Result<()> {
        Err(io::Error::other("this platform has no symbolic links"))
    }

    /// Renames one path to another, which is the whole of MoveOut while the
    /// Surface and the store share a volume.
    pub(super) fn rename(source: &Path, destination: &Path) -> io::Result<()> {
        std::fs::rename(source, destination)
    }

    /// Removes a file, a directory or a link, whichever is there.
    pub(super) fn remove(path: &Path) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        match metadata.is_dir() && !metadata.file_type().is_symlink() {
            true => std::fs::remove_dir_all(path),
            false => std::fs::remove_file(path),
        }
    }
}

#[cfg(feature = "daemon")]
pub use store::QuarantineStore;

#[cfg(feature = "daemon")]
mod store {
    use super::disk::{
        BESIDE_SUFFIX, MODES_FILE, PAYLOAD, apply_modes, copy_across, crosses_volumes, modes_below,
        remove, rename, strip_executable_bits,
    };
    use super::{
        Conflict, EnforcementError, MoveOutPlan, ReceiptId, Store, compare_and_swap, current_hash,
    };

    use std::io;
    use std::path::{Path, PathBuf};

    use serde_json::{Map, Value};

    use crate::adapter::Primitive;
    use crate::eventlog::{Outcome, ReceiptStep};
    use crate::host::Host;
    use crate::paths::DataDirectory;

    /// The write side of the quarantine store.
    ///
    /// The daemon is the only writer (spec section 6.2), which this type
    /// carries: it exists only in a build with the `daemon` feature, and it is
    /// the only [`Store`] there is, so an adapter's enforcement path is
    /// unreachable anywhere else.
    #[derive(Clone, Debug)]
    pub struct QuarantineStore {
        directory: DataDirectory,
        rename: fn(&Path, &Path) -> io::Result<()>,
    }

    impl QuarantineStore {
        /// The store of one data directory, created if it is not there yet.
        pub fn open(directory: &DataDirectory) -> io::Result<QuarantineStore> {
            directory.create()?;
            Ok(QuarantineStore {
                directory: directory.clone(),
                rename,
            })
        }

        /// The same store with the rename reporting that the two paths are on
        /// different volumes, which is the seam the copy path is proven
        /// through without a second volume to run the suite on.
        pub fn across_volumes(mut self) -> QuarantineStore {
            self.rename = |_, _| Err(io::Error::from(io::ErrorKind::CrossesDevices));
            self
        }

        /// The data directory the store sits in.
        pub fn directory(&self) -> &DataDirectory {
            &self.directory
        }

        /// The directory of one Receipt: its payload and the payload's modes.
        fn receipt_directory(&self, receipt: &ReceiptId) -> PathBuf {
            self.directory.quarantine().join(receipt.as_str())
        }

        /// Moves one path into the other, atomically where the file system can
        /// and by copy, hash check and delete where it cannot.
        fn relocate(
            &self,
            host: &Host,
            source: &Path,
            destination: &Path,
            expected: &Expected<'_>,
        ) -> Result<Via, EnforcementError> {
            match (self.rename)(source, destination) {
                Ok(()) => Ok(Via::Rename),
                Err(error) if crosses_volumes(&error) => {
                    copy_across(source, destination)?;
                    let landed = current_hash(host, destination, expected.shape, expected.caps)?;
                    if landed != expected.hash {
                        let _ = remove(destination);
                        return Err(EnforcementError::Store(io::Error::other(
                            "the copy onto the other volume did not verify",
                        )));
                    }
                    remove(source)?;
                    Ok(Via::Copy)
                }
                Err(error) => Err(EnforcementError::Store(error)),
            }
        }

        fn write_modes(&self, receipt: &ReceiptId, modes: &Map<String, Value>) -> io::Result<()> {
            let path = self.receipt_directory(receipt).join(MODES_FILE);
            std::fs::write(path, Value::Object(modes.clone()).to_string())
        }

        fn read_modes(&self, receipt: &ReceiptId) -> Map<String, Value> {
            let path = self.receipt_directory(receipt).join(MODES_FILE);
            std::fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|value| value.as_object().cloned())
                .unwrap_or_default()
        }
    }

    /// What the content that is being moved has to hash to, and how.
    struct Expected<'a> {
        hash: &'a str,
        shape: crate::item::Shape,
        caps: crate::item::TreeCaps,
    }

    /// How a payload got where it is.
    enum Via {
        Rename,
        Copy,
    }

    impl Via {
        fn as_str(&self) -> &'static str {
            match self {
                Via::Rename => "moved",
                Via::Copy => "copied onto another volume, checked and deleted",
            }
        }
    }

    impl Store for QuarantineStore {
        fn begin(&self) -> Result<ReceiptId, EnforcementError> {
            ReceiptId::generate()
        }

        fn payload_of(&self, receipt: &ReceiptId) -> PathBuf {
            self.directory.quarantine_payload(receipt.as_str())
        }

        fn move_out(
            &self,
            host: &Host,
            receipt: &ReceiptId,
            plan: &MoveOutPlan<'_>,
        ) -> Result<ReceiptStep, EnforcementError> {
            if std::fs::symlink_metadata(plan.source).is_err() {
                return Err(EnforcementError::Missing {
                    path: plan.source.to_path_buf(),
                });
            }
            compare_and_swap(host, plan)?;

            let directory = self.receipt_directory(receipt);
            std::fs::create_dir_all(&directory).map_err(EnforcementError::Store)?;
            let modes = modes_below(plan.source).map_err(EnforcementError::Store)?;
            self.write_modes(receipt, &modes)
                .map_err(EnforcementError::Store)?;

            let payload = directory.join(PAYLOAD);
            let via = match self.relocate(
                host,
                plan.source,
                &payload,
                &Expected {
                    hash: plan.expected_hash,
                    shape: plan.shape,
                    caps: plan.caps,
                },
            ) {
                Ok(via) => via,
                Err(error) => {
                    // Nothing moved, so the store keeps no directory for a
                    // Quarantine that did not happen: the manifest rebuilt
                    // from the Event Log and the store agree.
                    let _ = std::fs::remove_dir_all(&directory);
                    return Err(error);
                }
            };
            strip_executable_bits(&payload).map_err(EnforcementError::Store)?;

            let mut detail = format!("{} into the quarantine store", via.as_str());
            if !plan.detail.is_empty() {
                detail = format!("{}; {detail}", plan.detail);
            }
            Ok(ReceiptStep {
                primitive: Primitive::MoveOut.recorded(),
                outcome: Outcome::Ok,
                path: plan.source.display().to_string(),
                locator: String::new(),
                detail,
            })
        }

        fn move_back(
            &self,
            receipt: &ReceiptId,
            step: &ReceiptStep,
            conflict: Conflict,
        ) -> ReceiptStep {
            let mut replayed = step.clone();
            let payload = self.payload_of(receipt);
            if std::fs::symlink_metadata(&payload).is_err() {
                replayed.outcome = Outcome::Skipped;
                replayed.detail = "the payload is no longer in the store".to_string();
                return replayed;
            }
            let original = PathBuf::from(&step.path);
            let taken = std::fs::symlink_metadata(&original).is_ok();
            let destination = match (taken, conflict) {
                (false, _) => original.clone(),
                (true, Conflict::Refuse) => {
                    replayed.outcome = Outcome::Failed;
                    replayed.detail = format!(
                        "something else is at {}: replace it or restore beside it",
                        original.display()
                    );
                    return replayed;
                }
                (true, Conflict::Replace) => {
                    if let Err(error) = remove(&original) {
                        replayed.outcome = Outcome::Failed;
                        replayed.detail = format!(
                            "what is at {} could not be replaced: {error}",
                            original.display()
                        );
                        return replayed;
                    }
                    original.clone()
                }
                (true, Conflict::Beside) => {
                    PathBuf::from(format!("{}{BESIDE_SUFFIX}", original.display()))
                }
            };

            if let Some(parent) = destination.parent()
                && let Err(error) = std::fs::create_dir_all(parent)
            {
                replayed.outcome = Outcome::Failed;
                replayed.detail = format!("{} could not be made: {error}", parent.display());
                return replayed;
            }
            if let Err(error) = self.put_back(&payload, &destination) {
                replayed.outcome = Outcome::Failed;
                replayed.detail = format!("the payload could not be put back: {error}");
                return replayed;
            }
            apply_modes(&destination, &self.read_modes(receipt));
            let _ = std::fs::remove_file(self.receipt_directory(receipt).join(MODES_FILE));
            let _ = std::fs::remove_dir(self.receipt_directory(receipt));

            replayed.outcome = Outcome::Ok;
            replayed.detail = match destination == original {
                true => format!("put back at {}", destination.display()),
                false => format!("put back beside it at {}", destination.display()),
            };
            replayed
        }
    }

    impl QuarantineStore {
        /// Moves a payload out of the store, by rename where the file system
        /// can and by copy and delete where it cannot.
        fn put_back(&self, payload: &Path, destination: &Path) -> io::Result<()> {
            match (self.rename)(payload, destination) {
                Ok(()) => Ok(()),
                Err(error) if crosses_volumes(&error) => {
                    copy_across(payload, destination)?;
                    remove(payload)
                }
                Err(error) => Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Activation, Provenance, Scope};
    use crate::paths::DataDirectory;

    use tempfile::TempDir;

    /// A store over a temporary directory and a Host over another, which is
    /// how every test here stays off the real machine.
    struct Bench {
        _store_root: TempDir,
        surface: TempDir,
        store: QuarantineStore,
        host: Host,
    }

    impl Bench {
        fn new() -> Bench {
            let store_root = TempDir::new().expect("a temporary directory");
            let surface = TempDir::new().expect("a temporary directory");
            let directory = DataDirectory::at(store_root.path().join("data"));
            let store = QuarantineStore::open(&directory).expect("an open store");
            let host = Host::new(surface.path().to_path_buf(), Vec::new());
            Bench {
                _store_root: store_root,
                surface,
                store,
                host,
            }
        }

        fn across_volumes(mut self) -> Bench {
            self.store = self.store.across_volumes();
            self
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.surface.path().join(relative)
        }

        fn write(&self, relative: &str, content: &str) -> PathBuf {
            let path = self.path(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("a directory");
            }
            std::fs::write(&path, content).expect("a file");
            path
        }

        fn file_item(&self, relative: &str, content: &str) -> Item {
            let path = self.write(relative, content);
            Item::file(
                "claude-code",
                Scope::User,
                Kind::InstructionFile,
                relative,
                path,
                Provenance::Manual,
                Activation::Active,
                content.as_bytes().to_vec(),
            )
        }

        fn tree_item(&self, relative: &str) -> Item {
            let root = self.path(relative);
            Item::tree(
                "claude-code",
                Scope::User,
                Kind::Skill,
                relative,
                root.clone(),
                Provenance::Manual,
                Activation::Active,
                Tree::of(&self.host, &root, TreeCaps::default()),
            )
        }
    }

    fn quarantine(bench: &Bench, item: &Item) -> Result<Receipt, EnforcementError> {
        let id = bench.store.begin()?;
        let step = move_out_item(&bench.host, &bench.store, &id, item, TreeCaps::default())?;
        Ok(Receipt::new(id, item).with(step))
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path)
            .expect("the path")
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn a_receipt_id_is_checked_rather_than_trusted() {
        let id = ReceiptId::generate().expect("an id");
        assert_eq!(ReceiptId::parse(id.as_str()), Some(id));
        assert!(ReceiptId::parse("../../etc").is_none());
        assert!(ReceiptId::parse("q-../etc").is_none());
        assert!(ReceiptId::parse("r-1").is_none());
        assert!(ReceiptId::parse(&format!("q-{}", "Z".repeat(32))).is_none());
    }

    #[test]
    fn a_file_goes_into_the_store_and_comes_back_byte_for_byte() {
        let bench = Bench::new();
        let item = bench.file_item("CLAUDE.md", "# demo\n\nRun the tests.\n");
        let before = std::fs::read(&item.path).expect("the file");

        let receipt = quarantine(&bench, &item).expect("a Quarantine");

        assert!(!item.path.exists(), "the Surface still holds the file");
        let payload = bench.store.payload_of(&receipt.id);
        assert_eq!(std::fs::read(&payload).expect("the payload"), before);
        assert_eq!(receipt.result(), Outcome::Ok);

        let report = replay_in_reverse(&bench.store, &receipt, Conflict::Refuse);

        assert!(report.is_complete(), "{report:?}");
        assert_eq!(std::fs::read(&item.path).expect("the file"), before);
    }

    #[test]
    fn the_original_name_is_nowhere_in_the_store() {
        let bench = Bench::new();
        let item = bench.file_item("secrets-of-the-realm.md", "# demo\n");
        let receipt = quarantine(&bench, &item).expect("a Quarantine");

        let payload = bench.store.payload_of(&receipt.id);
        let rendered = payload.display().to_string();
        assert!(!rendered.contains("secrets-of-the-realm"), "{rendered}");
        assert!(rendered.ends_with(&format!("{}/payload", receipt.id)));
        // The path is in the Receipt, which is what the Event Log records.
        assert_eq!(receipt.steps[0].path, item.path.display().to_string());
    }

    #[cfg(unix)]
    #[test]
    fn a_tree_keeps_its_bytes_and_its_modes_and_loses_its_executable_bits_in_the_store() {
        let bench = Bench::new();
        bench.write("skills/pdf/SKILL.md", "---\nname: pdf\n---\n");
        let helper = bench.write("skills/pdf/bin/helper", "#!/bin/sh\necho hi\n");
        disk::set_mode(&helper, 0o755);
        let item = bench.tree_item("skills/pdf");

        let receipt = quarantine(&bench, &item).expect("a Quarantine");

        assert!(!item.path.exists());
        let payload = bench.store.payload_of(&receipt.id);
        assert_eq!(mode(&payload.join("bin/helper")) & 0o111, 0);
        assert_eq!(
            std::fs::read_to_string(payload.join("bin/helper")).expect("the payload"),
            "#!/bin/sh\necho hi\n"
        );

        let report = replay_in_reverse(&bench.store, &receipt, Conflict::Refuse);

        assert!(report.is_complete(), "{report:?}");
        assert_eq!(mode(&helper), 0o755);
        assert_eq!(
            sha256_hex(&Tree::of(&bench.host, &item.path, TreeCaps::default()).manifest()),
            item.content_hash
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_skill_moves_the_link_and_leaves_the_target_alone() {
        let bench = Bench::new();
        bench.write("shared/notes/SKILL.md", "---\nname: notes\n---\n");
        let link = bench.path("skills/notes");
        std::fs::create_dir_all(link.parent().expect("a parent")).expect("a directory");
        disk::symlink_to(&bench.path("shared/notes"), &link).expect("a link");
        let item = bench
            .tree_item("skills/notes")
            .through_link(&bench.path("shared/notes"));

        let receipt = quarantine(&bench, &item).expect("a Quarantine");

        assert!(
            bench.path("shared/notes/SKILL.md").is_file(),
            "the target was moved"
        );
        assert!(std::fs::symlink_metadata(&link).is_err());
        let payload = bench.store.payload_of(&receipt.id);
        assert!(
            std::fs::symlink_metadata(&payload)
                .expect("the payload")
                .file_type()
                .is_symlink()
        );
        assert!(receipt.steps[0].detail.contains("its target"));

        let report = replay_in_reverse(&bench.store, &receipt, Conflict::Refuse);

        assert!(report.is_complete(), "{report:?}");
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("the link")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn a_file_that_changed_since_the_enumeration_fails_with_file_is_changing() {
        let bench = Bench::new();
        let item = bench.file_item("CLAUDE.md", "# demo\n");
        std::fs::write(&item.path, "# something else\n").expect("a rewritten file");

        let error = quarantine(&bench, &item).expect_err("a refusal");

        assert!(matches!(error, EnforcementError::FileIsChanging { .. }));
        assert!(error.to_string().starts_with("file is changing"));
        assert!(item.path.is_file(), "the file was moved anyway");
        assert_eq!(
            std::fs::read_dir(bench.store.directory().quarantine())
                .expect("the store")
                .count(),
            0,
            "a Quarantine that did not happen left a directory behind"
        );
    }

    #[test]
    fn a_file_that_is_what_the_finding_was_about_passes_the_compare_and_swap() {
        let bench = Bench::new();
        let item = bench.file_item("CLAUDE.md", "# demo\n");
        let plan = MoveOutPlan {
            source: &item.path,
            contents: &item.path,
            shape: Shape::File,
            expected_hash: &item.content_hash,
            caps: TreeCaps::default(),
            detail: String::new(),
        };
        assert!(compare_and_swap(&bench.host, &plan).is_ok());
    }

    #[test]
    fn restore_onto_changed_content_refuses_and_both_alternatives_work() {
        let bench = Bench::new();
        let item = bench.file_item("CLAUDE.md", "# demo\n");
        let receipt = quarantine(&bench, &item).expect("a Quarantine");
        std::fs::write(&item.path, "# whatever came after\n").expect("a new file");

        let refused = replay_in_reverse(&bench.store, &receipt, Conflict::Refuse);
        assert_eq!(refused.result, Outcome::Failed);
        assert!(refused.conflicted);
        assert_eq!(refused.steps[0].outcome, Outcome::Failed);
        assert!(refused.steps[0].detail.contains("restore beside it"));

        let beside = replay_in_reverse(&bench.store, &receipt, Conflict::Beside);
        assert!(beside.is_complete(), "{beside:?}");
        assert_eq!(
            std::fs::read_to_string(bench.path("CLAUDE.md.restored")).expect("the restored file"),
            "# demo\n"
        );
        assert_eq!(
            std::fs::read_to_string(&item.path).expect("what took its place"),
            "# whatever came after\n"
        );

        // Again, from the top, to prove the other alternative.
        let item = bench.file_item("OTHER.md", "# demo\n");
        let receipt = quarantine(&bench, &item).expect("a Quarantine");
        std::fs::write(&item.path, "# whatever came after\n").expect("a new file");
        let replaced = replay_in_reverse(&bench.store, &receipt, Conflict::Replace);
        assert!(replaced.is_complete(), "{replaced:?}");
        assert_eq!(
            std::fs::read_to_string(&item.path).expect("the restored file"),
            "# demo\n"
        );
    }

    #[test]
    fn a_payload_that_is_gone_is_a_skipped_step_and_not_a_failure() {
        let bench = Bench::new();
        let item = bench.file_item("CLAUDE.md", "# demo\n");
        let receipt = quarantine(&bench, &item).expect("a Quarantine");
        std::fs::remove_file(bench.store.payload_of(&receipt.id)).expect("a lost payload");

        let report = replay_in_reverse(&bench.store, &receipt, Conflict::Refuse);

        assert_eq!(report.result, Outcome::Skipped);
        assert_eq!(report.steps[0].outcome, Outcome::Skipped);
        assert!(report.steps[0].detail.contains("no longer in the store"));
    }

    #[test]
    fn a_receipt_replays_its_steps_in_reverse() {
        let bench = Bench::new();
        let item = bench.file_item("CLAUDE.md", "# demo\n");
        let receipt = quarantine(&bench, &item)
            .expect("a Quarantine")
            .with(ReceiptStep::new(
                crate::eventlog::Primitive::NativeDisable,
                "/somewhere/settings.json",
            ));

        let report = replay_in_reverse(&bench.store, &receipt, Conflict::Refuse);

        assert_eq!(report.steps.len(), 2);
        assert_eq!(
            report.steps[0].primitive,
            crate::eventlog::Primitive::NativeDisable
        );
        assert_eq!(
            report.steps[1].primitive,
            crate::eventlog::Primitive::MoveOut
        );
        assert_eq!(report.steps[0].outcome, Outcome::Failed);
        assert_eq!(report.steps[1].outcome, Outcome::Ok);
        assert_eq!(report.result, Outcome::Failed);
    }

    #[cfg(unix)]
    #[test]
    fn an_item_on_another_volume_is_copied_checked_and_only_then_deleted() {
        let bench = Bench::new().across_volumes();
        bench.write("skills/pdf/SKILL.md", "---\nname: pdf\n---\n");
        let helper = bench.write("skills/pdf/bin/helper", "#!/bin/sh\necho hi\n");
        disk::set_mode(&helper, 0o755);
        let item = bench.tree_item("skills/pdf");

        let receipt = quarantine(&bench, &item).expect("a Quarantine");

        assert!(receipt.steps[0].detail.contains("another volume"));
        assert!(!item.path.exists());
        let payload = bench.store.payload_of(&receipt.id);
        assert_eq!(mode(&payload.join("bin/helper")) & 0o111, 0);

        let report = replay_in_reverse(&bench.store, &receipt, Conflict::Refuse);

        assert!(report.is_complete(), "{report:?}");
        assert_eq!(mode(&helper), 0o755);
        assert_eq!(
            sha256_hex(&Tree::of(&bench.host, &item.path, TreeCaps::default()).manifest()),
            item.content_hash
        );
    }

    #[test]
    fn an_item_that_is_not_there_is_not_quarantined() {
        let bench = Bench::new();
        let item = bench.file_item("CLAUDE.md", "# demo\n");
        std::fs::remove_file(&item.path).expect("a removed file");

        let error = quarantine(&bench, &item).expect_err("a refusal");

        assert!(matches!(error, EnforcementError::Missing { .. }));
    }

    #[test]
    fn an_entry_item_is_never_moved_out() {
        let bench = Bench::new();
        let item = Item::entry(
            "claude-code",
            Scope::User,
            Kind::McpServer,
            ".mcp.json#leak",
            bench.path(".mcp.json"),
            Provenance::Manual,
            Activation::Active,
            b"{}".to_vec(),
        );

        let error = quarantine(&bench, &item).expect_err("a refusal");

        assert!(matches!(error, EnforcementError::Unsupported { .. }));
    }
}
