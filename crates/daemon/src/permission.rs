//! Needs Permission: which project roots the daemon may read by itself.
//!
//! macOS guards a handful of locations with a consent of their own: Documents,
//! Desktop, Downloads, iCloud Drive and other File Provider storage, removable
//! volumes and network volumes. The first read into one of them may put a
//! system alert on screen, and a Full Scan at login must never do that at an
//! arbitrary moment. So the daemon never makes the first read into a location
//! class it has not read successfully before (spec section 9.7). A pooled root
//! in such a class is Needs Permission: it is not read, not watched and never
//! counts towards an all-clear, until the user clicks **Check now** and the
//! read that may raise the alert is made on a thread of its own.
//!
//! The class is decided from the path alone. Nothing inside the root is
//! touched to decide it, not even a `stat`: whether metadata reads are free of
//! the alert is marked unverified in the research
//! (`docs/research/macos-first-run-permissions.md`, section 3), so the daemon
//! does not rely on it.
//!
//! A class read successfully before is remembered in the state file. A root
//! in such a class is read through [`Folders`] before the adapters see it, and
//! an `EPERM` there (a grant taken back in System Settings) is Needs
//! Permission again rather than a project whose Items have all gone.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use agentsweep_core::baseline::{Baseline, BaselineRecord, Origin};
use agentsweep_core::chain::ChainState;
use agentsweep_core::keychain::KeySource;
use agentsweep_core::overview::{Overview, ProjectCheck};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::state::Trigger;

use crate::service::Daemon;

/// Where a path lies, as far as the operating system's consent is concerned.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LocationClass {
    /// Nowhere the operating system asks about: the home's own directories
    /// such as `~/Developer`, and the rest of the disk.
    Unprotected,
    /// The home's Documents folder.
    Documents,
    /// The home's Desktop folder.
    Desktop,
    /// The home's Downloads folder.
    Downloads,
    /// iCloud Drive (`~/Library/Mobile Documents`) and every other File
    /// Provider's storage (`~/Library/CloudStorage/<provider>`).
    FileProvider,
    /// A volume mounted under `/Volumes`.
    RemovableVolumes,
    /// A share mounted under `/Network` or `/net`.
    NetworkVolumes,
}

impl LocationClass {
    /// Every protected class, in the order the state file lists them.
    pub const PROTECTED: [LocationClass; 6] = [
        LocationClass::Documents,
        LocationClass::Desktop,
        LocationClass::Downloads,
        LocationClass::FileProvider,
        LocationClass::RemovableVolumes,
        LocationClass::NetworkVolumes,
    ];

    /// The spelling the state file carries.
    pub fn as_str(self) -> &'static str {
        match self {
            LocationClass::Unprotected => "unprotected",
            LocationClass::Documents => "documents",
            LocationClass::Desktop => "desktop",
            LocationClass::Downloads => "downloads",
            LocationClass::FileProvider => "file_provider",
            LocationClass::RemovableVolumes => "removable_volumes",
            LocationClass::NetworkVolumes => "network_volumes",
        }
    }

    /// Reads back a protected class's spelling. The unprotected class is
    /// never remembered, so it never reads back.
    pub fn parse(text: &str) -> Option<LocationClass> {
        LocationClass::PROTECTED
            .into_iter()
            .find(|class| class.as_str() == text)
    }

    /// True for every class the operating system asks the user about.
    pub fn is_protected(self) -> bool {
        self != LocationClass::Unprotected
    }
}

/// The location class of one path, decided from the path alone.
///
/// Names are compared without regard to ASCII case, as the default macOS
/// volume compares them, so `~/documents/app` is Documents too: reading too
/// much into a name only ever withholds a root, never reads one. The prefix
/// `/System/Volumes/Data`, under which the data volume is also reachable, is
/// taken off first. A home that lives on a volume of its own keeps its
/// Documents, Desktop and Downloads classes.
pub fn classify(home: &Path, path: &Path) -> LocationClass {
    let path = on_the_data_volume(&lexical(path));
    let home = on_the_data_volume(&lexical(home));
    if let Some(rest) = below(&path, &home) {
        let first = rest.first().map(String::as_str).unwrap_or_default();
        let second = rest.get(1).map(String::as_str).unwrap_or_default();
        if first.eq_ignore_ascii_case("Documents") {
            return LocationClass::Documents;
        }
        if first.eq_ignore_ascii_case("Desktop") {
            return LocationClass::Desktop;
        }
        if first.eq_ignore_ascii_case("Downloads") {
            return LocationClass::Downloads;
        }
        if first.eq_ignore_ascii_case("Library")
            && (second.eq_ignore_ascii_case("Mobile Documents")
                || second.eq_ignore_ascii_case("CloudStorage"))
        {
            return LocationClass::FileProvider;
        }
    }
    let names = names(&path);
    match names.first().map(String::as_str) {
        Some(first) if first.eq_ignore_ascii_case("Volumes") && names.len() > 1 => {
            LocationClass::RemovableVolumes
        }
        Some(first)
            if (first.eq_ignore_ascii_case("Network") || first.eq_ignore_ascii_case("net"))
                && names.len() > 1 =>
        {
            LocationClass::NetworkVolumes
        }
        _ => LocationClass::Unprotected,
    }
}

/// The path with `.` dropped and `..` taken back, without asking the disk.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The names of an absolute path's components, root left out.
fn names(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// The path without the data volume's own prefix.
fn on_the_data_volume(path: &Path) -> PathBuf {
    let names = names(path);
    let data = ["System", "Volumes", "Data"];
    if path.is_absolute()
        && names.len() >= data.len()
        && names
            .iter()
            .zip(data)
            .all(|(name, wanted)| name.eq_ignore_ascii_case(wanted))
    {
        let mut out = PathBuf::from("/");
        out.extend(&names[data.len()..]);
        return out;
    }
    path.to_path_buf()
}

/// The names of `path` below `base`, compared without regard to ASCII case;
/// nothing when `path` is not below `base`.
fn below(path: &Path, base: &Path) -> Option<Vec<String>> {
    let path = names(path);
    let base = names(base);
    if base.is_empty() || path.len() < base.len() {
        return None;
    }
    path.iter()
        .zip(&base)
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
        .then(|| path[base.len()..].to_vec())
}

/// The one read into a project root the daemon makes before an adapter may.
///
/// It is the seam the protected locations sit behind: the shipped daemon
/// lists the directory, a test hands in a handle that records every root it
/// is asked to open, answers as a denial would, or blocks the way the system
/// alert may block the call (research section 3).
pub trait Folders: Send + Sync {
    /// Reads the contents of one root.
    fn read(&self, root: &Path) -> io::Result<()>;
}

/// The disk itself: one directory listing, which is the read the operating
/// system asks the user about.
#[derive(Clone, Copy, Debug, Default)]
pub struct Disk;

impl Folders for Disk {
    fn read(&self, root: &Path) -> io::Result<()> {
        let mut entries = std::fs::read_dir(root)?;
        if let Some(entry) = entries.next() {
            entry?;
        }
        Ok(())
    }
}

/// True when a read failed because the operating system's consent is
/// missing. Such a denial is `EPERM`; plain file permissions fail with
/// `EACCES`, which is a Problem the adapters report like any other (research
/// section 3).
pub fn is_denied(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EPERM)
}

/// How far a Scan may go into one registered project root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reach {
    /// The root is read and enumerated like any other.
    Read,
    /// The root is not read: its class was never read before, or the read
    /// was denied.
    NeedsPermission,
    /// Nothing is at the root any more.
    Gone,
}

/// What a Scan may read by itself: the classes read successfully before, and
/// the handle the read into such a class is made through.
#[derive(Clone, Copy)]
pub struct Access<'a> {
    /// The protected classes read successfully before.
    pub readable: &'a BTreeSet<LocationClass>,
    /// The handle a root of such a class is read through.
    pub folders: &'a dyn Folders,
}

impl std::fmt::Debug for Access<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Access")
            .field("readable", &self.readable)
            .finish_non_exhaustive()
    }
}

impl Access<'_> {
    /// How far a Scan may go into one root of the machine whose home is
    /// given.
    ///
    /// An unprotected root is pooled when it is a directory, as it always
    /// was. A root of a protected class never read before is not touched at
    /// all. A root of a class read before is read once through the handle,
    /// and a denial there is Needs Permission again.
    pub fn reach(&self, home: &Path, root: &Path) -> Reach {
        let class = classify(home, root);
        if !class.is_protected() {
            return match root.is_dir() {
                true => Reach::Read,
                false => Reach::Gone,
            };
        }
        if !self.readable.contains(&class) {
            return Reach::NeedsPermission;
        }
        match self.folders.read(root) {
            Ok(()) => Reach::Read,
            Err(error) if is_denied(&error) => Reach::NeedsPermission,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Reach::Gone,
            Err(_) => match root.is_dir() {
                true => Reach::Read,
                false => Reach::Gone,
            },
        }
    }
}

/// The protected classes a state file names, which is what a Scan may read
/// by itself. A spelling this version does not know is left out.
pub fn remembered<'a>(names: impl IntoIterator<Item = &'a String>) -> BTreeSet<LocationClass> {
    names
        .into_iter()
        .filter_map(|name| LocationClass::parse(name))
        .collect()
}

/// The protected classes the Baseline proves AgentSweep read before: a
/// record the key in hand verifies, of an Item read from a path in that
/// class. What a rebuilt state file starts from, so a lost state file does
/// not turn every granted project back to Needs Permission.
pub fn proven_readable<'a>(
    home: &Path,
    records: impl IntoIterator<Item = &'a BaselineRecord>,
) -> BTreeSet<LocationClass> {
    proven_by(
        home,
        records
            .into_iter()
            .map(|record| (record.path.as_str(), record.origin)),
    )
}

/// The same over each record's path and origin.
fn proven_by<'a>(
    home: &Path,
    records: impl IntoIterator<Item = (&'a str, Origin)>,
) -> BTreeSet<LocationClass> {
    records
        .into_iter()
        .filter(|(path, origin)| *origin == Origin::Verified && !path.is_empty())
        .map(|(path, _)| classify(home, Path::new(path)))
        .filter(|class| class.is_protected())
        .collect()
}

/// How many projects the Overview lists as Needing Permission, which is the
/// count Health carries (spec section 6.6).
pub fn needing_permission(overview: &Overview) -> usize {
    overview
        .projects
        .iter()
        .filter(|project| project.check == ProjectCheck::NeedsPermission)
        .count()
}

/// The protected classes an intact Baseline in the data directory proves
/// readable, as the state file spells them. Nothing when the Baseline cannot
/// be read or is not intact: a record nobody can vouch for proves nothing.
pub fn proven_readable_classes(
    directory: &DataDirectory,
    keys: &dyn KeySource,
    home: &Path,
) -> BTreeSet<String> {
    match Baseline::in_data_directory(directory).read(keys) {
        Ok(view) if view.state == ChainState::Intact => proven_readable(home, view.records())
            .into_iter()
            .map(|class| class.as_str().to_string())
            .collect(),
        _ => BTreeSet::new(),
    }
}

/// The name of the thread "Check now" makes its reads on, which is never a
/// thread that answers a connection.
pub const FIRST_READ_THREAD: &str = "agentsweep-first-read";

impl Daemon {
    /// The protected classes the state file remembers as read before.
    pub(crate) fn readable_classes(&self) -> BTreeSet<LocationClass> {
        remembered(
            &self
                .state
                .lock()
                .expect("the state is not poisoned")
                .readable_classes,
        )
    }

    /// "Check now": the user's click that makes the first read into each
    /// location class a project Needs Permission in (spec sections 8.6 and
    /// 9.7).
    ///
    /// One root of each pending class is read, on a thread that serves no
    /// connection, because the call may block for as long as the system alert
    /// is on screen (research section 3). A class whose read succeeds is
    /// remembered in the state file, and a Full Scan then reads its projects;
    /// a denied read leaves its projects Needing Permission. Answers with
    /// true when the reads were started, false when one "Check now" is still
    /// making them or no project Needs Permission.
    pub fn check_now(self: &Arc<Daemon>) -> bool {
        if self.checking.swap(true, Ordering::SeqCst) {
            return false;
        }
        let pending = self.pending_classes();
        if pending.is_empty() {
            self.checking.store(false, Ordering::SeqCst);
            return false;
        }
        let daemon = Arc::clone(self);
        let started = std::thread::Builder::new()
            .name(FIRST_READ_THREAD.to_string())
            .spawn(move || {
                daemon.read_for_the_first_time(pending);
                daemon.checking.store(false, Ordering::SeqCst);
            });
        if started.is_err() {
            say!("the thread that makes the first reads could not be started");
            self.checking.store(false, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// The roots that Need Permission, by their protected class.
    fn pending_classes(&self) -> BTreeMap<LocationClass, Vec<PathBuf>> {
        let home = self.machine.home().to_path_buf();
        let state = self.state.lock().expect("the state is not poisoned");
        let mut pending: BTreeMap<LocationClass, Vec<PathBuf>> = BTreeMap::new();
        for project in &state.overview.projects {
            if project.check != ProjectCheck::NeedsPermission {
                continue;
            }
            let root = PathBuf::from(&project.root);
            let class = classify(&home, &root);
            if class.is_protected() {
                pending.entry(class).or_default().push(root);
            }
        }
        pending
    }

    /// Reads one root of each class, remembers each class that answered and
    /// asks for the Full Scan that reads their projects. A root that is gone
    /// gives way to the next root of its class.
    fn read_for_the_first_time(self: &Arc<Daemon>, pending: BTreeMap<LocationClass, Vec<PathBuf>>) {
        let mut granted = Vec::new();
        for (class, roots) in pending {
            for root in roots {
                match self.tuning.folders.read(&root) {
                    Ok(()) => {
                        say!("{} is readable: {}", class.as_str(), root.display());
                        granted.push(class);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        say!(
                            "{} is not readable yet ({}): {}",
                            class.as_str(),
                            match is_denied(&error) {
                                true => "the operating system did not allow it",
                                false => "the read failed",
                            },
                            root.display()
                        );
                        break;
                    }
                }
            }
        }
        if granted.is_empty() {
            return;
        }
        {
            let mut state = self.state.lock().expect("the state is not poisoned");
            for class in granted {
                state.readable_classes.insert(class.as_str().to_string());
            }
            self.write_state(&state);
        }
        self.scan_behind(Trigger::ScanNow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const HOME: &str = "/Users/someone";

    fn class_of(path: &str) -> LocationClass {
        classify(Path::new(HOME), Path::new(path))
    }

    #[test]
    fn the_home_folders_the_system_asks_about_are_their_own_classes() {
        assert_eq!(
            class_of("/Users/someone/Documents/app"),
            LocationClass::Documents
        );
        assert_eq!(
            class_of("/Users/someone/Documents"),
            LocationClass::Documents
        );
        assert_eq!(
            class_of("/Users/someone/Desktop/demo"),
            LocationClass::Desktop
        );
        assert_eq!(
            class_of("/Users/someone/Downloads/x/y"),
            LocationClass::Downloads
        );
    }

    #[test]
    fn icloud_drive_and_every_file_provider_are_one_class() {
        assert_eq!(
            class_of("/Users/someone/Library/Mobile Documents/com~apple~CloudDocs/app"),
            LocationClass::FileProvider
        );
        assert_eq!(
            class_of("/Users/someone/Library/CloudStorage/GoogleDrive-someone@example.invalid/app"),
            LocationClass::FileProvider
        );
        assert_eq!(
            class_of("/Users/someone/Library/CloudStorage/Dropbox/app"),
            LocationClass::FileProvider
        );
        assert_eq!(
            class_of("/Users/someone/Library/Application Support/app"),
            LocationClass::Unprotected,
            "other Application Support directories are outside the consent"
        );
    }

    #[test]
    fn mounted_volumes_and_shares_are_their_own_classes() {
        assert_eq!(
            class_of("/Volumes/STICK/app"),
            LocationClass::RemovableVolumes
        );
        assert_eq!(
            class_of("/Network/Servers/nas/app"),
            LocationClass::NetworkVolumes
        );
        assert_eq!(class_of("/net/nas/app"), LocationClass::NetworkVolumes);
    }

    #[test]
    fn the_developer_folder_and_the_rest_of_the_disk_are_unprotected() {
        assert_eq!(
            class_of("/Users/someone/Developer/app"),
            LocationClass::Unprotected
        );
        assert_eq!(
            class_of("/Users/someone/code/app"),
            LocationClass::Unprotected
        );
        assert_eq!(class_of("/Users/someone"), LocationClass::Unprotected);
        assert_eq!(class_of("/opt/work/app"), LocationClass::Unprotected);
        assert_eq!(
            class_of("/Users/someone/Developer/Documents"),
            LocationClass::Unprotected,
            "only the home's own Documents folder is protected"
        );
        assert_eq!(
            class_of("/Users/other/Documents/app"),
            LocationClass::Unprotected
        );
    }

    #[test]
    fn case_dots_and_the_data_volume_prefix_do_not_hide_a_class() {
        assert_eq!(
            class_of("/Users/someone/documents/app"),
            LocationClass::Documents
        );
        assert_eq!(
            class_of("/Users/someone/Developer/../Desktop/app"),
            LocationClass::Desktop
        );
        assert_eq!(
            class_of("/System/Volumes/Data/Users/someone/Downloads/app"),
            LocationClass::Downloads
        );
    }

    #[test]
    fn a_home_on_a_volume_of_its_own_keeps_its_folder_classes() {
        let home = Path::new("/Volumes/Work/someone");
        assert_eq!(
            classify(home, Path::new("/Volumes/Work/someone/Documents/app")),
            LocationClass::Documents
        );
        assert_eq!(
            classify(home, Path::new("/Volumes/Work/someone/Developer/app")),
            LocationClass::RemovableVolumes
        );
    }

    #[test]
    fn every_protected_class_reads_back_and_the_unprotected_one_never_does() {
        for class in LocationClass::PROTECTED {
            assert!(class.is_protected());
            assert_eq!(LocationClass::parse(class.as_str()), Some(class));
        }
        assert_eq!(LocationClass::parse("unprotected"), None);
        assert_eq!(LocationClass::parse("photos"), None);
    }

    /// A handle that records every root it is asked to open and answers the
    /// way it was told to.
    struct Recording {
        opened: Mutex<Vec<PathBuf>>,
        answer: fn() -> io::Result<()>,
    }

    impl Folders for Recording {
        fn read(&self, root: &Path) -> io::Result<()> {
            self.opened
                .lock()
                .expect("not poisoned")
                .push(root.to_path_buf());
            (self.answer)()
        }
    }

    fn recording(answer: fn() -> io::Result<()>) -> Recording {
        Recording {
            opened: Mutex::new(Vec::new()),
            answer,
        }
    }

    #[test]
    fn a_class_never_read_before_is_not_touched() {
        let folders = recording(|| Ok(()));
        let readable = BTreeSet::new();
        let access = Access {
            readable: &readable,
            folders: &folders,
        };
        assert_eq!(
            access.reach(Path::new(HOME), Path::new("/Users/someone/Documents/app")),
            Reach::NeedsPermission
        );
        assert!(folders.opened.lock().expect("not poisoned").is_empty());
    }

    #[test]
    fn a_class_read_before_is_read_and_a_denial_needs_permission_again() {
        let readable = BTreeSet::from([LocationClass::Documents]);
        let root = Path::new("/Users/someone/Documents/app");

        let granted = recording(|| Ok(()));
        let access = Access {
            readable: &readable,
            folders: &granted,
        };
        assert_eq!(access.reach(Path::new(HOME), root), Reach::Read);
        assert_eq!(*granted.opened.lock().expect("not poisoned"), vec![root]);

        let denied = recording(|| Err(io::Error::from_raw_os_error(libc::EPERM)));
        let access = Access {
            readable: &readable,
            folders: &denied,
        };
        assert_eq!(access.reach(Path::new(HOME), root), Reach::NeedsPermission);

        let gone = recording(|| Err(io::Error::from_raw_os_error(libc::ENOENT)));
        let access = Access {
            readable: &readable,
            folders: &gone,
        };
        assert_eq!(access.reach(Path::new(HOME), root), Reach::Gone);
    }

    #[test]
    fn plain_file_permissions_are_not_a_missing_consent() {
        assert!(is_denied(&io::Error::from_raw_os_error(libc::EPERM)));
        assert!(!is_denied(&io::Error::from_raw_os_error(libc::EACCES)));
    }

    #[test]
    fn an_unprotected_root_is_never_read_through_the_handle() {
        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let folders = recording(|| Ok(()));
        let readable = BTreeSet::new();
        let access = Access {
            readable: &readable,
            folders: &folders,
        };
        let home = temporary.path();
        assert_eq!(access.reach(home, home), Reach::Read);
        assert_eq!(access.reach(home, &home.join("missing")), Reach::Gone);
        assert!(folders.opened.lock().expect("not poisoned").is_empty());
    }

    #[test]
    fn the_baseline_proves_only_the_classes_its_verified_records_were_read_from() {
        let records = [
            ("/Users/someone/Documents/app/CLAUDE.md", Origin::Verified),
            ("/Users/someone/Developer/tool/CLAUDE.md", Origin::Verified),
            (
                "/Users/someone/Desktop/demo/CLAUDE.md",
                Origin::UnverifiedOrigin,
            ),
            ("", Origin::Verified),
        ];
        assert_eq!(
            proven_by(Path::new(HOME), records),
            BTreeSet::from([LocationClass::Documents])
        );
    }

    #[test]
    fn the_state_files_names_read_back_as_classes() {
        let names = ["documents".to_string(), "photos".to_string()];
        assert_eq!(
            remembered(&names),
            BTreeSet::from([LocationClass::Documents])
        );
    }
}
