//! The daemon watching its own executable and the bundle around it.
//!
//! An update replaces the app bundle while the daemon from the old one is
//! still running, and a drag to the Trash takes the bundle away from under it.
//! Spec section 9.5 settles both: a bundle that was replaced means finish the
//! work in hand and exit, so `KeepAlive` starts the new binary; a bundle that
//! is gone means exit cleanly for good. The version handshake the app makes at
//! every launch is the backstop for anything this misses.
//!
//! Two things live here, kept apart the way the Scan watcher keeps them.
//! [`judge`] is plain logic: two [`Snapshot`]s go in and a [`Change`] comes out,
//! and it is unit-tested against a temporary directory. [`watch`] is the thin
//! part around it: FSEvents on the folder the bundle sits in, a slow look
//! every few minutes behind it in case an event was dropped, on a thread of
//! its own and never the Scan watcher's.
//!
//! Only a daemon inside an app bundle is watched. A developer's daemon runs
//! out of the build directory, where every rebuild replaces the binary, and
//! the only thing it could do about that is stop in the middle of a hand run.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};

/// How long a bundle that vanished is given to come back before it counts as
/// gone. An update that moves the old bundle aside and the new one into its
/// place leaves a moment with no bundle at all, and that moment is not an
/// uninstall.
pub const GRACE: Duration = Duration::from_secs(10);

/// How often the bundle is looked at when no event arrived, in case one was
/// dropped. It is a handful of `stat` calls.
pub const BACKSTOP: Duration = Duration::from_secs(300);

/// The exit status of a daemon whose bundle was replaced.
///
/// It is not zero on purpose. The launch agent keeps the daemon alive only
/// when it did not exit successfully (`KeepAlive` with `SuccessfulExit` false),
/// so this status is what makes launchd start the new binary, and the zero a
/// daemon whose bundle is gone exits with is what keeps it down for good.
/// 75 is `EX_TEMPFAIL`: try again, which is what launchd is asked to do.
pub const EXIT_REPLACED: u8 = 75;

/// What is running: the executable, and the app bundle that encloses it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Own {
    /// The daemon's own executable.
    pub executable: PathBuf,
    /// The `.app` directory it sits in, as `Contents/MacOS/agentsweepd`.
    pub bundle: PathBuf,
}

impl Own {
    /// The executable and its bundle, or nothing when the executable does not
    /// sit at `<name>.app/Contents/MacOS/` inside one.
    pub fn of(executable: &Path) -> Option<Own> {
        let macos = executable.parent()?;
        let contents = macos.parent()?;
        let bundle = contents.parent()?;
        let is_bundle = macos.file_name()? == "MacOS"
            && contents.file_name()? == "Contents"
            && bundle.extension()? == "app";
        is_bundle.then(|| Own {
            executable: executable.to_path_buf(),
            bundle: bundle.to_path_buf(),
        })
    }

    /// The running daemon's own, when it runs out of a bundle.
    pub fn this_process() -> Option<Own> {
        Own::of(&std::env::current_exe().ok()?)
    }

    /// The bundle's `Info.plist`, which carries its version.
    pub fn info_plist(&self) -> PathBuf {
        self.bundle.join("Contents").join("Info.plist")
    }

    /// What the executable and the bundle are right now.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            executable: FileId::of(&self.executable),
            bundle: FileId::of(&self.bundle),
            info_plist: std::fs::read(self.info_plist()).ok(),
        }
    }
}

/// Which file a path names: its device and inode. A replaced file is a new
/// inode at the same path, whatever its bytes are.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileId {
    device: u64,
    inode: u64,
}

impl FileId {
    fn of(path: &Path) -> Option<FileId> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        Some(FileId {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

/// The executable and the bundle at one moment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// The executable, absent when there is nothing at its path.
    pub executable: Option<FileId>,
    /// The bundle directory, absent when there is nothing at its path.
    pub bundle: Option<FileId>,
    /// The bytes of the bundle's `Info.plist`, which change with its version.
    pub info_plist: Option<Vec<u8>>,
}

/// What happened to the bundle since the daemon started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change {
    /// Nothing: the same executable in the same bundle at the same version.
    Same,
    /// A new executable, a new bundle or a new version at the same place.
    Replaced,
    /// No bundle at its place any more: dragged to the Trash or uninstalled.
    Gone,
}

/// Compares the bundle now with the bundle the daemon started from.
pub fn judge(started: &Snapshot, now: &Snapshot) -> Change {
    if now.bundle.is_none() {
        return Change::Gone;
    }
    if now.executable != started.executable
        || now.bundle != started.bundle
        || now.info_plist != started.info_plist
    {
        return Change::Replaced;
    }
    Change::Same
}

/// Looks again after the grace a vanished bundle is given, and answers with
/// what the second look found. A bundle that came back in the meantime was
/// replaced, or was moved away and back, and the second look says which.
pub fn settle(first: Change, grace: Duration, mut look_again: impl FnMut() -> Change) -> Change {
    if first != Change::Gone {
        return first;
    }
    std::thread::sleep(grace);
    look_again()
}

/// A running watch on the bundle. Dropping it stops the watch.
pub struct BundleWatch {
    _watcher: Option<RecommendedWatcher>,
    _thread: std::thread::JoinHandle<()>,
}

impl std::fmt::Debug for BundleWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleWatch").finish_non_exhaustive()
    }
}

/// Watches `own` and calls `then` once, with the first change that is not
/// [`Change::Same`]. The thread ends after that: a daemon whose bundle changed
/// is on its way out.
pub fn watch(
    own: Own,
    grace: Duration,
    backstop: Duration,
    then: impl FnOnce(Change) + Send + 'static,
) -> BundleWatch {
    let started = own.snapshot();
    let (sender, receiver) = channel::<()>();
    // FSEvents on the folder the bundle sits in, because a bundle that is
    // replaced whole is a new directory, and a stream on the old one would
    // follow it to wherever it was moved. A watcher that will not start
    // leaves the backstop, which still notices, only later.
    let bundle = own.bundle.clone();
    let watcher = own.bundle.parent().and_then(|folder| {
        let events = sender.clone();
        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
                let ours = match result {
                    Ok(event) => {
                        event.need_rescan()
                            || event.paths.iter().any(|path| path.starts_with(&bundle))
                    }
                    Err(_) => true,
                };
                if ours {
                    let _ = events.send(());
                }
            })
            .ok()?;
        watcher.watch(folder, RecursiveMode::Recursive).ok()?;
        Some(watcher)
    });
    drop(sender);

    let thread = std::thread::Builder::new()
        .name("agentsweep-bundle-watch".to_string())
        .spawn(move || {
            loop {
                match receiver.recv_timeout(backstop) {
                    Ok(()) | Err(RecvTimeoutError::Timeout) => {}
                    // No watcher: the backstop is all there is.
                    Err(RecvTimeoutError::Disconnected) => std::thread::sleep(backstop),
                }
                let change = settle(judge(&started, &own.snapshot()), grace, || {
                    judge(&started, &own.snapshot())
                });
                if change != Change::Same {
                    then(change);
                    return;
                }
            }
        })
        .expect("the bundle watch thread starts");

    BundleWatch {
        _watcher: watcher,
        _thread: thread,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::sync::mpsc;
    use std::time::Instant;

    /// A bundle laid out the way the app ships: the daemon at
    /// `Contents/MacOS/agentsweepd` and a version in `Contents/Info.plist`.
    fn bundle_in(folder: &Path, version: &str) -> Own {
        let bundle = folder.join("AgentSweep.app");
        let macos = bundle.join("Contents").join("MacOS");
        fs::create_dir_all(&macos).expect("a bundle");
        fs::write(macos.join("agentsweepd"), b"the daemon").expect("an executable");
        fs::write(
            bundle.join("Contents").join("Info.plist"),
            format!(
                "<plist><dict><key>CFBundleVersion</key><string>{version}</string></dict></plist>"
            ),
        )
        .expect("an Info.plist");
        Own::of(&macos.join("agentsweepd")).expect("a daemon inside a bundle")
    }

    #[test]
    fn only_a_daemon_inside_an_app_bundle_has_a_bundle_to_watch() {
        let own = Own::of(Path::new(
            "/Applications/AgentSweep.app/Contents/MacOS/agentsweepd",
        ))
        .expect("a bundle");
        assert_eq!(own.bundle, PathBuf::from("/Applications/AgentSweep.app"));
        assert_eq!(
            own.info_plist(),
            PathBuf::from("/Applications/AgentSweep.app/Contents/Info.plist")
        );
        assert_eq!(Own::of(Path::new("/repo/target/debug/agentsweepd")), None);
        assert_eq!(
            Own::of(Path::new("/x/AgentSweep/Contents/MacOS/agentsweepd")),
            None
        );
        assert_eq!(Own::of(Path::new("agentsweepd")), None);
    }

    #[test]
    fn a_bundle_nobody_touched_is_the_same() {
        let folder = tempfile::tempdir().expect("a temporary directory");
        let own = bundle_in(folder.path(), "0.1.0");
        let started = own.snapshot();
        assert_eq!(judge(&started, &own.snapshot()), Change::Same);
    }

    /// An updater that swaps the whole bundle for a new one: a new directory
    /// at the same path.
    #[test]
    fn a_bundle_swapped_for_a_new_one_is_replaced() {
        let folder = tempfile::tempdir().expect("a temporary directory");
        let own = bundle_in(folder.path(), "0.1.0");
        let started = own.snapshot();

        let staging = tempfile::tempdir_in(folder.path()).expect("a staging directory");
        bundle_in(staging.path(), "0.1.0");
        fs::rename(&own.bundle, folder.path().join("old.app")).expect("the old bundle moved");
        fs::rename(staging.path().join("AgentSweep.app"), &own.bundle).expect("the new one in");

        assert_eq!(judge(&started, &own.snapshot()), Change::Replaced);
    }

    /// An update in place: a new executable written over the old path.
    #[test]
    fn a_new_executable_at_the_same_path_is_replaced() {
        let folder = tempfile::tempdir().expect("a temporary directory");
        let own = bundle_in(folder.path(), "0.1.0");
        let started = own.snapshot();
        let fresh = own.executable.with_file_name("agentsweepd.new");
        fs::write(&fresh, b"the new daemon").expect("a new executable");
        fs::rename(&fresh, &own.executable).expect("the new executable in place");
        assert_eq!(judge(&started, &own.snapshot()), Change::Replaced);
    }

    #[test]
    fn a_new_bundle_version_is_replaced() {
        let folder = tempfile::tempdir().expect("a temporary directory");
        let own = bundle_in(folder.path(), "0.1.0");
        let started = own.snapshot();
        fs::write(
            own.info_plist(),
            "<plist><dict><key>CFBundleVersion</key><string>0.2.0</string></dict></plist>",
        )
        .expect("a new version");
        assert_eq!(judge(&started, &own.snapshot()), Change::Replaced);
    }

    /// Dragged to the Trash: nothing at the bundle's path any more.
    #[test]
    fn a_bundle_moved_away_is_gone() {
        let folder = tempfile::tempdir().expect("a temporary directory");
        let own = bundle_in(folder.path(), "0.1.0");
        let started = own.snapshot();
        let trash = folder.path().join(".Trash");
        fs::create_dir_all(&trash).expect("a trash");
        fs::rename(&own.bundle, trash.join("AgentSweep.app")).expect("the bundle trashed");
        assert_eq!(judge(&started, &own.snapshot()), Change::Gone);
    }

    /// The moment in an update with no bundle at all is not an uninstall: the
    /// second look finds the new bundle and says replaced.
    #[test]
    fn a_bundle_that_comes_back_within_the_grace_was_replaced_not_removed() {
        let folder = tempfile::tempdir().expect("a temporary directory");
        let own = bundle_in(folder.path(), "0.1.0");
        let started = own.snapshot();
        fs::rename(&own.bundle, folder.path().join("aside.app")).expect("the bundle moved aside");
        let first = judge(&started, &own.snapshot());
        assert_eq!(first, Change::Gone);

        let settled = settle(first, Duration::from_millis(1), || {
            bundle_in(folder.path(), "0.2.0");
            judge(&started, &own.snapshot())
        });
        assert_eq!(settled, Change::Replaced);

        let gone = settle(Change::Gone, Duration::from_millis(1), || Change::Gone);
        assert_eq!(gone, Change::Gone);
        assert_eq!(
            settle(Change::Same, Duration::from_secs(3600), || unreachable!()),
            Change::Same
        );
    }

    /// The watch itself, end to end on a temporary bundle: a replacement is
    /// reported once and promptly.
    #[test]
    fn the_watch_reports_a_replaced_bundle() {
        let folder = tempfile::tempdir().expect("a temporary directory");
        let own = bundle_in(folder.path(), "0.1.0");
        let (sender, receiver) = mpsc::channel();
        let _watch = watch(
            own.clone(),
            Duration::from_millis(50),
            Duration::from_millis(200),
            move |change| {
                let _ = sender.send(change);
            },
        );
        std::thread::sleep(Duration::from_millis(100));
        let began = Instant::now();
        fs::write(
            own.info_plist(),
            "<plist><dict><key>CFBundleVersion</key><string>0.2.0</string></dict></plist>",
        )
        .expect("a new version");
        let change = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("a change within ten seconds");
        assert_eq!(change, Change::Replaced);
        assert!(began.elapsed() < Duration::from_secs(10));
    }
}
