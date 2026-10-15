//! **Install command line tool** (spec section 8.10): a symbolic link to the
//! `agentsweep` binary inside the bundle, at `~/.local/bin/agentsweep`.
//!
//! No admin prompt: the directory belongs to the user, and the app creates it
//! when it is absent. The app writes that one link and nothing else, never a
//! shell profile. Where the directory is not on the PATH the app was given,
//! the answer carries the line the user may add to their profile.
//!
//! A link is AgentSweep's own when it points at an `agentsweep` binary in the
//! `Contents/MacOS` directory of an app bundle: that is what this module
//! writes, and a link left behind by a moved or older copy of the app is
//! replaced. Anything else at that place, a file, a directory, or a link to
//! another `agentsweep` (a `cargo install`, say), is the user's and is never
//! overwritten.
//!
//! Every function takes the home directory, the binary and the PATH it works
//! with, so the suite runs on a temporary home.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::launch_agent::CLI_BINARY;

/// The directory the link goes in, relative to the home directory.
pub const LINK_DIRECTORY: &str = ".local/bin";

/// The line that puts the directory on the PATH, for the user's profile.
pub const PATH_LINE: &str = "export PATH=\"$HOME/.local/bin:$PATH\"";

/// What installing did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The link was made.
    Created,
    /// A link of AgentSweep's own that pointed elsewhere was replaced.
    Replaced,
    /// The link was already there, pointing at this binary.
    AlreadyThere,
}

/// The answer to **Install command line tool**.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Installed {
    /// What was done.
    pub outcome: Outcome,
    /// The link.
    pub link: PathBuf,
    /// The line to add to a shell profile, present when the directory is not
    /// on the PATH given.
    pub path_line: Option<&'static str>,
}

impl Installed {
    /// The sentences the Settings pane shows for it.
    pub fn lines(&self) -> Vec<String> {
        let mut lines =
            vec![match self.outcome {
            Outcome::Created => "The command line tool is installed: agentsweep in ~/.local/bin.",
            Outcome::Replaced => {
                "The command line tool is installed: agentsweep in ~/.local/bin now points at \
                 this copy of AgentSweep."
            }
            Outcome::AlreadyThere => {
                "The command line tool was already installed: agentsweep in ~/.local/bin."
            }
        }
        .to_string()];
        if let Some(line) = self.path_line {
            lines.push(
                "~/.local/bin is not on the PATH AgentSweep was started with. If a new \
                 terminal does not find agentsweep, add this line to your shell profile, \
                 such as ~/.zshrc:"
                    .to_string(),
            );
            lines.push(line.to_string());
        }
        lines
    }
}

/// Why nothing was installed.
#[derive(Debug)]
pub enum Refused {
    /// This copy of AgentSweep carries no command line tool.
    NoBinary(PathBuf),
    /// Something that is not AgentSweep's own link is at the place.
    Occupied(PathBuf),
    /// The file system said no.
    Io(io::Error),
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refused::NoBinary(_) => write!(
                f,
                "This copy of AgentSweep carries no command line tool, so nothing was installed."
            ),
            Refused::Occupied(_) => write!(
                f,
                "Something else is already at ~/.local/bin/agentsweep, so AgentSweep left it \
                 as it is and installed nothing. Move it away and try again."
            ),
            Refused::Io(error) => write!(
                f,
                "The command line tool could not be installed: {error}. Nothing was changed."
            ),
        }
    }
}

impl From<io::Error> for Refused {
    fn from(error: io::Error) -> Refused {
        Refused::Io(error)
    }
}

/// The binary beside the app's own executable: Tauri puts every sidecar in
/// `Contents/MacOS` (see [`crate::launch_agent::bundle_program`]).
pub fn bundled_cli(app_executable: &Path) -> Option<PathBuf> {
    Some(app_executable.parent()?.join(CLI_BINARY))
}

/// The link under `home`.
pub fn link_path(home: &Path) -> PathBuf {
    home.join(LINK_DIRECTORY).join(CLI_BINARY)
}

/// True when `target` is where AgentSweep links to: an `agentsweep` binary in
/// the `Contents/MacOS` directory of an app bundle. Whether it still exists
/// does not matter; a link into a bundle that moved is still AgentSweep's.
pub fn is_own_target(target: &Path) -> bool {
    let mut up = target.iter().rev();
    up.next() == Some(OsStr::new(CLI_BINARY))
        && up.next() == Some(OsStr::new("MacOS"))
        && up.next() == Some(OsStr::new("Contents"))
        && up
            .next()
            .and_then(|bundle| Path::new(bundle).extension())
            .is_some_and(|extension| extension == "app")
}

/// True when `directory` is one of the entries of `path`, a PATH value.
pub fn on_path(directory: &Path, path: Option<&OsStr>) -> bool {
    let Some(path) = path else {
        return false;
    };
    std::env::split_paths(path).any(|entry| {
        !entry.as_os_str().is_empty() && strip_trailing(&entry) == strip_trailing(directory)
    })
}

fn strip_trailing(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Installs the link to `cli` under `home`, given the PATH the app runs with.
pub fn install(home: &Path, cli: &Path, path: Option<&OsStr>) -> Result<Installed, Refused> {
    if !cli.is_file() {
        return Err(Refused::NoBinary(cli.to_path_buf()));
    }
    let directory = home.join(LINK_DIRECTORY);
    let link = link_path(home);
    let outcome = match std::fs::symlink_metadata(&link) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(&directory)?;
            symlink(cli, &link)?;
            Outcome::Created
        }
        Err(error) => return Err(Refused::Io(error)),
        Ok(found) if found.file_type().is_symlink() => {
            let target = std::fs::read_link(&link)?;
            if target == cli {
                Outcome::AlreadyThere
            } else if is_own_target(&target) {
                // A new link beside it, renamed over it: the place is never
                // empty and never holds anything but a link.
                let fresh = directory.join(format!(".{CLI_BINARY}.{}", std::process::id()));
                let _ = std::fs::remove_file(&fresh);
                symlink(cli, &fresh)?;
                if let Err(error) = std::fs::rename(&fresh, &link) {
                    let _ = std::fs::remove_file(&fresh);
                    return Err(Refused::Io(error));
                }
                Outcome::Replaced
            } else {
                return Err(Refused::Occupied(link));
            }
        }
        Ok(_) => return Err(Refused::Occupied(link)),
    };
    Ok(Installed {
        outcome,
        link,
        path_line: match on_path(&directory, path) {
            true => None,
            false => Some(PATH_LINE),
        },
    })
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symbolic links are made on macOS only",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    use std::ffi::OsString;

    /// A temporary home and an app bundle beside it carrying the binary.
    struct Machine {
        root: tempfile::TempDir,
    }

    impl Machine {
        fn new() -> Machine {
            let machine = Machine {
                root: tempfile::tempdir().expect("a temporary directory"),
            };
            std::fs::create_dir_all(machine.home()).expect("a home");
            machine
        }

        fn home(&self) -> PathBuf {
            self.root.path().join("home")
        }

        /// The binary inside a bundle called `name`.
        fn bundle(&self, name: &str) -> PathBuf {
            let macos = self.root.path().join(name).join("Contents/MacOS");
            std::fs::create_dir_all(&macos).expect("a bundle");
            let cli = macos.join(CLI_BINARY);
            std::fs::write(&cli, b"#!/bin/sh\necho agentsweep\n").expect("a binary");
            cli
        }

        fn path_with(&self, entries: &[PathBuf]) -> OsString {
            std::env::join_paths(entries).expect("a PATH")
        }
    }

    #[test]
    fn the_link_is_made_in_a_new_local_bin_pointing_at_the_bundle() {
        let machine = Machine::new();
        let cli = machine.bundle("AgentSweep.app");
        let installed = install(&machine.home(), &cli, None).expect("installed");
        assert_eq!(installed.outcome, Outcome::Created);
        let link = machine.home().join(".local/bin/agentsweep");
        assert_eq!(installed.link, link);
        assert_eq!(std::fs::read_link(&link).expect("a link"), cli);
        // Nothing else was written: the directory holds the link alone.
        let entries: Vec<_> = std::fs::read_dir(machine.home().join(".local/bin"))
            .expect("the directory")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(entries, vec![OsString::from("agentsweep")]);
        // And no shell profile was touched.
        assert!(!machine.home().join(".zshrc").exists());
        assert!(!machine.home().join(".zprofile").exists());
    }

    #[test]
    fn a_stale_link_of_its_own_is_replaced_and_a_current_one_kept() {
        let machine = Machine::new();
        let old = machine.bundle("Old/AgentSweep.app");
        let cli = machine.bundle("AgentSweep.app");
        install(&machine.home(), &old, None).expect("the old link");
        // The old copy is gone; its link dangles and is still AgentSweep's.
        std::fs::remove_dir_all(machine.root.path().join("Old")).expect("removed");

        let installed = install(&machine.home(), &cli, None).expect("replaced");
        assert_eq!(installed.outcome, Outcome::Replaced);
        assert_eq!(std::fs::read_link(&installed.link).expect("a link"), cli);

        let again = install(&machine.home(), &cli, None).expect("kept");
        assert_eq!(again.outcome, Outcome::AlreadyThere);
        assert_eq!(std::fs::read_link(&again.link).expect("a link"), cli);
        let entries = std::fs::read_dir(machine.home().join(".local/bin"))
            .expect("the directory")
            .count();
        assert_eq!(entries, 1, "no temporary link is left behind");
    }

    #[test]
    fn what_is_not_its_own_link_is_never_overwritten() {
        let machine = Machine::new();
        let cli = machine.bundle("AgentSweep.app");
        let bin = machine.home().join(".local/bin");
        std::fs::create_dir_all(&bin).expect("the directory");
        let link = bin.join("agentsweep");

        // A file of the user's.
        std::fs::write(&link, b"mine").expect("a file");
        assert!(matches!(
            install(&machine.home(), &cli, None),
            Err(Refused::Occupied(_))
        ));
        assert_eq!(std::fs::read(&link).expect("still there"), b"mine");
        std::fs::remove_file(&link).expect("removed");

        // A link to another agentsweep, such as a cargo install.
        let cargo = machine.home().join(".cargo/bin/agentsweep");
        std::fs::create_dir_all(cargo.parent().expect("a parent")).expect("a directory");
        std::fs::write(&cargo, b"cargo").expect("a binary");
        std::os::unix::fs::symlink(&cargo, &link).expect("a link");
        let refused = install(&machine.home(), &cli, None).expect_err("refused");
        assert!(matches!(refused, Refused::Occupied(_)));
        assert!(refused.to_string().contains("left it as it is"));
        assert_eq!(std::fs::read_link(&link).expect("still a link"), cargo);
        std::fs::remove_file(&link).expect("removed");

        // A directory.
        std::fs::create_dir(&link).expect("a directory");
        assert!(matches!(
            install(&machine.home(), &cli, None),
            Err(Refused::Occupied(_))
        ));
        assert!(link.is_dir());
    }

    #[test]
    fn a_bundle_without_the_binary_installs_nothing() {
        let machine = Machine::new();
        let missing = machine
            .root
            .path()
            .join("Dev.app/Contents/MacOS/agentsweep");
        assert!(matches!(
            install(&machine.home(), &missing, None),
            Err(Refused::NoBinary(_))
        ));
        assert!(!machine.home().join(".local").exists());
    }

    #[test]
    fn the_path_line_is_reported_only_when_the_directory_is_not_on_the_path() {
        let machine = Machine::new();
        let cli = machine.bundle("AgentSweep.app");
        let bin = machine.home().join(".local/bin");

        let without = machine.path_with(&[PathBuf::from("/usr/bin"), PathBuf::from("/bin")]);
        let installed = install(&machine.home(), &cli, Some(&without)).expect("installed");
        assert_eq!(installed.path_line, Some(PATH_LINE));
        let lines = installed.lines();
        assert_eq!(lines.last().expect("a line"), PATH_LINE);
        assert_eq!(PATH_LINE, "export PATH=\"$HOME/.local/bin:$PATH\"");

        let with = machine.path_with(&[PathBuf::from("/usr/bin"), bin.clone()]);
        let installed = install(&machine.home(), &cli, Some(&with)).expect("installed");
        assert_eq!(installed.path_line, None);
        assert_eq!(installed.lines().len(), 1);

        // A trailing slash is the same directory; no PATH at all is not on it.
        let slashed = OsString::from(format!("/bin:{}/", bin.display()));
        assert!(on_path(&bin, Some(&slashed)));
        assert!(!on_path(&bin, None));
        assert!(!on_path(&bin, Some(OsStr::new(""))));
    }

    #[test]
    fn its_own_target_is_the_binary_inside_an_app_bundle() {
        assert!(is_own_target(Path::new(
            "/Applications/AgentSweep.app/Contents/MacOS/agentsweep"
        )));
        assert!(is_own_target(Path::new(
            "/Users/x/Downloads/AgentSweep 2.app/Contents/MacOS/agentsweep"
        )));
        assert!(!is_own_target(Path::new("/Users/x/.cargo/bin/agentsweep")));
        assert!(!is_own_target(Path::new(
            "/Applications/AgentSweep.app/Contents/MacOS/agentsweepd"
        )));
        assert!(!is_own_target(Path::new("/Contents/MacOS/agentsweep")));
        assert_eq!(
            bundled_cli(Path::new(
                "/Applications/AgentSweep.app/Contents/MacOS/agentsweep-menubar"
            )),
            Some(PathBuf::from(
                "/Applications/AgentSweep.app/Contents/MacOS/agentsweep"
            ))
        );
    }
}
