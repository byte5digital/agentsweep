//! `agentsweep uninstall [--keep | --restore-all | --delete-everything]`:
//! Uninstall from the command line (spec section 9.6).
//!
//! It sends the daemon the same `uninstall` request the Settings flow sends,
//! with the same default, Keep. The daemon does everything that touches the
//! Agents and the stores: it takes the Gate's entries and the Codex pin away,
//! then keeps, restores or deletes what is in quarantine.
//!
//! Then it does what the Settings flow does next. The daemon and the login
//! item are registrations of the app through SMAppService, which the app's
//! own executable takes off, so this command runs that executable from its
//! own bundle with [`FINISH`]: it quits a running AgentSweep and unregisters
//! both, which stops the daemon. This command waits for the daemon to go and
//! says what is left. What no process can do for the user, moving the bundle
//! this command runs from to the Trash, it asks for, naming the folder the
//! bundle is in. A daemon that does not answer stops it before anything is
//! touched, as in Settings, since only the daemon can take its hooks out, and
//! the command exits non-zero.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agentsweep_ipc::protocol::{Role, UninstallChoice, UninstallReport};
use agentsweep_ipc::{Client, ClientError};

use crate::actions::{DONE, NOT_DONE, UNREACHABLE};

/// One `uninstall` command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// What happens to what is in quarantine, Keep unless named.
    pub choice: UninstallChoice,
    /// The socket to ask at, the documented one unless named.
    pub socket: Option<PathBuf>,
}

/// The flag of each choice.
fn flag(choice: UninstallChoice) -> &'static str {
    match choice {
        UninstallChoice::RestoreAll => "--restore-all",
        UninstallChoice::Keep => "--keep",
        UninstallChoice::DeleteEverything => "--delete-everything",
    }
}

/// Reads the command line after `uninstall`. At most one choice; none is
/// Keep.
pub fn parse(arguments: &[String]) -> Result<Invocation, String> {
    let mut choice = None;
    let mut socket = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        if argument == "--socket" {
            let path = rest
                .next()
                .ok_or_else(|| "`--socket` takes a path".to_string())?;
            socket = Some(PathBuf::from(path));
            continue;
        }
        let named = UninstallChoice::ALL
            .into_iter()
            .find(|choice| flag(*choice) == argument);
        match (named, choice) {
            (Some(named), None) => choice = Some(named),
            (Some(_), Some(_)) => {
                return Err("`uninstall` takes one of --keep, --restore-all and \
                            --delete-everything"
                    .to_string());
            }
            (None, _) => {
                return Err(format!(
                    "`uninstall` takes --keep, --restore-all or --delete-everything, not \
                     `{argument}`"
                ));
            }
        }
    }
    Ok(Invocation {
        choice: choice.unwrap_or_default(),
        socket,
    })
}

/// The app's own executable, beside this one in `Contents/MacOS`.
pub const APP_EXECUTABLE: &str = "agentsweep-menubar";

/// The flag with which the app's executable quits a running AgentSweep and
/// unregisters the daemon and the login item, then exits.
pub const FINISH: &str = "--finish-uninstall";

/// How long the daemon is given to stop once it is unregistered.
pub const STOP_WAIT: Duration = Duration::from_secs(10);

/// What no daemon answering means: nothing was touched, and what is left.
pub const NOTHING_CHANGED: &str = "Nothing was changed: AgentSweep is not running.\n\
     Its hooks, its data and its background item stay. Open AgentSweep, then run this again.\n";

/// The app bundle this command runs out of.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bundle {
    /// The bundle, `.../AgentSweep.app`.
    pub app: PathBuf,
    /// The app's own executable inside it.
    pub executable: PathBuf,
}

impl Bundle {
    /// The bundle of a command line interface at this path: the nearest
    /// directory above it whose name ends in `.app`. Nothing outside one.
    pub fn of(cli: &Path) -> Option<Bundle> {
        let app = cli.ancestors().skip(1).find(|ancestor| {
            ancestor
                .extension()
                .is_some_and(|extension| extension == "app")
        })?;
        Some(Bundle {
            app: app.to_path_buf(),
            executable: cli.with_file_name(APP_EXECUTABLE),
        })
    }

    /// The bundle of this process, also when it was run through the link in
    /// `~/.local/bin`.
    pub fn of_this_process() -> Option<Bundle> {
        let cli = std::env::current_exe().ok()?.canonicalize().ok()?;
        Bundle::of(&cli)
    }

    /// The folder the bundle is in, which the user drags it out of.
    pub fn folder(&self) -> &Path {
        self.app.parent().unwrap_or(Path::new("/"))
    }
}

/// Asks the daemon, finishes as the Settings flow does, and says what it did
/// and what is left.
pub fn run(invocation: &Invocation) -> (String, u8) {
    run_in(invocation, Bundle::of_this_process().as_ref(), STOP_WAIT)
}

/// The same, for a bundle of the caller's choosing.
pub fn run_in(invocation: &Invocation, bundle: Option<&Bundle>, wait: Duration) -> (String, u8) {
    let asked =
        connect(&invocation.socket).and_then(|mut client| client.uninstall(invocation.choice));
    let report = match asked {
        Ok(report) => report,
        Err(ClientError::Unreachable(_)) => return (NOTHING_CHANGED.to_string(), UNREACHABLE),
        Err(error) => {
            return (
                format!("Nothing was changed: AgentSweep could not be asked ({error}).\n"),
                NOT_DONE,
            );
        }
    };
    let left = match bundle {
        Some(bundle) => finish(bundle, &invocation.socket, wait),
        // A developer run outside a bundle registered nothing.
        None => Vec::new(),
    };
    let code = match report.complete() && left.is_empty() {
        true => DONE,
        false => NOT_DONE,
    };
    (render(&report, &left, bundle), code)
}

fn connect(socket: &Option<PathBuf>) -> Result<Client, ClientError> {
    match socket {
        Some(socket) => Client::connect_at(socket, Role::Cli),
        None => Client::connect(Role::Cli),
    }
}

/// Runs the app's executable with [`FINISH`] and waits for the daemon to
/// stop. Answers what is left, one line each, and nothing when all is done.
fn finish(bundle: &Bundle, socket: &Option<PathBuf>, wait: Duration) -> Vec<String> {
    let ran = Command::new(&bundle.executable)
        .arg(FINISH)
        .stdin(Stdio::null())
        .output();
    let output = match ran {
        Ok(output) => output,
        Err(error) => {
            return vec![format!(
                "the daemon and the login item could not be unregistered: {error}"
            )];
        }
    };
    if !output.status.success() {
        let said: Vec<String> = String::from_utf8_lossy(&output.stderr)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        return match said.is_empty() {
            true => vec!["the daemon and the login item could not be unregistered".to_string()],
            false => said,
        };
    }
    match stopped(socket, wait) {
        true => Vec::new(),
        false => vec!["the daemon still runs".to_string()],
    }
}

/// True once no daemon answers at the socket, waiting at most `wait`.
fn stopped(socket: &Option<PathBuf>, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if matches!(connect(socket), Err(ClientError::Unreachable(_))) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The step left to the user: drag AgentSweep out of its folder to the
/// Trash, quitting it first where it may still be open, since macOS refuses
/// to trash an app that is open.
pub fn last_step(bundle: Option<&Bundle>, stopped: bool) -> String {
    match (bundle, stopped) {
        (Some(bundle), true) => format!(
            "AgentSweep has stopped. Now drag it from {} to the Trash.",
            bundle.folder().display()
        ),
        (Some(bundle), false) => format!(
            "Quit AgentSweep, then drag it from {} to the Trash.",
            bundle.folder().display()
        ),
        (None, _) => "Quit AgentSweep, then drag it to the Trash.".to_string(),
    }
}

/// The report as the terminal shows it: the sentence, one line per Item
/// restored or not, what was deleted, what failed or is left, and the step
/// left to the user.
pub fn render(report: &UninstallReport, left: &[String], bundle: Option<&Bundle>) -> String {
    let mut out = format!("{}\n", report.message);
    for restored in &report.restored {
        out.push_str(&format!(
            "  {} ({}): {}\n",
            restored.item_id, restored.receipt_id, restored.message
        ));
    }
    if !report.deleted.is_empty() {
        out.push_str(&format!("Deleted: {}.\n", report.deleted.join(", ")));
    }
    for failed in report.failed.iter().chain(left) {
        out.push_str(&format!("Not done: {failed}.\n"));
    }
    out.push_str(&last_step(bundle, bundle.is_some() && left.is_empty()));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &[&str]) -> Vec<String> {
        line.iter().map(|word| word.to_string()).collect()
    }

    /// No flag is Keep, the same default as the Settings flow, which sends
    /// the same request through [`Client::uninstall`].
    #[test]
    fn no_flag_is_keep_and_each_flag_names_its_choice() {
        let bare = parse(&[]).expect("a command");
        assert_eq!(bare.choice, UninstallChoice::Keep);
        assert_eq!(bare.choice, UninstallChoice::default());
        for (word, choice) in [
            ("--keep", UninstallChoice::Keep),
            ("--restore-all", UninstallChoice::RestoreAll),
            ("--delete-everything", UninstallChoice::DeleteEverything),
        ] {
            assert_eq!(parse(&words(&[word])).expect("a command").choice, choice);
        }
        assert_eq!(
            parse(&words(&["--socket", "/tmp/a.sock", "--restore-all"])).expect("a command"),
            Invocation {
                choice: UninstallChoice::RestoreAll,
                socket: Some(PathBuf::from("/tmp/a.sock")),
            }
        );
        assert!(parse(&words(&["--keep", "--delete-everything"])).is_err());
        assert!(parse(&words(&["everything"])).is_err());
        assert!(parse(&words(&["--socket"])).is_err());
    }

    /// A temporary folder of one test's own, removed when it is dropped.
    struct Folder(PathBuf);

    impl Folder {
        fn new() -> Folder {
            use std::sync::atomic::{AtomicU32, Ordering};
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "agentsweep-cli-uninstall-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temporary folder");
            Folder(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A socket nothing listens on.
    fn nowhere(name: &str) -> PathBuf {
        let nowhere = std::env::temp_dir().join(format!(
            "agentsweep-uninstall-{name}-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&nowhere);
        nowhere
    }

    /// A bundle in `folder/Apps`, with this command's place in it and a
    /// stand-in for the app's executable that runs `script` under `/bin/sh`.
    fn fake_bundle(folder: &Path, script: &str) -> Bundle {
        use std::os::unix::fs::PermissionsExt as _;

        let macos = folder.join("Apps/AgentSweep.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).expect("a bundle");
        let executable = macos.join(APP_EXECUTABLE);
        std::fs::write(&executable, format!("#!/bin/sh\n{script}\n")).expect("a script");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        Bundle::of(&macos.join("agentsweep")).expect("a bundle")
    }

    /// No daemon: nothing is touched and nothing is run, the exit is
    /// non-zero, and two short lines say so and what is left.
    #[test]
    fn no_daemon_changes_nothing_exits_non_zero_and_says_what_is_left() {
        let folder = Folder::new();
        let marker = folder.path().join("ran");
        let bundle = fake_bundle(folder.path(), &format!("touch '{}'", marker.display()));
        let (rendered, code) = run_in(
            &Invocation {
                choice: UninstallChoice::DeleteEverything,
                socket: Some(nowhere("nobody")),
            },
            Some(&bundle),
            Duration::ZERO,
        );
        assert_ne!(code, DONE);
        assert_eq!(code, UNREACHABLE);
        assert_eq!(rendered.lines().count(), 2, "{rendered}");
        assert!(rendered.starts_with("Nothing was changed"), "{rendered}");
        assert!(
            rendered.contains("Its hooks, its data and its background item stay"),
            "{rendered}"
        );
        assert!(!marker.exists(), "nothing was run");
    }

    #[test]
    fn the_bundle_is_the_nearest_app_above_the_cli_and_its_folder_is_named() {
        let bundle = Bundle::of(Path::new(
            "/Users/someone/agentsweep-hand-check/AgentSweep.app/Contents/MacOS/agentsweep",
        ))
        .expect("a bundle");
        assert_eq!(
            bundle.executable,
            Path::new(
                "/Users/someone/agentsweep-hand-check/AgentSweep.app/Contents/MacOS/agentsweep-menubar"
            )
        );
        assert_eq!(
            bundle.folder(),
            Path::new("/Users/someone/agentsweep-hand-check")
        );
        assert_eq!(Bundle::of(Path::new("/src/target/debug/agentsweep")), None);
    }

    /// The app's executable runs with the finishing flag; what it could not
    /// do comes back line by line, and the last step asks to quit first.
    #[test]
    fn what_the_app_could_not_do_is_left_and_the_text_asks_to_quit_first() {
        let folder = Folder::new();
        let flag = folder.path().join("flag");
        let bundle = fake_bundle(
            folder.path(),
            &format!(
                "echo \"$@\" > '{}'\necho 'AgentSweep did not quit' >&2\nexit 1",
                flag.display()
            ),
        );
        let left = finish(&bundle, &Some(nowhere("unfinished")), Duration::ZERO);
        assert_eq!(left, vec!["AgentSweep did not quit".to_string()]);
        assert_eq!(
            std::fs::read_to_string(&flag).expect("it ran").trim(),
            FINISH
        );
        let rendered = render(
            &UninstallReport {
                message: "AgentSweep's hooks are out of Claude Code and Codex.".to_string(),
                ..UninstallReport::default()
            },
            &left,
            Some(&bundle),
        );
        assert!(
            rendered.contains("Not done: AgentSweep did not quit.\n"),
            "{rendered}"
        );
        assert!(
            rendered.trim_end().ends_with(&format!(
                "Quit AgentSweep, then drag it from {} to the Trash.",
                folder.path().join("Apps").display()
            )),
            "{rendered}"
        );
    }

    /// Once the app's executable has done its part and no daemon answers,
    /// nothing is left and the last step names the bundle's folder.
    #[test]
    fn a_finished_uninstall_names_the_folder_to_drag_agentsweep_from() {
        let folder = Folder::new();
        let bundle = fake_bundle(folder.path(), "exit 0");
        assert!(finish(&bundle, &Some(nowhere("finished")), Duration::ZERO).is_empty());
        let rendered = render(
            &UninstallReport {
                choice: UninstallChoice::DeleteEverything,
                deleted: vec!["the data directory".to_string(), "the caches".to_string()],
                message: "Deleted everything AgentSweep made.".to_string(),
                ..UninstallReport::default()
            },
            &[],
            Some(&bundle),
        );
        assert!(rendered.starts_with("Deleted everything"), "{rendered}");
        assert!(rendered.contains("Deleted: the data directory, the caches."));
        assert!(
            rendered.trim_end().ends_with(&format!(
                "AgentSweep has stopped. Now drag it from {} to the Trash.",
                folder.path().join("Apps").display()
            )),
            "{rendered}"
        );
        assert!(!rendered.contains("Applications"), "{rendered}");
    }
}
