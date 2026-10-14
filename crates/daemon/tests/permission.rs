//! Needs Permission, end to end: a project in a protected location class the
//! daemon has never read is not read, not counted towards an all-clear, and
//! is read only after the user's "Check now" (spec sections 8.6 and 9.7).
//!
//! No test raises a real macOS privacy alert or touches a protected folder of
//! the real user. The home is a temporary directory, so its `Documents`
//! directory stands in for the real one, and every read into a protected
//! class goes through a handle the test hands in, which records the root it
//! is asked to open and answers as the test says: granted, denied with
//! `EPERM`, or blocked the way the system alert may block the call. Nothing
//! touches the real home, the real data directory, the documented socket or
//! the login Keychain.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentsweep_core::baseline::{Baseline, BaselineView};
use agentsweep_core::health::Rung;
use agentsweep_core::keychain::{ChainKey, KeyError, KeySource, MemoryKeySource};
use agentsweep_core::overview::ProjectCheck;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::state::StateFile;
use agentsweep_daemon::Tuning;
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::permission::{FIRST_READ_THREAD, Folders};
use agentsweep_daemon::service::{self, Background, Daemon};
use agentsweep_daemon::watcher::Timings;
use agentsweep_ipc::Client;
use agentsweep_ipc::peer::SameUser;
use agentsweep_ipc::protocol::{Role, Status};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A Rule 0001 hit (defanged: the payload decodes to `echo`), which a Scan
/// that read the file could not miss.
const A_BAD_INSTRUCTION_FILE: &str =
    include_str!("../../../rules/0001-decode-pipe-exec/bad/skill-base64-pipe-bash/tree/SKILL.md");

const A_PLAIN_INSTRUCTION_FILE: &str =
    "# app\n\nRun the tests before opening a change for review.\n";

/// The one chain key a sandbox's daemons share, as a Mac's Keychain would.
#[derive(Clone, Debug)]
struct SharedKey(Arc<MemoryKeySource>);

impl KeySource for SharedKey {
    fn load(&self) -> Result<Option<ChainKey>, KeyError> {
        self.0.load()
    }

    fn renew(&self) -> Result<ChainKey, KeyError> {
        self.0.renew()
    }

    fn forget(&self) -> Result<(), KeyError> {
        self.0.forget()
    }
}

/// The handle every read into a protected class goes through in these tests.
#[derive(Default)]
struct Stand {
    /// Every root it was asked to open, with the name of the thread that
    /// asked.
    opened: Mutex<Vec<(PathBuf, String)>>,
    /// Answer as the operating system does when the consent is missing.
    deny: AtomicBool,
    /// Told the thread's name when a read starts, and then waited on until
    /// the test lets the read finish, the way the system alert holds it.
    block: Mutex<Option<(Sender<String>, Receiver<()>)>>,
}

impl Folders for Stand {
    fn read(&self, root: &Path) -> io::Result<()> {
        let thread = std::thread::current()
            .name()
            .unwrap_or_default()
            .to_string();
        self.opened
            .lock()
            .expect("not poisoned")
            .push((root.to_path_buf(), thread.clone()));
        if let Some((entered, release)) = self.block.lock().expect("not poisoned").take() {
            let _ = entered.send(thread);
            let _ = release.recv();
        }
        match self.deny.load(Ordering::SeqCst) {
            true => Err(io::Error::from_raw_os_error(libc::EPERM)),
            false => Ok(()),
        }
    }
}

impl Stand {
    fn opened(&self) -> Vec<(PathBuf, String)> {
        self.opened.lock().expect("not poisoned").clone()
    }

    /// How many times "Check now" read this root.
    fn first_reads_of(&self, root: &Path) -> usize {
        self.opened()
            .iter()
            .filter(|(opened, thread)| opened == root && thread == FIRST_READ_THREAD)
            .count()
    }
}

/// One machine to scan, one data directory and one socket, all temporary.
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    socket: PathBuf,
    keys: SharedKey,
    /// A project in the home's Documents folder.
    documents: PathBuf,
    /// A project in a place nobody asks about.
    developer: PathBuf,
}

impl Sandbox {
    /// A home where Claude Code is installed and names two projects: one in
    /// Documents, one in Developer.
    fn new(purpose: &str, instruction_file: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-permission-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        std::fs::create_dir_all(home.join(".claude")).expect("an installed Agent");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        let documents = home.join("Documents").join("app");
        let developer = home.join("Developer").join("tool");
        for project in [&documents, &developer] {
            std::fs::create_dir_all(project).expect("a project");
        }
        std::fs::write(documents.join("CLAUDE.md"), instruction_file).expect("a file");
        std::fs::write(developer.join("CLAUDE.md"), A_PLAIN_INSTRUCTION_FILE).expect("a file");
        std::fs::write(
            home.join(".claude.json"),
            format!(
                "{{\n  \"projects\": {{\n    {:?}: {{\"hasTrustDialogAccepted\": true}},\n    {:?}: {{\"hasTrustDialogAccepted\": true}}\n  }}\n}}\n",
                documents.display().to_string(),
                developer.display().to_string()
            ),
        )
        .expect("a registry");
        let socket = std::env::temp_dir().join(format!(
            "asp-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        Sandbox {
            root,
            home,
            socket,
            keys: SharedKey(Arc::new(MemoryKeySource::empty())),
            documents,
            developer,
        }
    }

    fn data(&self) -> DataDirectory {
        DataDirectory::at(self.root.join("data"))
    }

    fn options(&self) -> Options {
        Options {
            data_dir: self.data(),
            socket: self.socket.clone(),
            home: Some(self.home.clone()),
            key_source: KeySourceChoice::Memory,
            log: LogChoice::Stderr,
        }
    }

    fn start(&self, stand: &Arc<Stand>) -> Background {
        let daemon = Daemon::open_tuned(
            &self.options(),
            Arc::new(SameUser),
            Box::new(self.keys.clone()),
            Tuning {
                watch: Timings::of(Duration::from_millis(100), Duration::from_millis(500)),
                folders: Arc::clone(stand) as Arc<dyn Folders>,
                ..Tuning::default()
            },
        )
        .expect("an open daemon");
        let running = service::start_with(&self.options(), daemon).expect("a daemon");
        let background = running.serve_in_the_background();
        wait_for_a_scan(background.daemon());
        background
    }

    fn client(&self) -> Client {
        Client::connect_at(&self.socket, Role::App).expect("a client")
    }

    fn status(&self) -> Status {
        self.client().status().expect("a status")
    }

    fn baseline(&self) -> BaselineView {
        Baseline::in_data_directory(&self.data())
            .read(&self.keys)
            .expect("a readable Baseline")
    }

    fn check_of(&self, status: &Status, root: &Path) -> ProjectCheck {
        status
            .overview
            .projects
            .iter()
            .find(|project| project.root == root.display().to_string())
            .map(|project| project.check)
            .expect("a project record")
    }

    /// True when the Baseline holds a record of an Item read from under the
    /// root.
    fn baseline_reaches(&self, root: &Path) -> bool {
        self.baseline()
            .records()
            .any(|record| Path::new(&record.path).starts_with(root))
    }

    fn remembered_classes(&self) -> Vec<String> {
        StateFile::in_data_directory(&self.data())
            .read(&self.keys)
            .expect("a readable state file")
            .readable_classes
            .into_iter()
            .collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn wait_for_a_scan(daemon: &Arc<Daemon>) {
    for _ in 0..3_600 {
        if !daemon.health().scanning && daemon.status().scan.is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the Full Scan did not finish");
}

/// Polls until the condition holds, for up to three minutes.
fn until(condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Waits for a Full Scan that started after `after` and has finished.
fn a_full_scan_after(
    sandbox: &Sandbox,
    daemon: &Arc<Daemon>,
    after: agentsweep_core::envelope::Timestamp,
) {
    assert!(
        until(|| {
            !daemon.health().scanning
                && sandbox.status().scan.is_some_and(|scan| {
                    scan.kind == agentsweep_core::scan_pass::ScanKind::Full
                        && scan.started_at > after
                })
        }),
        "a Full Scan ran after {after:?}"
    );
}

/// A project in Documents is never read by a Full Scan of its own accord:
/// nothing is opened inside it, its Rule 0001 hit raises no Finding, it is
/// neither pooled nor watched, Health counts one project Needing Permission
/// and the all-clear rung cannot show. The project in Developer is read.
#[test]
fn a_project_in_documents_is_never_read_and_needs_permission() {
    let sandbox = Sandbox::new("unread", A_BAD_INSTRUCTION_FILE);
    let stand = Arc::new(Stand::default());
    let running = sandbox.start(&stand);
    let daemon = running.daemon();
    let status = sandbox.status();

    assert!(
        stand.opened().is_empty(),
        "nothing was read through the handle: {:?}",
        stand.opened()
    );
    assert_eq!(status.health.projects_need_permission, 1);
    assert_eq!(status.health.rung(), Rung::NeedsPermission);
    assert_ne!(status.health.rung(), Rung::AllClear);
    assert_eq!(
        sandbox.check_of(&status, &sandbox.documents),
        ProjectCheck::NeedsPermission
    );
    assert_eq!(
        sandbox.check_of(&status, &sandbox.developer),
        ProjectCheck::Checked
    );
    assert!(
        status
            .findings
            .iter()
            .all(|finding| !finding.item_id.as_str().contains("Documents")),
        "no Finding about what was never read: {:?}",
        status.findings
    );
    assert!(!sandbox.baseline_reaches(&sandbox.documents));
    assert!(sandbox.baseline_reaches(&sandbox.developer));
    assert!(!daemon.pooled_roots().contains(&sandbox.documents));
    assert!(daemon.pooled_roots().contains(&sandbox.developer));
    let watching = daemon.watching();
    assert!(
        !watching.covers(&sandbox.documents.join("CLAUDE.md"))
            && watching
                .all()
                .all(|watched| !watched.starts_with(&sandbox.documents)),
        "the watcher is never relied on for it: {watching:?}"
    );
    assert!(watching.covers(&sandbox.developer.join("CLAUDE.md")));
    assert!(sandbox.remembered_classes().is_empty());
}

/// "Check now" reads the project once, on a thread of its own, remembers its
/// class and scans it. The next Full Scan reads it without a click, a
/// restarted daemon remembers the class, and a rebuilt state file is rebuilt
/// with the classes the Baseline proves readable.
#[test]
fn check_now_reads_the_project_once_remembers_the_class_and_scans_it() {
    let sandbox = Sandbox::new("check", A_PLAIN_INSTRUCTION_FILE);
    let stand = Arc::new(Stand::default());
    {
        let running = sandbox.start(&stand);
        let daemon = running.daemon();
        assert_eq!(sandbox.status().health.projects_need_permission, 1);

        let before = sandbox.status().scan.expect("a Scan").started_at;
        assert!(sandbox.client().check_now().expect("an answer"));
        a_full_scan_after(&sandbox, daemon, before);

        let status = sandbox.status();
        assert_eq!(stand.first_reads_of(&sandbox.documents), 1);
        assert_eq!(status.health.projects_need_permission, 0);
        assert_eq!(
            sandbox.check_of(&status, &sandbox.documents),
            ProjectCheck::Checked
        );
        assert!(sandbox.baseline_reaches(&sandbox.documents));
        assert!(daemon.pooled_roots().contains(&sandbox.documents));
        assert_eq!(sandbox.remembered_classes(), vec!["documents".to_string()]);
        assert!(
            !sandbox.client().check_now().expect("an answer"),
            "nothing Needs Permission any more"
        );

        // The next Full Scan reads it by itself.
        let before = sandbox.status().scan.expect("a Scan").started_at;
        assert!(sandbox.client().scan_now().expect("an answer"));
        a_full_scan_after(&sandbox, daemon, before);
        assert_eq!(
            sandbox.check_of(&sandbox.status(), &sandbox.documents),
            ProjectCheck::Checked
        );
        assert_eq!(
            stand.first_reads_of(&sandbox.documents),
            1,
            "no second click"
        );
    }

    // A restarted daemon remembers the class.
    let restarted = Arc::new(Stand::default());
    {
        let _running = sandbox.start(&restarted);
        let status = sandbox.status();
        assert_eq!(status.health.projects_need_permission, 0);
        assert_eq!(
            sandbox.check_of(&status, &sandbox.documents),
            ProjectCheck::Checked
        );
        assert_eq!(restarted.first_reads_of(&sandbox.documents), 0);
    }

    // A lost state file is rebuilt with the classes the Baseline proves.
    std::fs::remove_file(StateFile::in_data_directory(&sandbox.data()).path())
        .expect("the state file goes");
    let rebuilt = Arc::new(Stand::default());
    let _running = sandbox.start(&rebuilt);
    let status = sandbox.status();
    assert_eq!(status.health.projects_need_permission, 0);
    assert_eq!(
        sandbox.check_of(&status, &sandbox.documents),
        ProjectCheck::Checked
    );
    assert_eq!(rebuilt.first_reads_of(&sandbox.documents), 0);
    assert_eq!(sandbox.remembered_classes(), vec!["documents".to_string()]);
}

/// A class read before whose read now fails with `EPERM` turns the project
/// back to Needs Permission, and a file changed in it meanwhile raises no
/// Drift Finding, because nothing in it was read.
#[test]
fn a_denied_read_of_a_remembered_class_needs_permission_again_without_drift() {
    let sandbox = Sandbox::new("denied", A_PLAIN_INSTRUCTION_FILE);
    let stand = Arc::new(Stand::default());
    let running = sandbox.start(&stand);
    let daemon = running.daemon();
    let before = sandbox.status().scan.expect("a Scan").started_at;
    assert!(sandbox.client().check_now().expect("an answer"));
    a_full_scan_after(&sandbox, daemon, before);
    assert_eq!(
        sandbox.check_of(&sandbox.status(), &sandbox.documents),
        ProjectCheck::Checked
    );

    // The grant is taken back, and the file changes while it is.
    stand.deny.store(true, Ordering::SeqCst);
    std::fs::write(
        sandbox.documents.join("CLAUDE.md"),
        format!("{A_PLAIN_INSTRUCTION_FILE}\nKeep the headings as they are.\n"),
    )
    .expect("an edited file");

    let before = sandbox.status().scan.expect("a Scan").started_at;
    assert!(until(|| sandbox.client().scan_now().expect("an answer")));
    a_full_scan_after(&sandbox, daemon, before);

    let status = sandbox.status();
    assert_eq!(
        sandbox.check_of(&status, &sandbox.documents),
        ProjectCheck::NeedsPermission
    );
    assert_eq!(status.health.projects_need_permission, 1);
    assert_ne!(status.health.rung(), Rung::AllClear);
    assert!(
        status
            .findings
            .iter()
            .all(|finding| !finding.item_id.as_str().contains("Documents")),
        "no Drift Finding for what could not be read: {:?}",
        status.findings
    );
    assert!(!daemon.pooled_roots().contains(&sandbox.documents));
    assert_eq!(
        sandbox.remembered_classes(),
        vec!["documents".to_string()],
        "the class stays remembered: the next read is not a first read"
    );
}

/// "Check now" answers at once and makes its read on a thread of its own: a
/// status request is answered while the read is held the way the system
/// alert may hold it, and a second click while it is held starts nothing.
#[test]
fn a_status_answers_while_the_first_read_blocks() {
    let sandbox = Sandbox::new("blocked", A_PLAIN_INSTRUCTION_FILE);
    let stand = Arc::new(Stand::default());
    let running = sandbox.start(&stand);
    let daemon = running.daemon();

    let (entered_send, entered) = mpsc::channel();
    let (release, release_receive) = mpsc::channel();
    *stand.block.lock().expect("not poisoned") = Some((entered_send, release_receive));

    let mut client = sandbox.client();
    assert!(
        client
            .check_now()
            .expect("check-now answers before the read ends")
    );
    let thread = entered
        .recv_timeout(Duration::from_secs(30))
        .expect("the read started");
    assert_eq!(thread, FIRST_READ_THREAD);

    let (answered_send, answered) = mpsc::channel();
    let socket = sandbox.socket.clone();
    std::thread::spawn(move || {
        let status = Client::connect_at(&socket, Role::App)
            .expect("a client")
            .status();
        let _ = answered_send.send(status.is_ok());
    });
    assert_eq!(
        answered.recv_timeout(Duration::from_secs(30)),
        Ok(true),
        "a status is answered while the first read is held"
    );
    assert!(
        !client.check_now().expect("an answer"),
        "a second click while the read is held starts nothing"
    );
    assert_eq!(
        sandbox.status().health.projects_need_permission,
        1,
        "still Needing Permission until the read answers"
    );

    let before = sandbox.status().scan.expect("a Scan").started_at;
    release.send(()).expect("the read is let go");
    a_full_scan_after(&sandbox, daemon, before);
    assert_eq!(
        sandbox.check_of(&sandbox.status(), &sandbox.documents),
        ProjectCheck::Checked
    );
}
