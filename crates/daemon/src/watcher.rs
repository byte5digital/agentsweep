//! The watcher: what changed on the Surfaces, gathered into one Batch.
//!
//! The daemon follows the directories the Surface Adapters declare, recursive
//! and non-recursive as each adapter says, through FSEvents and never kqueue,
//! which is one file descriptor per file and runs out at a few hundred of them
//! (spec section 6.1). Every backend can drop events and say so, so the
//! watcher is never trusted to have seen everything: a `Rescan` flag, an error
//! or a batch of more than two hundred paths is a Full Scan, and one runs every
//! day in any case.
//!
//! Two things live here and they are kept apart on purpose. [`Debouncer`] is
//! plain logic with no file system in it: observations and a moment go in, a
//! [`Batch`] comes out after two seconds of quiet or fifteen seconds of holding
//! on, whichever comes first, and a [`Decision`] says what that Batch is worth.
//! It is unit-tested with synthetic events at synthetic moments. [`Watch`] is
//! the thin part around it that owns the `notify` watcher and one thread.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use agentsweep_core::adapter::WatchRoots;

/// How long the watcher waits for quiet before it decides a batch is over.
pub const QUIET: Duration = Duration::from_secs(2);

/// How long it holds on to a batch that never goes quiet.
pub const MAXIMUM_HOLD: Duration = Duration::from_secs(15);

/// How many paths one batch may carry before it is a Full Scan instead
/// (spec section 6.4).
pub const PATHS_PER_BATCH: usize = 200;

/// The two moments the debounce is made of.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timings {
    /// How long nothing must happen before the batch is handed over.
    pub quiet: Duration,
    /// How long one batch may grow before it is handed over anyway.
    pub hold: Duration,
}

impl Default for Timings {
    /// What the specification fixes: two seconds quiet, fifteen seconds
    /// maximum hold.
    fn default() -> Timings {
        Timings {
            quiet: QUIET,
            hold: MAXIMUM_HOLD,
        }
    }
}

impl Timings {
    /// Timings of a caller's own, which is how a test runs the debounce in
    /// milliseconds instead of in seconds.
    pub fn of(quiet: Duration, hold: Duration) -> Timings {
        Timings { quiet, hold }
    }
}

/// One thing the watcher noticed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observation {
    /// These paths changed.
    Changed(Vec<PathBuf>),
    /// The backend dropped events and says the tree must be read again.
    Rescan,
    /// The backend failed.
    Failed(String),
}

/// What one debounced batch of watcher events holds.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Batch {
    paths: BTreeSet<PathBuf>,
    rescan: bool,
    failed: Option<String>,
}

impl Batch {
    /// A batch of the paths given, which is how a test builds one.
    pub fn of(paths: impl IntoIterator<Item = PathBuf>) -> Batch {
        Batch {
            paths: paths.into_iter().collect(),
            ..Batch::default()
        }
    }

    /// The paths it holds, in a stable order and each one once.
    pub fn paths(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.paths.iter().map(PathBuf::as_path)
    }

    /// Takes one more path into this batch, which is how two batches waiting
    /// for the same Scan become one.
    pub fn also(&mut self, path: PathBuf) {
        self.paths.insert(path);
    }

    /// How many paths it holds.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// True when it holds no path and nothing went wrong.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && !self.rescan && self.failed.is_none()
    }

    /// What this Batch is worth: nothing, a Change Scan, or a Full Scan
    /// because the watcher cannot say it saw everything (spec section 6.4).
    pub fn decide(self) -> Decision {
        if let Some(detail) = &self.failed {
            return Decision::Full(Escalation::Failed(detail.clone()));
        }
        if self.rescan {
            return Decision::Full(Escalation::Rescan);
        }
        if self.paths.len() > PATHS_PER_BATCH {
            return Decision::Full(Escalation::TooManyPaths(self.paths.len()));
        }
        if self.paths.is_empty() {
            return Decision::Nothing;
        }
        Decision::Change(self)
    }
}

/// Why a batch is a Full Scan rather than a Change Scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Escalation {
    /// The backend raised the `Rescan` flag: events were dropped.
    Rescan,
    /// The backend failed, so nothing it says can be relied on.
    Failed(String),
    /// More paths than one batch may carry.
    TooManyPaths(usize),
}

impl fmt::Display for Escalation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Escalation::Rescan => f.write_str("the watcher dropped events"),
            Escalation::Failed(detail) => write!(f, "the watcher failed: {detail}"),
            Escalation::TooManyPaths(paths) => {
                write!(
                    f,
                    "{paths} paths changed at once, more than {PATHS_PER_BATCH}"
                )
            }
        }
    }
}

/// What the daemon does with one batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Nothing worth a Scan happened.
    Nothing,
    /// A Change Scan of the Items behind these paths.
    Change(Batch),
    /// A Full Scan, because the watcher may have missed something.
    Full(Escalation),
}

/// Gathers observations into one Batch and says when it is over.
///
/// The batch is handed over after [`Timings::quiet`] with nothing new, or
/// after [`Timings::hold`] from the first observation in it, whichever comes
/// first. A `Rescan` flag and an error do not cut the batch short: they ride
/// along and turn it into a Full Scan when it is handed over, so a burst of
/// events and the dropped-event flag in the middle of it are one Scan and not
/// two.
#[derive(Clone, Debug)]
pub struct Debouncer {
    timings: Timings,
    opened: Option<Instant>,
    latest: Option<Instant>,
    batch: Batch,
}

impl Debouncer {
    /// A debouncer holding nothing.
    pub fn new(timings: Timings) -> Debouncer {
        Debouncer {
            timings,
            opened: None,
            latest: None,
            batch: Batch::default(),
        }
    }

    /// Takes one observation, made at this moment.
    pub fn saw(&mut self, observation: Observation, now: Instant) {
        match observation {
            Observation::Changed(paths) => self.batch.paths.extend(paths),
            Observation::Rescan => self.batch.rescan = true,
            Observation::Failed(detail) => self.batch.failed = Some(detail),
        }
        self.opened.get_or_insert(now);
        self.latest = Some(now);
    }

    /// True when a batch is open.
    pub fn waiting(&self) -> bool {
        self.opened.is_some()
    }

    /// True when the open batch is ready to be handed over.
    pub fn due(&self, now: Instant) -> bool {
        let (Some(opened), Some(latest)) = (self.opened, self.latest) else {
            return false;
        };
        now.duration_since(latest) >= self.timings.quiet
            || now.duration_since(opened) >= self.timings.hold
    }

    /// How long to wait before asking again, absent when no batch is open and
    /// there is nothing to wait for.
    pub fn wait_for(&self, now: Instant) -> Option<Duration> {
        let (opened, latest) = (self.opened?, self.latest?);
        let quiet_at = self
            .timings
            .quiet
            .saturating_sub(now.duration_since(latest));
        let hold_at = self.timings.hold.saturating_sub(now.duration_since(opened));
        Some(quiet_at.min(hold_at))
    }

    /// Hands the open batch over and starts a new one.
    pub fn take(&mut self) -> Option<Batch> {
        self.opened.take()?;
        self.latest = None;
        Some(std::mem::take(&mut self.batch))
    }
}

/// Why the watcher could not be started.
#[derive(Debug)]
pub struct WatchError(notify::Error);

impl fmt::Display for WatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the watcher could not be started: {}", self.0)
    }
}

impl std::error::Error for WatchError {}

/// A running watcher: the `notify` stream, the debounce thread and the roots
/// they were started on.
///
/// Dropping it stops both. The watcher is dropped first, which closes the
/// channel the thread is asleep on, so nothing polls and an idle daemon wakes
/// for nothing at all.
pub struct Watch {
    watcher: Option<RecommendedWatcher>,
    stopping: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    roots: WatchRoots,
    following: usize,
}

impl fmt::Debug for Watch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Watch")
            .field("following", &self.following)
            .finish()
    }
}

impl Watch {
    /// How many roots the watcher is actually following, which is fewer than
    /// were declared when one of them has gone away since the Scan that
    /// declared it.
    pub fn following(&self) -> usize {
        self.following
    }

    /// The roots it was started on.
    pub fn roots(&self) -> &WatchRoots {
        &self.roots
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        // Dropping the watcher drops the handler that holds the sending end,
        // which wakes the thread out of its blocking read.
        self.watcher.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts watching the declared roots and hands every decision to `sink`.
///
/// A root that has gone away since the Scan that declared it is skipped rather
/// than refused: the next Full Scan will not declare it again.
pub fn watch(
    roots: &WatchRoots,
    timings: Timings,
    sink: impl Fn(Decision) + Send + 'static,
) -> Result<Watch, WatchError> {
    let (sender, receiver) = channel::<Observation>();
    let events = sender.clone();
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
        let observation = match result {
            Ok(event) if event.need_rescan() => Observation::Rescan,
            Ok(event) => Observation::Changed(event.paths),
            Err(error) => Observation::Failed(error.to_string()),
        };
        let _ = events.send(observation);
    })
    .map_err(WatchError)?;
    drop(sender);

    let mut following = 0;
    let mut spelled: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (root, mode) in roots
        .recursive
        .iter()
        .map(|root| (root, RecursiveMode::Recursive))
        .chain(
            roots
                .non_recursive
                .iter()
                .map(|root| (root, RecursiveMode::NonRecursive)),
        )
    {
        if watcher.watch(root, mode).is_ok() {
            following += 1;
            // FSEvents answers with the path the file really has, so a root
            // reached through a symbolic link comes back spelled another way
            // than the adapter declared it. What the adapter declared is what
            // an Item's path is, so the real spelling is remembered and
            // undone on the way back in.
            if let Ok(real) = std::fs::canonicalize(root)
                && real != *root
            {
                spelled.push((real, root.clone()));
            }
        }
    }
    // The longest real prefix wins, so a root inside another root is rewritten
    // with its own spelling rather than its parent's.
    spelled.sort_by_key(|(real, _)| std::cmp::Reverse(real.as_os_str().len()));

    let stopping = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stopping);
    let declared = roots.clone();
    let thread = std::thread::Builder::new()
        .name("agentsweep-watcher".to_string())
        .spawn(move || {
            pump(
                receiver,
                Debouncer::new(timings),
                Declared {
                    roots: declared,
                    spelled,
                },
                flag,
                sink,
            )
        })
        .expect("the watcher thread starts");

    Ok(Watch {
        watcher: Some(watcher),
        stopping,
        thread: Some(thread),
        roots: roots.clone(),
        following,
    })
}

/// Reads observations until the watcher goes away, handing over each batch.
///
/// With no batch open it blocks, so an idle daemon has no timer of its own
/// here at all; with one open it waits exactly as long as the debounce has
/// left to run.
fn pump(
    receiver: Receiver<Observation>,
    mut debouncer: Debouncer,
    roots: Declared,
    stopping: Arc<AtomicBool>,
    sink: impl Fn(Decision),
) {
    loop {
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let read = match debouncer.wait_for(Instant::now()) {
            Some(wait) => receiver.recv_timeout(wait),
            None => receiver.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match read {
            Ok(observation) => debouncer.saw(inside(observation, &roots), Instant::now()),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if debouncer.due(Instant::now())
            && let Some(batch) = debouncer.take()
        {
            let decision = batch.decide();
            if decision != Decision::Nothing {
                sink(decision);
            }
        }
    }
}

/// The roots as the adapters spelled them, and how the file system spells the
/// ones that are reached through a symbolic link.
#[derive(Clone, Debug, Default)]
struct Declared {
    roots: WatchRoots,
    spelled: Vec<(PathBuf, PathBuf)>,
}

impl Declared {
    /// The path as an adapter would have written it: the real spelling the
    /// backend answered with, put back the way the Scan saw it.
    fn as_declared(&self, path: PathBuf) -> PathBuf {
        for (real, declared) in &self.spelled {
            if let Ok(rest) = path.strip_prefix(real) {
                return declared.join(rest);
            }
        }
        path
    }
}

/// Drops the paths of an observation that fall outside the declared roots, and
/// spells the rest the way the adapters do.
///
/// A non-recursive root is a directory watched for its own entries only, and
/// the backend is not asked to promise that: the promise is kept here, so a
/// Change Scan is only ever told about paths an adapter declared an interest
/// in.
fn inside(observation: Observation, roots: &Declared) -> Observation {
    match observation {
        Observation::Changed(paths) => Observation::Changed(
            paths
                .into_iter()
                .map(|path| roots.as_declared(path))
                .filter(|path| roots.roots.covers(path))
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(now: Instant, millis: u64) -> Instant {
        now + Duration::from_millis(millis)
    }

    fn timings() -> Timings {
        Timings::of(Duration::from_millis(200), Duration::from_millis(1_500))
    }

    fn changed(path: &str) -> Observation {
        Observation::Changed(vec![PathBuf::from(path)])
    }

    /// Two seconds of quiet: the batch waits while events keep arriving and is
    /// handed over once they stop.
    #[test]
    fn a_batch_is_handed_over_once_the_events_stop() {
        let start = Instant::now();
        let mut debouncer = Debouncer::new(timings());
        assert!(!debouncer.waiting());
        assert_eq!(debouncer.wait_for(start), None);

        debouncer.saw(changed("/home/.claude.json"), start);
        assert!(debouncer.waiting());
        assert!(!debouncer.due(at(start, 199)));

        // Another event inside the quiet window puts the clock back.
        debouncer.saw(changed("/home/.claude/settings.json"), at(start, 150));
        assert!(!debouncer.due(at(start, 300)));
        assert!(debouncer.due(at(start, 350)));

        let batch = debouncer.take().expect("a batch");
        assert_eq!(batch.len(), 2);
        assert!(!debouncer.waiting());
        assert_eq!(debouncer.take(), None);
    }

    /// Fifteen seconds of holding on: a batch that never goes quiet is handed
    /// over anyway.
    #[test]
    fn a_batch_that_never_goes_quiet_is_handed_over_at_the_maximum_hold() {
        let start = Instant::now();
        let mut debouncer = Debouncer::new(timings());
        for step in 0..20 {
            let now = at(start, step * 100);
            debouncer.saw(changed(&format!("/home/.claude/skills/s{step}")), now);
            if step * 100 < 1_500 {
                assert!(!debouncer.due(now), "held at {step}");
            }
        }
        assert!(debouncer.due(at(start, 1_500)));
        assert_eq!(debouncer.take().expect("a batch").len(), 20);
    }

    /// The same path twice is one path, and the batch is in a stable order.
    #[test]
    fn a_path_that_changed_twice_is_in_the_batch_once() {
        let start = Instant::now();
        let mut debouncer = Debouncer::new(timings());
        debouncer.saw(changed("/home/b"), start);
        debouncer.saw(changed("/home/a"), at(start, 10));
        debouncer.saw(changed("/home/b"), at(start, 20));
        let batch = debouncer.take_now(at(start, 300));
        assert_eq!(
            batch.paths().collect::<Vec<_>>(),
            vec![Path::new("/home/a"), Path::new("/home/b")]
        );
    }

    /// Spec section 6.4: a Rescan flag, an error and a batch over two hundred
    /// paths are each a Full Scan.
    #[test]
    fn a_rescan_an_error_and_an_oversized_batch_are_full_scans() {
        let start = Instant::now();

        let mut dropped = Debouncer::new(timings());
        dropped.saw(changed("/home/.claude.json"), start);
        dropped.saw(Observation::Rescan, at(start, 10));
        assert_eq!(
            dropped.take_now(at(start, 300)).decide(),
            Decision::Full(Escalation::Rescan)
        );

        let mut broken = Debouncer::new(timings());
        broken.saw(Observation::Failed("no more watches".to_string()), start);
        assert_eq!(
            broken.take_now(at(start, 300)).decide(),
            Decision::Full(Escalation::Failed("no more watches".to_string()))
        );

        let mut many = Debouncer::new(timings());
        let paths: Vec<PathBuf> = (0..=PATHS_PER_BATCH)
            .map(|n| PathBuf::from(format!("/home/.claude/skills/s{n}")))
            .collect();
        assert_eq!(paths.len(), PATHS_PER_BATCH + 1);
        many.saw(Observation::Changed(paths), start);
        assert_eq!(
            many.take_now(at(start, 300)).decide(),
            Decision::Full(Escalation::TooManyPaths(PATHS_PER_BATCH + 1))
        );
    }

    /// Exactly two hundred paths is still a Change Scan: the escalation is
    /// over the limit, not at it.
    #[test]
    fn a_batch_of_exactly_two_hundred_paths_is_a_change_scan() {
        let paths: Vec<PathBuf> = (0..PATHS_PER_BATCH)
            .map(|n| PathBuf::from(format!("/home/.claude/skills/s{n}")))
            .collect();
        match Batch::of(paths).decide() {
            Decision::Change(batch) => assert_eq!(batch.len(), PATHS_PER_BATCH),
            other => panic!("expected a Change Scan, got {other:?}"),
        }
    }

    /// A batch nothing is in is worth nothing.
    #[test]
    fn an_empty_batch_asks_for_no_scan() {
        assert_eq!(Batch::default().decide(), Decision::Nothing);
        assert!(Batch::default().is_empty());
    }

    /// A path outside every declared root never reaches a batch, whatever the
    /// backend delivered.
    #[test]
    fn a_path_outside_the_declared_roots_is_dropped() {
        let mut roots = WatchRoots::default();
        roots.watch_recursively(PathBuf::from("/home/.claude"));
        roots.watch(PathBuf::from("/home"));
        let declared = Declared {
            roots,
            spelled: Vec::new(),
        };

        let seen = inside(
            Observation::Changed(vec![
                PathBuf::from("/home/.claude/skills/one/SKILL.md"),
                PathBuf::from("/home/.claude.json"),
                PathBuf::from("/home/src/demo/main.rs"),
            ]),
            &declared,
        );
        assert_eq!(
            seen,
            Observation::Changed(vec![
                PathBuf::from("/home/.claude/skills/one/SKILL.md"),
                PathBuf::from("/home/.claude.json"),
            ])
        );
    }

    /// FSEvents answers with the path a file really has, so a root reached
    /// through a symbolic link comes back spelled another way. What the
    /// adapter declared is what an Item's path is, so the spelling is put back
    /// before anything is matched against it.
    #[test]
    fn a_root_reached_through_a_link_is_spelled_the_way_the_adapter_declared_it() {
        let mut roots = WatchRoots::default();
        roots.watch_recursively(PathBuf::from("/var/agentsweep/.claude"));
        let declared = Declared {
            roots,
            spelled: vec![(
                PathBuf::from("/private/var/agentsweep/.claude"),
                PathBuf::from("/var/agentsweep/.claude"),
            )],
        };

        let seen = inside(
            Observation::Changed(vec![
                PathBuf::from("/private/var/agentsweep/.claude/settings.json"),
                PathBuf::from("/private/var/elsewhere/settings.json"),
            ]),
            &declared,
        );
        assert_eq!(
            seen,
            Observation::Changed(vec![PathBuf::from("/var/agentsweep/.claude/settings.json")])
        );
    }

    /// The wait is the shorter of what is left of the quiet window and what is
    /// left of the maximum hold, so neither is ever overshot.
    #[test]
    fn the_wait_is_whichever_deadline_comes_first() {
        let start = Instant::now();
        let mut debouncer = Debouncer::new(timings());
        debouncer.saw(changed("/home/a"), start);
        assert_eq!(
            debouncer.wait_for(start),
            Some(Duration::from_millis(200)),
            "the quiet window is nearer at the start"
        );
        debouncer.saw(changed("/home/b"), at(start, 1_400));
        assert_eq!(
            debouncer.wait_for(at(start, 1_400)),
            Some(Duration::from_millis(100)),
            "the maximum hold is nearer at the end"
        );
    }

    impl Debouncer {
        /// The batch as it stands at this moment, for a test that has already
        /// checked the timing elsewhere.
        fn take_now(&mut self, now: Instant) -> Batch {
            assert!(self.due(now), "the batch is not due yet");
            self.take().expect("a batch")
        }
    }
}
