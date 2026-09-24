//! The due check: the daily Full Scan, and what Low Power Mode does to it.
//!
//! There is no `StartCalendarInterval` and no cron (spec section 6.4). The
//! daemon asks itself, every fifteen minutes and when the machine wakes,
//! whether the last completed Full Scan is a day old. If it is, one runs. Low
//! Power Mode defers that Full Scan, but never past three days: a machine left
//! on the power saver for a week is still checked. Being on battery defers
//! nothing.
//!
//! Low Power Mode is read off `NSProcessInfo` behind [`PowerState`], so a test
//! sets it without a machine that is in it.
//!
//! **On wake**: there is no workspace wake notification here. Subscribing to
//! one means AppKit and a run loop thread inside a background agent, and the
//! same answer is reached without either: the loop wakes once a minute, and a
//! wall clock that moved much further than the sleep it asked for is a machine
//! that was asleep, which is checked at once. A minute of an integer
//! comparison is nothing, and the fifteen-minute check stands behind it.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use agentsweep_core::envelope::Timestamp;

/// How old the last completed Full Scan has to be before the next one is due.
pub const DUE_AFTER_MS: i64 = 24 * 3_600_000;

/// How long Low Power Mode may defer it, at the very most.
pub const DEFERRED_AT_MOST_MS: i64 = 72 * 3_600_000;

/// How often the daemon asks whether a Full Scan is due.
pub const CHECK_EVERY: Duration = Duration::from_secs(15 * 60);

/// How long the loop sleeps at a time between those checks. It is short enough
/// that a wall clock that jumped is noticed soon after the machine woke, and
/// long enough that an idle daemon does nothing measurable.
pub const SLICE: Duration = Duration::from_secs(60);

/// How much further than the sleep it asked for the wall clock has to have
/// moved before the loop calls it a wake rather than a slow machine.
pub const WOKE_AFTER: Duration = Duration::from_secs(30);

/// Whether the machine is saving power. Read off the system, or set by a test.
pub trait PowerState: Send + Sync {
    /// True when Low Power Mode is on.
    fn low_power_mode(&self) -> bool;
}

/// Low Power Mode as `NSProcessInfo` reports it.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemPower;

#[cfg(target_os = "macos")]
impl PowerState for SystemPower {
    fn low_power_mode(&self) -> bool {
        objc2_foundation::NSProcessInfo::processInfo().isLowPowerModeEnabled()
    }
}

/// A machine with no Low Power Mode to read, which is every machine that is
/// not a Mac until the integration layer for the other platforms exists (spec
/// section 6.1).
#[cfg(not(target_os = "macos"))]
impl PowerState for SystemPower {
    fn low_power_mode(&self) -> bool {
        false
    }
}

/// A power state a caller states outright, which is how a test runs both sides
/// of the deferral without a machine in Low Power Mode.
#[derive(Clone, Copy, Debug)]
pub struct Stated(pub bool);

impl PowerState for Stated {
    fn low_power_mode(&self) -> bool {
        self.0
    }
}

/// Whether the daily Full Scan is due now.
///
/// A daemon that has never completed one is always due: its first Full Scan is
/// the one that runs at start, and until it has finished nothing is known
/// about this machine at all.
pub fn is_due(last_full_scan: Option<Timestamp>, now: Timestamp, low_power: bool) -> bool {
    let Some(last) = last_full_scan else {
        return true;
    };
    let waited = now.as_unix_ms() - last.as_unix_ms();
    match low_power {
        true => waited >= DEFERRED_AT_MOST_MS,
        false => waited >= DUE_AFTER_MS,
    }
}

/// A loop asking the question, on a thread of its own.
///
/// Dropping it stops the thread at the next slice, or at once if it is asleep
/// on the condition variable.
pub struct DueCheck {
    stopping: Arc<Stop>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for DueCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DueCheck").finish_non_exhaustive()
    }
}

impl Drop for DueCheck {
    fn drop(&mut self) {
        self.stopping.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The flag the loop sleeps against, so that stopping is immediate rather than
/// one slice away.
#[derive(Debug, Default)]
struct Stop {
    stopped: Mutex<bool>,
    woken: Condvar,
}

impl Stop {
    fn stop(&self) {
        *self.stopped.lock().expect("the flag is not poisoned") = true;
        self.woken.notify_all();
    }

    /// Sleeps for at most this long. True when the loop is to stop.
    fn sleep(&self, how_long: Duration) -> bool {
        let stopped = self.stopped.lock().expect("the flag is not poisoned");
        if *stopped {
            return true;
        }
        let (stopped, _) = self
            .woken
            .wait_timeout(stopped, how_long)
            .expect("the flag is not poisoned");
        *stopped
    }
}

/// How the loop reads the time and how long it sleeps, so that a test runs a
/// day of due checks in a few milliseconds.
#[derive(Clone)]
pub struct Schedule {
    /// How long between two checks.
    pub every: Duration,
    /// How long the loop sleeps at a time.
    pub slice: Duration,
    /// What the wall clock says.
    pub now: Arc<dyn Fn() -> Timestamp + Send + Sync>,
}

impl std::fmt::Debug for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Schedule")
            .field("every", &self.every)
            .field("slice", &self.slice)
            .finish_non_exhaustive()
    }
}

impl Default for Schedule {
    /// Every fifteen minutes, in slices of a minute, off the machine's clock.
    fn default() -> Schedule {
        Schedule {
            every: CHECK_EVERY,
            slice: SLICE,
            now: Arc::new(Timestamp::now),
        }
    }
}

/// Why the loop is asking this time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Occasion {
    /// The fifteen minutes are up.
    Scheduled,
    /// The wall clock moved further than the sleep asked for, so the machine
    /// was asleep and has woken.
    Woke,
}

impl std::fmt::Display for Occasion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Occasion::Scheduled => "the fifteen minute check",
            Occasion::Woke => "the machine woke",
        })
    }
}

/// Starts the loop. `ask` is called on every occasion and decides for itself
/// whether a Full Scan runs.
pub fn every(schedule: Schedule, ask: impl Fn(Occasion) + Send + 'static) -> DueCheck {
    let stopping = Arc::new(Stop::default());
    let flag = Arc::clone(&stopping);
    let thread = std::thread::Builder::new()
        .name("agentsweep-due-check".to_string())
        .spawn(move || run(&schedule, &flag, ask))
        .expect("the due check thread starts");
    DueCheck {
        stopping,
        thread: Some(thread),
    }
}

/// The loop itself: sleep a slice, notice a wall clock that jumped, and ask
/// once every `every`.
fn run(schedule: &Schedule, stopping: &Stop, ask: impl Fn(Occasion)) {
    let mut last_asked = (schedule.now)();
    loop {
        let before = (schedule.now)();
        if stopping.sleep(schedule.slice) {
            return;
        }
        let now = (schedule.now)();
        let slept = Duration::from_millis((now.as_unix_ms() - before.as_unix_ms()).max(0) as u64);

        // A wall clock that moved much further than the sleep asked for is a
        // machine that was suspended in the middle of it.
        if slept > schedule.slice + WOKE_AFTER {
            last_asked = now;
            ask(Occasion::Woke);
            continue;
        }
        if now.as_unix_ms() - last_asked.as_unix_ms() >= schedule.every.as_millis() as i64 {
            last_asked = now;
            ask(Occasion::Scheduled);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    fn moment(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a readable moment")
    }

    /// Spec section 6.4: due once the last completed Full Scan is a day old.
    #[test]
    fn the_daily_full_scan_is_due_after_a_day() {
        let last = moment("2026-09-23T08:00:00.000Z");
        assert!(!is_due(
            Some(last),
            moment("2026-09-24T07:59:59.000Z"),
            false
        ));
        assert!(is_due(
            Some(last),
            moment("2026-09-24T08:00:00.000Z"),
            false
        ));
    }

    /// Low Power Mode defers it, and never past three days.
    #[test]
    fn low_power_mode_defers_the_full_scan_for_at_most_three_days() {
        let last = moment("2026-09-21T08:00:00.000Z");
        assert!(
            !is_due(Some(last), moment("2026-09-22T08:00:00.000Z"), true),
            "a day into Low Power Mode nothing runs"
        );
        assert!(
            !is_due(Some(last), moment("2026-09-24T07:59:59.000Z"), true),
            "just under three days, still deferred"
        );
        assert!(
            is_due(Some(last), moment("2026-09-24T08:00:00.000Z"), true),
            "three days is the cap"
        );
        assert!(
            is_due(Some(last), moment("2026-09-22T08:00:00.000Z"), false),
            "off the power saver the same moment is long overdue"
        );
    }

    /// A daemon that has never finished a Full Scan is always due, whatever
    /// the machine is doing about power.
    #[test]
    fn a_machine_that_was_never_fully_scanned_is_always_due() {
        assert!(is_due(None, moment("2026-09-24T08:00:00.000Z"), false));
        assert!(is_due(None, moment("2026-09-24T08:00:00.000Z"), true));
    }

    /// The loop asks once per interval and stops when it is dropped.
    #[test]
    fn the_loop_asks_once_an_interval() {
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&asked);
        let check = every(
            Schedule {
                every: Duration::from_millis(20),
                slice: Duration::from_millis(2),
                ..Schedule::default()
            },
            move |occasion| {
                assert_eq!(occasion, Occasion::Scheduled);
                counted.fetch_add(1, Ordering::SeqCst);
            },
        );
        for _ in 0..200 {
            if asked.load(Ordering::SeqCst) >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(asked.load(Ordering::SeqCst) >= 2, "the loop asked twice");
        drop(check);
        let settled = asked.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            asked.load(Ordering::SeqCst),
            settled,
            "a dropped due check stops asking"
        );
    }

    /// A wall clock that moved much further than the sleep it asked for is a
    /// machine that woke, and the loop asks at once rather than waiting out
    /// the rest of the interval.
    #[test]
    fn a_wall_clock_that_jumped_is_read_as_a_wake() {
        let jumped = Arc::new(AtomicBool::new(false));
        let clock = Arc::clone(&jumped);
        let woke = Arc::new(AtomicBool::new(false));
        let noticed = Arc::clone(&woke);

        let check = every(
            Schedule {
                // Far longer than the test is willing to wait, so nothing but
                // the jump can make the loop ask.
                every: Duration::from_secs(3_600),
                slice: Duration::from_millis(2),
                now: Arc::new(move || {
                    let base = 1_700_000_000_000;
                    match clock.load(Ordering::SeqCst) {
                        true => Timestamp::from_unix_ms(base + 10 * 3_600_000),
                        false => Timestamp::from_unix_ms(base),
                    }
                }),
            },
            move |occasion| {
                if occasion == Occasion::Woke {
                    noticed.store(true, Ordering::SeqCst);
                }
            },
        );

        std::thread::sleep(Duration::from_millis(20));
        assert!(!woke.load(Ordering::SeqCst), "a still clock is no wake");
        jumped.store(true, Ordering::SeqCst);
        for _ in 0..200 {
            if woke.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(woke.load(Ordering::SeqCst), "the jump was read as a wake");
        drop(check);
    }

    /// The stated power state is the seam a test sets, and the system one
    /// answers without asking anything of the caller.
    #[test]
    fn the_power_state_is_read_behind_a_seam() {
        assert!(Stated(true).low_power_mode());
        assert!(!Stated(false).low_power_mode());
        // Whatever this machine is doing, reading it must not panic.
        let _ = SystemPower.low_power_mode();
    }
}
