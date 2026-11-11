//! The daemons a test sandbox started, so the sandbox removes its temporary
//! folder only once none of them writes to it any more.
//!
//! Dropping a daemon's `Background` stops its accept loop, but a Scan or a Rule Feed
//! fetch already under way runs to its end on a thread of its own and writes
//! the Baseline and the state file when it does. A folder removed under it
//! comes back with those files in it. A sandbox follows every daemon it
//! starts and waits for them in its `Drop`, which runs when a test fails as
//! well as when it passes.

use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use agentsweep_daemon::service::Daemon;

/// How long a sandbox waits for its daemons at most. A daemon a subscriber
/// still holds stays alive until the process ends, so the wait is bounded.
const PATIENCE: Duration = Duration::from_secs(10);

/// How long a daemon that is still alive must have no Scan running or asked
/// for before the sandbox takes it as done writing. A due check that keeps
/// finding a Full Scan due asks again well within it.
const QUIET: Duration = Duration::from_millis(500);

/// The daemons one sandbox started, followed without keeping them alive.
#[derive(Debug, Default)]
pub struct Started(Mutex<Vec<Weak<Daemon>>>);

impl Started {
    /// Follows `daemon`, served in the background or opened alone.
    pub fn follow(&self, daemon: &Arc<Daemon>) {
        self.0
            .lock()
            .expect("the followed daemons are not poisoned")
            .push(Arc::downgrade(daemon));
    }

    /// Waits until every daemon followed is gone, or has had no Scan running
    /// or asked for for a while.
    pub fn settle(&self) {
        let daemons = match self.0.lock() {
            Ok(daemons) => daemons.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let deadline = Instant::now() + PATIENCE;
        for daemon in daemons {
            let mut quiet_since = Instant::now();
            while Instant::now() < deadline {
                let scanning = match daemon.upgrade() {
                    None => break,
                    Some(daemon) => daemon.health().scanning,
                };
                if scanning {
                    quiet_since = Instant::now();
                } else if quiet_since.elapsed() >= QUIET {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}
