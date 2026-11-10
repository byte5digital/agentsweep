//! One press, one request. The windows name every press of a button that
//! asks the daemon for something, and the app carries out each press once.
//!
//! The webview delivers one press twice when it takes the first delivery of
//! a command for lost and sends it again by its other route, although the
//! first one reached the app. Carried out twice, a Quarantine is refused the
//! second time and the window shows that refusal instead of what happened;
//! "I agree, turn it on" hands the key over twice; Check now asks for two
//! Full Scans. So the same press asked again is answered with what it came
//! to, and a delivery that arrives while the press is still under way waits
//! for it. Different presses never wait for each other.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

/// How many presses are remembered. A repeat delivery follows its first one
/// within moments, so the last few are all that is ever asked again.
pub const KEPT: usize = 64;

/// Where one press stands.
#[derive(Debug)]
enum Stage<T> {
    /// Its first delivery is being carried out.
    Running,
    /// It came to this.
    Done(T),
    /// Its first delivery ended without an answer.
    Abandoned,
}

/// One press and what it came to.
#[derive(Debug)]
struct Press<T> {
    stage: Mutex<Stage<T>>,
    moved: Condvar,
}

/// Marks a press abandoned when its first delivery ends without an answer,
/// so a repeat delivery that waits for it is not left waiting.
struct Running<'a, T> {
    press: &'a Press<T>,
    answered: bool,
}

impl<T> Drop for Running<'_, T> {
    fn drop(&mut self) {
        if !self.answered {
            if let Ok(mut stage) = self.press.stage.lock() {
                *stage = Stage::Abandoned;
            }
            self.press.moved.notify_all();
        }
    }
}

/// The last presses of one kind of request and what each came to.
pub struct Presses<T> {
    seen: Mutex<VecDeque<(String, Arc<Press<T>>)>>,
}

impl<T> Default for Presses<T> {
    fn default() -> Presses<T> {
        Presses {
            seen: Mutex::new(VecDeque::new()),
        }
    }
}

/// Says how many presses are remembered and nothing of what they came to,
/// which may be a typed key's answer.
impl<T> std::fmt::Debug for Presses<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let remembered = self.seen.lock().map(|seen| seen.len()).unwrap_or(0);
        formatter
            .debug_struct("Presses")
            .field("remembered", &remembered)
            .finish()
    }
}

impl<T: Clone> Presses<T> {
    /// Carries out `run` once for `press`: the first delivery runs it, and
    /// every other delivery of the same press is answered with what it came
    /// to, waiting for it while it is under way. A first delivery that ended
    /// without an answer leaves the next delivery to run it.
    pub fn once(&self, press: &str, run: impl FnOnce() -> T) -> T {
        let (first, held) = self.take(press);
        if !first {
            let mut stage = held.stage.lock().expect("the press is not poisoned");
            loop {
                match &*stage {
                    Stage::Done(answer) => return answer.clone(),
                    Stage::Running => {
                        stage = held.moved.wait(stage).expect("the press is not poisoned");
                    }
                    Stage::Abandoned => {
                        *stage = Stage::Running;
                        break;
                    }
                }
            }
        }
        let mut running = Running {
            press: &held,
            answered: false,
        };
        let answer = run();
        *held.stage.lock().expect("the press is not poisoned") = Stage::Done(answer.clone());
        running.answered = true;
        held.moved.notify_all();
        answer
    }

    /// The press of this name, and whether this delivery is its first.
    fn take(&self, press: &str) -> (bool, Arc<Press<T>>) {
        let mut seen = self.seen.lock().expect("the presses are not poisoned");
        if let Some((_, held)) = seen.iter().find(|(name, _)| name == press) {
            return (false, Arc::clone(held));
        }
        let held = Arc::new(Press {
            stage: Mutex::new(Stage::Running),
            moved: Condvar::new(),
        });
        seen.push_back((press.to_string(), Arc::clone(&held)));
        while seen.len() > KEPT {
            seen.pop_front();
        }
        (true, held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::channel;
    use std::time::Duration;

    #[test]
    fn the_same_press_is_carried_out_once_and_answered_alike() {
        let presses = Presses::default();
        let runs = AtomicUsize::new(0);
        let run = || {
            runs.fetch_add(1, Ordering::SeqCst);
            "done".to_string()
        };
        assert_eq!(presses.once("a", run), "done");
        assert_eq!(presses.once("a", || "again".to_string()), "done");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(presses.once("b", || "b".to_string()), "b");
    }

    /// A repeat delivery that arrives while the first is under way waits for
    /// it and gets its answer; another press does not wait.
    #[test]
    fn a_repeat_waits_for_the_first_delivery_and_another_press_does_not() {
        let presses = Arc::new(Presses::default());
        let (started, running) = channel();
        let (release, held) = channel::<()>();
        let first = {
            let presses = Arc::clone(&presses);
            std::thread::spawn(move || {
                presses.once("a", || {
                    started.send(()).expect("the test listens");
                    held.recv().expect("released");
                    1
                })
            })
        };
        running.recv().expect("the first delivery started");
        let repeat = {
            let presses = Arc::clone(&presses);
            std::thread::spawn(move || presses.once("a", || 2))
        };
        assert_eq!(presses.once("b", || 3), 3, "another press runs at once");
        std::thread::sleep(Duration::from_millis(50));
        assert!(!repeat.is_finished(), "the repeat waits for the first");
        release.send(()).expect("the first waits");
        assert_eq!(first.join().expect("the first"), 1);
        assert_eq!(repeat.join().expect("the repeat"), 1);
    }

    #[test]
    fn a_first_delivery_without_an_answer_leaves_the_next_to_run() {
        let presses = Arc::new(Presses::default());
        let failed = {
            let presses = Arc::clone(&presses);
            std::thread::spawn(move || presses.once("a", || -> u8 { panic!("lost") }))
        };
        assert!(failed.join().is_err());
        assert_eq!(presses.once("a", || 7), 7);
        assert_eq!(presses.once("a", || 8), 7);
    }

    #[test]
    fn only_the_last_presses_are_remembered_and_none_is_shown() {
        let presses = Presses::default();
        for n in 0..=KEPT {
            presses.once(&n.to_string(), || format!("secret {n}"));
        }
        assert_eq!(presses.once("0", || "again".to_string()), "again");
        assert_eq!(
            presses.once(&KEPT.to_string(), || "again".to_string()),
            format!("secret {KEPT}")
        );
        assert!(!format!("{presses:?}").contains("secret"));
    }
}
