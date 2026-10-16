//! The Gate switch, as the daemon reads and moves it (spec sections 7.6 and
//! 8.10: "Stop the AI from using flagged items").
//!
//! The switch lives in the settings file, on by default. Off takes the Gate's
//! entries and the Codex pin away from every Agent, one `gate-removed` event
//! per entry, and from then on the registration check of every Full Scan
//! neither registers nor raises a Gate line. On runs that check at once,
//! rather than waiting for the next Full Scan. Health carries where the
//! switch stands, so a client says "off" rather than implying the Gate
//! stands.
//!
//! The switch governs registration only. The `gate` request is answered from
//! the state the same way whether it is on or off (spec section 7.3).
//!
//! Taking the Gate away is one operation, [`Daemon::remove_the_gate`], which
//! Uninstall calls on every path (spec section 9.6) without moving the
//! switch.

use std::sync::Arc;

use agentsweep_core::settings::{SettingsFile, SettingsWriter};
use agentsweep_ipc::protocol::RequestError;

use crate::gate::{self, Removal};
use crate::service::Daemon;

impl Daemon {
    /// Whether the Gate switch is on.
    pub fn gate_hooks_enabled(&self) -> bool {
        self.settings
            .lock()
            .expect("the settings are not poisoned")
            .gate_hooks
    }

    /// Moves the Gate switch and answers with where it stands afterwards.
    ///
    /// Waits for a running Scan or action to finish, the way every action
    /// does, so no Scan registers the Gate between the switch and the
    /// removal. Switching to where the switch already stands writes nothing
    /// and touches no Agent. A settings file that could not be read is
    /// written over here, as by any choice the user makes, and the Health
    /// note goes; the Agents are touched only when the switch moved.
    pub fn set_gate_hooks(self: &Arc<Daemon>, enabled: bool) -> Result<bool, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let unreadable = self
            .health
            .lock()
            .expect("the health is not poisoned")
            .settings_unreadable;
        let moved = {
            let mut settings = self.settings.lock().expect("the settings are not poisoned");
            let moved = settings.gate_hooks != enabled;
            if !moved && !unreadable {
                return Ok(enabled);
            }
            let mut next = settings.clone();
            next.gate_hooks = enabled;
            let file = SettingsFile::in_data_directory(&self.directory);
            SettingsWriter::write(&file, &next).map_err(|error| {
                say!("the settings file could not be written: {error}");
                RequestError::new("not-written", "the choice could not be written down")
            })?;
            *settings = next;
            moved
        };
        say!(
            "the Gate was switched {}",
            if enabled { "on" } else { "off" }
        );

        let lines = match (moved, enabled, self.tuning.gate.as_ref()) {
            (false, _, _) => None,
            (true, false, _) => {
                self.take_the_gate_away();
                Some(Vec::new())
            }
            (true, true, Some(command)) => Some(gate::check_detected(
                &self.machine_in_force(),
                &self.directory,
                &*self.keys,
                command,
            )),
            (true, true, None) => {
                say!("the Gate has no command line interface to run, so nothing is registered");
                Some(Vec::new())
            }
        };
        {
            let mut health = self.health.lock().expect("the health is not poisoned");
            health.gate_hooks = enabled;
            health.settings_unreadable = false;
            if let Some(lines) = lines {
                health.gate_lines = lines;
            }
        }
        self.tell_health();
        Ok(enabled)
    }

    /// Takes the Gate's entries and the Codex pin away from every Agent and
    /// records every entry taken away, without moving the switch: the one
    /// removal Uninstall calls on every path (spec section 9.6). The user's
    /// own hooks and pins stay. Waits for a running Scan or action to finish.
    pub fn remove_the_gate(&self) -> Removal {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let removal = self.take_the_gate_away();
        self.health
            .lock()
            .expect("the health is not poisoned")
            .gate_lines
            .clear();
        self.tell_health();
        removal
    }

    /// The removal itself, for a caller that already holds the write lock.
    fn take_the_gate_away(&self) -> Removal {
        let Some(command) = self.tuning.gate.as_ref() else {
            say!("the Gate has no command line interface path, so there is nothing to remove");
            return Removal::default();
        };
        gate::remove_everywhere(
            &self.machine_in_force(),
            &self.directory,
            &*self.keys,
            command,
        )
    }
}
