//! The user's choices, as the daemon reads and moves them (spec sections 6.9
//! and 8.10).
//!
//! The daemon is the only writer of the settings file. One `settings` request
//! reads every choice, or moves the Rule Feed toggle, the app update check,
//! the Posture and the config-dir override per Agent, all of them or none: a
//! choice refused leaves the file as it was. Whenever a choice moved, through
//! this request, the `rule-feed` request or the `engine` requests, every
//! subscriber is told where every choice stands now.
//!
//! The config-dir override takes effect on the next Full Scan: every Host
//! the daemon builds after the change carries it, and the Surface Adapters
//! read the overridden directory in place of their default one.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use agentsweep_core::settings::{
    CONFIG_DIRS, ChoiceRefused, ConfigDir, SettingsFile, SettingsWriter,
};
use agentsweep_ipc::protocol::{RequestError, SettingsChange, SettingsState, StateEvent};

use crate::machine::{Machine, agents};
use crate::service::Daemon;

/// A refused choice as the client is told it.
fn refused(refusal: ChoiceRefused) -> RequestError {
    RequestError::new("refused", refusal.to_string())
}

/// The ids of the Agents an override may be set for: the Agent adapters'.
/// The workspace adapter has no config directory of its own.
fn agents_with_a_config_dir() -> Vec<&'static str> {
    agents()
        .iter()
        .map(|adapter| adapter.descriptor().agent)
        .collect()
}

impl Daemon {
    /// Where every choice the user made stands.
    pub fn settings_state(&self) -> SettingsState {
        let settings = self
            .settings
            .lock()
            .expect("the settings are not poisoned")
            .clone();
        SettingsState {
            rule_feed: settings.rule_feed,
            update_check: settings.update_check,
            posture: settings.posture,
            config_dirs: settings
                .config_dirs
                .iter()
                .map(|(agent, dir)| (agent.clone(), dir.as_str().to_string()))
                .collect(),
            engine: self.engine_state(),
        }
    }

    /// The machine with the config-dir override per Agent the settings hold
    /// now, which is what every Scan and every action reads.
    pub(crate) fn machine_in_force(&self) -> Machine {
        let config_dirs: BTreeMap<String, PathBuf> = self
            .settings
            .lock()
            .expect("the settings are not poisoned")
            .config_dirs
            .iter()
            .map(|(agent, dir)| (agent.clone(), dir.path().to_path_buf()))
            .collect();
        self.machine.clone().with_config_dirs(config_dirs)
    }

    /// Moves the choices a request names, all of them or none, and answers
    /// with where every choice stands afterwards.
    ///
    /// Every choice is checked before any is written. A settings file that
    /// could not be read is written over by any choice the user makes, with
    /// every other choice at its default, and the Health note goes; this is
    /// the one way the daemon writes over such a file.
    pub fn change_settings(
        self: &Arc<Daemon>,
        change: &SettingsChange,
    ) -> Result<SettingsState, RequestError> {
        if change.is_empty() {
            return Ok(self.settings_state());
        }
        let known = agents_with_a_config_dir();
        let mut overrides = Vec::new();
        for (agent, dir) in &change.config_dirs {
            if !known.contains(&agent.as_str()) {
                return Err(refused(ChoiceRefused::new(
                    CONFIG_DIRS,
                    "a config directory is set for Claude Code or Codex only",
                )));
            }
            let dir = match dir {
                Some(dir) => Some(ConfigDir::parse(dir).map_err(refused)?),
                None => None,
            };
            overrides.push((agent.clone(), dir));
        }

        let unreadable = self
            .health
            .lock()
            .expect("the health is not poisoned")
            .settings_unreadable;
        let wrote = {
            let mut settings = self.settings.lock().expect("the settings are not poisoned");
            let mut next = settings.clone();
            if let Some(update_check) = change.update_check {
                next.update_check = update_check;
            }
            if let Some(posture) = change.posture {
                next.posture = posture;
            }
            for (agent, dir) in overrides {
                match dir {
                    Some(dir) => next.config_dirs.insert(agent, dir),
                    None => next.config_dirs.remove(&agent),
                };
            }
            let names_another_choice = change.update_check.is_some()
                || change.posture.is_some()
                || !change.config_dirs.is_empty();
            let write = next != *settings || (unreadable && names_another_choice);
            if write {
                let file = SettingsFile::in_data_directory(&self.directory);
                SettingsWriter::write(&file, &next).map_err(|error| {
                    say!("the settings file could not be written: {error}");
                    RequestError::new("not-written", "the choice could not be written down")
                })?;
                if next.posture != settings.posture {
                    say!("the Posture is now {}", next.posture);
                }
                if next.update_check != settings.update_check {
                    say!(
                        "the app update check was switched {}",
                        if next.update_check { "on" } else { "off" }
                    );
                }
                if next.config_dirs != settings.config_dirs {
                    say!("a config-dir override changed; the next Full Scan reads it");
                }
                *settings = next;
            }
            write
        };
        if wrote {
            let cleared = {
                let mut health = self.health.lock().expect("the health is not poisoned");
                std::mem::replace(&mut health.settings_unreadable, false)
            };
            if cleared {
                self.tell_health();
            }
        }

        let feed_moved = match change.rule_feed {
            Some(enabled) if enabled != self.rule_feed_enabled() || (unreadable && !wrote) => {
                self.switch_rule_feed(enabled);
                true
            }
            _ => false,
        };
        if wrote || feed_moved {
            self.tell_settings();
        }
        // The first choice handed over releases a first Rule Feed fetch
        // still held for it; the toggle has moved by now, so a feed switched
        // off asks nothing.
        self.first_fetch.release();
        Ok(self.settings_state())
    }

    /// Tells every subscriber where every choice stands now, after one moved.
    pub(crate) fn tell_settings(&self) {
        self.publish(StateEvent::SettingsChanged {
            settings: Box::new(self.settings_state()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_is_set_for_the_agents_alone() {
        assert_eq!(agents_with_a_config_dir(), vec!["claude-code", "codex"]);
    }
}
