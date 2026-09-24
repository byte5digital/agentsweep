//! Switching one line of a project's own files off where it lies.
//!
//! Repository Metadata and env files are the two kinds AgentSweep never
//! quarantines by itself, however sure a Rule is (spec section 5.2). They are
//! the user's own repository and the user's own secrets, and taking either out
//! of the way would break a working directory rather than protect it. So the
//! primitive is NeutraliseInPlace: the lines that make the file a Surface are
//! commented out where they lie, each behind the receipt id of the Quarantine
//! that switched it off, and switching them back on is taking that prefix away
//! again.
//!
//! Which lines those are is this adapter's answer, and it is deliberately
//! narrow:
//!
//! - a `.git/config` key Item is the one line that sets that key, whichever
//!   section it sits in, and nothing else in the file moves;
//! - an env file is the lines that set one of the five keys that re-point an
//!   Agent. The user's database password is not a Surface and is never
//!   touched;
//! - a hook git would run, a gitdir pointer and a worktree's commondir are
//!   whole files whose every line is what does the work, so every line goes.
//!
//! A file that is not text is refused rather than half commented out: a
//! compiled hook is not something a `#` switches off, and saying so is more
//! honest than writing over it.

use std::path::Path;

use agentsweep_core::adapter::Primitive;
use agentsweep_core::composite::{Step, carry_out};
use agentsweep_core::entry_edit::{is_neutralised, lines_of};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Item, Kind, Shape};
use agentsweep_core::quarantine::{EnforcementError, Receipt, Store, settled};

use crate::env;

/// Carries out one Quarantine of one Item of this adapter.
pub fn enforce(
    host: &Host,
    store: &dyn Store,
    item: &Item,
    primitives: &[Primitive],
) -> Result<Receipt, EnforcementError> {
    if primitives != [Primitive::NeutraliseInPlace] {
        return Err(EnforcementError::Unsupported {
            kind: item.kind,
            primitive: primitives.first().copied().unwrap_or(Primitive::MoveOut),
        });
    }
    let lines = chosen(host, item)?;
    let steps = [Step::NeutraliseInPlace {
        file: &item.path,
        lines,
        detail: detail(item),
    }];
    carry_out(host, store, item, &steps)
}

/// The lines one Quarantine of this Item comments out, after checking that the
/// file still holds what the Finding was raised on.
///
/// The compare-and-swap is the core's, through the same seam a MoveOut uses
/// (spec section 5.3): for a whole-file Item the hash is the file's, and for a
/// `.git/config` key it is the canonical form of that one key, so a file
/// somebody else is in the middle of writing is left alone.
fn chosen(host: &Host, item: &Item) -> Result<Vec<usize>, EnforcementError> {
    let mut lines = Vec::new();
    settled(&item.content_hash, &item.path, &mut || {
        let text = read(host, &item.path)?;
        let (chosen, hash) = match item.shape {
            Shape::Entry => config_key(item, &text),
            _ => whole_file(item, &text),
        }
        .ok_or_else(|| EnforcementError::Missing {
            path: item.path.clone(),
        })?;
        lines = chosen;
        Ok(hash)
    })?;
    if lines.is_empty() {
        return Err(EnforcementError::NotEligible {
            reason: format!("nothing in {} is left to comment out", item.path.display()),
        });
    }
    Ok(lines)
}

/// The one line of `.git/config` that sets this key, and what that key's
/// canonical form hashes to as the file stands now.
///
/// Git reads a section header and a key name without regard for case and takes
/// the last value it sees, so the walk follows the same rules: the line that
/// wins is the last one under a matching header.
fn config_key(item: &Item, text: &str) -> Option<(Vec<usize>, String)> {
    let key = item.inside_file();
    let (section, name) = split_key(key)?;
    let mut in_section = false;
    let mut found = None;
    for (number, line) in lines_of(text) {
        let bare = line.trim();
        if is_neutralised(bare) {
            continue;
        }
        if let Some(header) = bare
            .strip_prefix('[')
            .and_then(|rest| rest.split(']').next())
        {
            in_section = matches(header, &section);
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((written, value)) = bare.split_once('=') else {
            continue;
        };
        if written.trim().eq_ignore_ascii_case(&name) {
            let value = value.trim().to_string();
            found = Some((number, value));
        }
    }
    let (number, value) = found?;
    let canonical = crate::git::ConfigKey {
        key: key.to_string(),
        value,
        value_outside_repo: false,
    }
    .canonical_form();
    Some((vec![number], agentsweep_core::item::sha256_hex(&canonical)))
}

/// A key as an Item names it, as the section it sits in and the name inside
/// it. A subsection is written in quotes in the file and with a dot in the
/// name, which is why the split is on the first and the last dot.
fn split_key(key: &str) -> Option<(String, String)> {
    let (section, rest) = key.split_once('.')?;
    match rest.rsplit_once('.') {
        Some((subsection, name)) => Some((format!("{section} \"{subsection}\""), name.to_string())),
        None => Some((section.to_string(), rest.to_string())),
    }
}

/// True when a section header in the file is the one a key names. Git ignores
/// case in the section name and keeps it in the subsection.
fn matches(header: &str, wanted: &str) -> bool {
    let tidy = |text: &str| text.trim().replace('\t', " ").replace("  ", " ");
    let header = tidy(header);
    let wanted = tidy(wanted);
    match (header.split_once(' '), wanted.split_once(' ')) {
        (Some((one, sub)), Some((other, wanted_sub))) => {
            one.eq_ignore_ascii_case(other) && sub == wanted_sub
        }
        (None, None) => header.eq_ignore_ascii_case(&wanted),
        _ => false,
    }
}

/// The lines of a whole-file Item that are switched off, and the hash of the
/// file as it stands.
///
/// An env file gives up only the lines that re-point an Agent; everything git
/// itself reads gives up every line it has, because every line of a hook is
/// what runs and a pointer file is one line that says where the repository is.
fn whole_file(item: &Item, text: &str) -> Option<(Vec<usize>, String)> {
    let hash = agentsweep_core::item::sha256_hex(text.as_bytes());
    let chosen = lines_of(text)
        .into_iter()
        .filter(|(_, line)| {
            let bare = line.trim();
            if bare.is_empty() || is_neutralised(bare) {
                return false;
            }
            match item.kind {
                Kind::EnvFile => env::keys(line.as_bytes())
                    .first()
                    .is_some_and(|key| env::is_repointing(key)),
                _ => true,
            }
        })
        .map(|(number, _)| number)
        .collect();
    Some((chosen, hash))
}

/// One line for the Activity: what was switched off, never what it held.
fn detail(item: &Item) -> String {
    match item.kind {
        Kind::EnvFile => {
            "the lines that take an Agent somewhere else are commented out".to_string()
        }
        _ => match item.shape {
            Shape::Entry => format!(
                "the {} key is commented out and git no longer reads it",
                item.inside_file()
            ),
            _ => "every line is commented out and git no longer runs it".to_string(),
        },
    }
}

/// The text of one file of the project.
fn read(host: &Host, path: &Path) -> Result<String, EnforcementError> {
    let bytes = host.read(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => EnforcementError::Missing {
            path: path.to_path_buf(),
        },
        _ => EnforcementError::Store(error),
    })?;
    String::from_utf8(bytes).map_err(|_| EnforcementError::Edit {
        path: path.to_path_buf(),
        reason: "the file is not text, so there is no line to comment out".to_string(),
    })
}
