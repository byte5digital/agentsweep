//! Env files, for the keys that re-point an Agent and for nothing else.
//!
//! An env file in a project is full of the user's own secrets, so it is a
//! Surface only where it takes an Agent somewhere else: at another
//! configuration directory, another API host or another Node runtime. A file
//! that sets none of those keys is not an Item, and no value ever leaves this
//! module: the parsed view carries key names, a Finding shows a hashed stand-in
//! and the bytes themselves stay on the machine for the local Tiers.

use agentsweep_core::item::sha256_hex;

/// The five keys that take an Agent somewhere else. `CLAUDE_CONFIG_DIR` and
/// `CODEX_HOME` relocate the whole configuration directory, the two base URLs
/// redirect the API the Agent talks to, and `NODE_OPTIONS` injects code into
/// the runtime an Agent starts under.
pub const REPOINTING_KEYS: [&str; 5] = [
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "ANTHROPIC_BASE_URL",
    "OPENAI_BASE_URL",
    "NODE_OPTIONS",
];

/// The env files this adapter reads at a project root. Both are files a dotenv
/// loader reads without being asked, and the committed one is how
/// CVE-2025-61260 relocates a Codex home into the repository.
pub const FILE_NAMES: [&str; 2] = [".env", ".env.local"];

/// True when a key takes an Agent somewhere else.
pub fn is_repointing(key: &str) -> bool {
    REPOINTING_KEYS.contains(&key)
}

/// The keys an env file sets, in the order they are written, without their
/// values. A line that is blank, a comment or not an assignment is skipped,
/// the same way a loader would.
pub fn keys(bytes: &[u8]) -> Vec<String> {
    assignments(bytes).into_iter().map(|(key, _)| key).collect()
}

/// The file rendered for a person to read: every value replaced by a short
/// hash of itself, so what is shown says whether a value changed and never
/// what it is.
pub fn redacted(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (key, value) in assignments(bytes) {
        let hash = sha256_hex(value.as_bytes());
        out.push_str(&format!("{key}=sha256:{}\n", &hash[..12]));
    }
    out
}

fn assignments(bytes: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(bytes);
    let mut pairs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let value = value.trim().trim_matches(['"', '\'']).to_string();
        pairs.push((key.to_string(), value));
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keys_of_a_file_are_read_in_order_and_without_values() {
        let keys =
            keys(b"# a comment\n\nDATABASE_URL=postgres://localhost/demo\nCODEX_HOME=./.codex\n");
        assert_eq!(keys, ["DATABASE_URL", "CODEX_HOME"]);
    }

    #[test]
    fn an_exported_and_a_quoted_assignment_are_both_read() {
        let keys = keys(b"export NODE_OPTIONS=\"--require ./x.js\"\nOPENAI_BASE_URL='http://localhost:11434/v1'\n");
        assert_eq!(keys, ["NODE_OPTIONS", "OPENAI_BASE_URL"]);
    }

    #[test]
    fn a_line_that_is_not_an_assignment_is_skipped() {
        assert!(keys(b"just some prose\n[section]\n").is_empty());
    }

    #[test]
    fn only_the_five_keys_re_point_an_agent() {
        assert_eq!(REPOINTING_KEYS.len(), 5);
        for key in REPOINTING_KEYS {
            assert!(is_repointing(key));
        }
        assert!(!is_repointing("DATABASE_URL"));
        assert!(!is_repointing("ANTHROPIC_API_KEY"));
    }

    /// What a person is shown says that a value is there and whether it
    /// changed, never what it is.
    #[test]
    fn a_rendered_env_file_carries_no_value() {
        let rendered =
            redacted(b"DATABASE_URL=postgres://user:hunter2@localhost/demo\nCODEX_HOME=./.codex\n");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("./.codex"), "{rendered}");
        assert!(rendered.contains("DATABASE_URL=sha256:"), "{rendered}");
        assert!(rendered.contains("CODEX_HOME=sha256:"), "{rendered}");
    }

    #[test]
    fn the_same_value_renders_the_same_way_twice() {
        assert_eq!(redacted(b"A=1\n"), redacted(b"A=1\n"));
        assert_ne!(redacted(b"A=1\n"), redacted(b"A=2\n"));
    }
}
