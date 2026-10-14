//! The user's own rules: an unsigned Rule Pack that can only ever flag.
//!
//! A developer may drop rules into the `rules.d/` directory of the data
//! directory (`rules/README.md`, "Packs"). Nothing signs them, so nothing in
//! them may claim the Rule tier: every rule loads as a Heuristic, whatever its
//! `tier` meta says, and a threat rule carries the Weight it declares, capped
//! at 3 and defaulting to 2. The rest of the authoring contract holds as it
//! does for the bundled pack, and the same meta lint rejects the same
//! mistakes.
//!
//! The sources are read into memory and the compiled pack borrows them, so a
//! [`UserRules`] lives as long as the pack built from it.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::rules::{PackTrust, RuleError, RulePack, RuleSource};

/// The file extension a user rule carries.
pub const RULE_EXTENSION: &str = "yar";

/// What went wrong while loading the user's rules.
#[derive(Debug)]
pub enum UserRulesError {
    /// The directory or one of its files could not be read.
    Io {
        /// What could not be read.
        path: PathBuf,
        /// Why not.
        error: io::Error,
    },
    /// A rule did not compile or did not pass the meta lint.
    Rule(RuleError),
}

impl fmt::Display for UserRulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserRulesError::Io { path, error } => {
                write!(f, "{} could not be read: {error}", path.display())
            }
            UserRulesError::Rule(error) => write!(f, "{error}"),
        }
    }
}

impl Error for UserRulesError {}

impl From<RuleError> for UserRulesError {
    fn from(error: RuleError) -> UserRulesError {
        UserRulesError::Rule(error)
    }
}

/// The rule sources of one user rules directory, read and ready to compile.
#[derive(Clone, Debug, Default)]
pub struct UserRules {
    sources: Vec<(String, String)>,
}

impl UserRules {
    /// Reads every `.yar` file directly under one directory, in name order. A
    /// directory that is not there is not a problem: it means the user wrote
    /// no rules.
    pub fn read(directory: &Path) -> Result<UserRules, UserRulesError> {
        if !directory.is_dir() {
            return Ok(UserRules::default());
        }
        let fail = |path: &Path, error: io::Error| UserRulesError::Io {
            path: path.to_path_buf(),
            error,
        };

        let mut paths: Vec<PathBuf> = fs::read_dir(directory)
            .map_err(|error| fail(directory, error))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<_, io::Error>>()
            .map_err(|error| fail(directory, error))?;
        paths.sort();

        let mut sources = Vec::new();
        for path in paths {
            if path.extension().and_then(|name| name.to_str()) != Some(RULE_EXTENSION) {
                continue;
            }
            let origin = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string();
            let source = fs::read_to_string(&path).map_err(|error| fail(&path, error))?;
            sources.push((origin, source));
        }
        Ok(UserRules { sources })
    }

    /// How many rule files were read.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// True when the user wrote no rules.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Compiles them into an unsigned pack, every rule forced to the Heuristic
    /// tier with its Weight capped.
    pub fn compile(&self) -> Result<RulePack, UserRulesError> {
        let sources: Vec<RuleSource<'_>> = self
            .sources
            .iter()
            .map(|(origin, source)| RuleSource { origin, source })
            .collect();
        Ok(RulePack::compile_with(&sources, PackTrust::Unsigned)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Category, RuleStatus, Severity, Tier};
    use crate::rules::{USER_RULE_DEFAULT_WEIGHT, USER_RULE_MAXIMUM_WEIGHT};

    /// One rule a user might write, with the `tier` and `weight` a test wants
    /// and every other meta key left valid.
    fn a_user_rule(id: i64, tier: &str, extra: &str, category: &str, severity: &str) -> String {
        format!(
            "rule as_{id:04}_mine {{\n  meta:\n    id = {id}\n    title = \"Mine\"\n\
             \x20   tier = {tier}\n    category = \"{category}\"\n    severity = \"{severity}\"\n\
{extra}\x20   class = 1\n    kinds = \"InstructionFile\"\n    status = \"stable\"\n\
             \x20   plain = \"Mine.\"\n    phrase = \"is mine\"\n    description = \"Mine.\"\n    references = \"none\"\n\
             \x20   sensitive = false\n  strings:\n    $m = \"MINE-{id}\"\n  condition:\n    $m\n}}\n"
        )
    }

    fn written(rules: &[(&str, String)]) -> (tempfile::TempDir, PathBuf) {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let directory = temporary.path().join("rules.d");
        fs::create_dir_all(&directory).expect("the user rules directory");
        for (name, source) in rules {
            fs::write(directory.join(name), source).expect("a user rule");
        }
        (temporary, directory)
    }

    #[test]
    fn a_directory_that_is_not_there_is_no_rules_and_no_problem() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let rules = UserRules::read(&temporary.path().join("rules.d")).expect("nothing to read");
        assert!(rules.is_empty());
        assert!(rules.compile().expect("an empty pack compiles").is_empty());
    }

    #[test]
    fn a_user_rule_declaring_tier_1_is_loaded_as_a_heuristic() {
        let (_temporary, directory) =
            written(&[("mine.yar", a_user_rule(9001, "1", "", "threat", "critical"))]);
        let rules = UserRules::read(&directory).expect("the rules are read");
        let pack = rules.compile().expect("the user pack compiles");

        let meta = pack.meta("as_9001_mine").expect("the rule is in the pack");
        assert_eq!(meta.tier, Tier::Heuristics);
        assert_eq!(meta.weight, Some(USER_RULE_DEFAULT_WEIGHT));
        assert_eq!(meta.severity, Severity::Critical, "severity is untouched");
    }

    #[test]
    fn a_user_rule_carries_the_weight_it_declares_capped_at_three() {
        let (_temporary, directory) = written(&[
            (
                "one.yar",
                a_user_rule(9002, "2", "    weight = 1\n", "threat", "high"),
            ),
            (
                "far-too-strong.yar",
                a_user_rule(9003, "1", "    weight = 9\n", "threat", "high"),
            ),
            (
                "none.yar",
                a_user_rule(9004, "2", "    weight = 3\n", "threat", "high"),
            ),
        ]);
        let rules = UserRules::read(&directory).expect("the rules are read");
        assert_eq!(rules.len(), 3);
        let pack = rules.compile().expect("the user pack compiles");

        assert_eq!(pack.meta("as_9002_mine").expect("9002").weight, Some(1));
        assert_eq!(
            pack.meta("as_9003_mine").expect("9003").weight,
            Some(USER_RULE_MAXIMUM_WEIGHT),
            "a user rule may not weigh more than the strongest Heuristic"
        );
        assert_eq!(pack.meta("as_9004_mine").expect("9004").weight, Some(3));
        for meta in pack.metas() {
            assert_eq!(meta.tier, Tier::Heuristics);
        }
    }

    #[test]
    fn a_user_exposure_rule_carries_no_weight_even_when_it_declares_one() {
        let (_temporary, directory) = written(&[(
            "exposed.yar",
            a_user_rule(9005, "1", "    weight = 2\n", "exposure", "medium"),
        )]);
        let pack = UserRules::read(&directory)
            .expect("the rules are read")
            .compile()
            .expect("the user pack compiles");

        let meta = pack.meta("as_9005_mine").expect("the rule is in the pack");
        assert_eq!(meta.category, Category::Exposure);
        assert_eq!(meta.tier, Tier::Heuristics);
        assert_eq!(meta.weight, None);
    }

    /// The pack says of itself that nothing signed it, which is what keeps a
    /// user rule out of every automatic decision.
    #[test]
    fn a_user_rules_directory_loads_as_an_unsigned_pack() {
        let (_temporary, directory) =
            written(&[("mine.yar", a_user_rule(9006, "1", "", "threat", "high"))]);
        let pack = UserRules::read(&directory)
            .expect("the rules are read")
            .compile()
            .expect("the user pack compiles");

        assert_eq!(pack.trust(), PackTrust::Unsigned);
        assert_eq!(
            RulePack::bundled().expect("bundled").trust(),
            PackTrust::Signed
        );
        assert_eq!(
            pack.meta("as_9006_mine").expect("the rule").status,
            RuleStatus::Stable
        );
    }

    #[test]
    fn a_user_rule_that_does_not_compile_names_itself() {
        let (_temporary, directory) = written(&[("broken.yar", "rule mine { condition: }".into())]);
        let problem = UserRules::read(&directory)
            .expect("the rules are read")
            .compile()
            .expect_err("a broken rule does not load")
            .to_string();
        assert!(problem.contains("did not compile"), "{problem}");
    }

    #[test]
    fn a_file_that_is_not_a_rule_is_left_alone() {
        let (_temporary, directory) = written(&[
            ("mine.yar", a_user_rule(9007, "2", "", "threat", "high")),
            ("notes.md", "Rules I mean to write one day.\n".to_string()),
        ]);
        let rules = UserRules::read(&directory).expect("the rules are read");
        assert_eq!(rules.len(), 1);
    }
}
