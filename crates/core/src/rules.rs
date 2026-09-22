//! The Rule tier (T1): the bundled Rule Pack and its compilation.
//!
//! YARA-X is the only rule language (ADR 0004). The bundled pack is the
//! `rules/` tree of this repository, embedded by the build script. The core
//! defines every view global with its full schema before it adds a single rule
//! source, so the shape a rule compiles against is the shape the Scanner sets
//! later.
//!
//! The pack pre-filters on the `kinds` meta: one compiled rule set per Surface
//! kind, holding only the rules that declare that kind. An Item is therefore
//! never run against a rule that does not apply to it.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use yara_x::{Compiler, MetaValue, Rules, SourceCode};

use crate::finding::{Category, RuleStatus, Severity, Tier};
use crate::item::Kind;
use crate::views::Views;

/// One rule source of a Rule Pack.
#[derive(Clone, Copy, Debug)]
pub struct RuleSource {
    /// Where the source sits in the pack, such as `0001-decode-pipe-exec/rule.yar`.
    pub origin: &'static str,
    /// The rule text.
    pub source: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/bundled_rules.rs"));

/// What went wrong while building a Rule Pack.
#[derive(Debug)]
pub enum RuleError {
    /// A rule source did not compile.
    Compile(Box<yara_x::errors::CompileError>),
    /// A view global could not be defined or set.
    Variable(yara_x::errors::VariableError),
    /// A rule is missing a required meta key, or carries one the contract does
    /// not allow.
    Meta {
        /// The rule the problem is about.
        rule: String,
        /// What is wrong with its meta.
        problem: String,
    },
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleError::Compile(error) => write!(f, "a rule did not compile: {error}"),
            RuleError::Variable(error) => write!(f, "a view global was rejected: {error}"),
            RuleError::Meta { rule, problem } => write!(f, "rule {rule}: {problem}"),
        }
    }
}

impl Error for RuleError {}

impl From<yara_x::errors::CompileError> for RuleError {
    fn from(error: yara_x::errors::CompileError) -> RuleError {
        RuleError::Compile(Box::new(error))
    }
}

impl From<yara_x::errors::VariableError> for RuleError {
    fn from(error: yara_x::errors::VariableError) -> RuleError {
        RuleError::Variable(error)
    }
}

/// The routing and wording a rule carries in its `meta:` block, read back from
/// the compiled rules.
#[derive(Clone, Debug)]
pub struct RuleMeta {
    /// The YARA name, `as_<nnnn>_<slug>`.
    pub name: String,
    /// Where the source sits in the pack.
    pub origin: String,
    /// The integer id, never reused.
    pub id: i64,
    /// The developer-facing one line.
    pub title: String,
    /// Rule or Heuristic.
    pub tier: Tier,
    /// Threat or Exposure.
    pub category: Category,
    /// How bad a hit is if true.
    pub severity: Severity,
    /// The ranked attack class of the threat model.
    pub class: i64,
    /// The kinds the rule applies to. The core pre-filters on this.
    pub kinds: Vec<Kind>,
    /// Probation, stable or retired.
    pub status: RuleStatus,
    /// The one sentence the Simple Posture shows.
    pub plain: String,
    /// What fires, what deliberately does not, and why.
    pub description: String,
    /// The primary sources behind the rule.
    pub references: String,
    /// True when matches can land on sensitive fields.
    pub sensitive: bool,
    /// The declared strength of a Heuristic, absent on a Rule.
    pub weight: Option<i64>,
    /// True when the heuristic fires on text that addresses a reviewer.
    pub reviewer_directed: bool,
}

/// A compiled Rule Pack: the meta index plus one compiled rule set per kind.
pub struct RulePack {
    index: BTreeMap<String, RuleMeta>,
    by_kind: BTreeMap<Kind, Rules>,
}

impl fmt::Debug for RulePack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RulePack")
            .field("rules", &self.index.len())
            .field("kinds", &self.by_kind.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RulePack {
    /// Compiles the pack embedded in this binary.
    pub fn bundled() -> Result<RulePack, RuleError> {
        RulePack::compile(BUNDLED_RULES)
    }

    /// Compiles a pack from its rule sources.
    pub fn compile(sources: &[RuleSource]) -> Result<RulePack, RuleError> {
        let index = read_index(sources)?;

        let mut by_kind = BTreeMap::new();
        for kind in Kind::ALL {
            let applicable: Vec<RuleSource> = sources
                .iter()
                .copied()
                .filter(|source| {
                    index.values().any(|meta| {
                        meta.origin == source.origin
                            && meta.status != RuleStatus::Retired
                            && meta.kinds.contains(&kind)
                    })
                })
                .collect();
            if applicable.is_empty() {
                continue;
            }
            by_kind.insert(kind, compile_sources(&applicable)?);
        }

        Ok(RulePack { index, by_kind })
    }

    /// The meta of one rule, by its YARA name.
    pub fn meta(&self, name: &str) -> Option<&RuleMeta> {
        self.index.get(name)
    }

    /// Every rule's meta, ordered by name.
    pub fn metas(&self) -> impl Iterator<Item = &RuleMeta> {
        self.index.values()
    }

    /// The compiled rules that apply to one kind, absent when no rule declares
    /// that kind.
    pub fn rules_for(&self, kind: Kind) -> Option<&Rules> {
        self.by_kind.get(&kind)
    }

    /// How many rules the pack holds.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// True when the pack holds no rule.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

/// Compiles rule sources against the full view-global schema.
fn compile_sources(sources: &[RuleSource]) -> Result<Rules, RuleError> {
    let mut compiler = Compiler::new();
    for (name, schema) in Views::schema() {
        compiler.define_global(name, schema)?;
    }
    for source in sources {
        compiler.add_source(SourceCode::from(source.source).with_origin(source.origin))?;
    }
    Ok(compiler.build())
}

/// Compiles every source once to read the `meta:` blocks back, then binds each
/// rule to the source its id points at. A rule whose id does not match its
/// directory prefix is rejected here, which is the contract in
/// `rules/README.md`.
fn read_index(sources: &[RuleSource]) -> Result<BTreeMap<String, RuleMeta>, RuleError> {
    let compiled = compile_sources(sources)?;
    let mut index = BTreeMap::new();
    for rule in compiled.iter() {
        let name = rule.identifier().to_string();
        let meta: BTreeMap<&str, MetaValue<'_>> = rule.metadata().collect();
        let id = integer(&name, &meta, "id")?;
        let prefix = format!("{id:04}-");
        let origin = sources
            .iter()
            .find(|source| source.origin.starts_with(&prefix))
            .ok_or_else(|| RuleError::Meta {
                rule: name.clone(),
                problem: format!("id {id} matches no rule directory named `{prefix}...`"),
            })?
            .origin
            .to_string();

        let tier =
            Tier::from_meta(integer(&name, &meta, "tier")?).ok_or_else(|| RuleError::Meta {
                rule: name.clone(),
                problem: "tier is neither 1 nor 2".to_string(),
            })?;
        let category =
            Category::parse(text(&name, &meta, "category")?).ok_or_else(|| RuleError::Meta {
                rule: name.clone(),
                problem: "category is neither threat nor exposure".to_string(),
            })?;
        let severity =
            Severity::parse(text(&name, &meta, "severity")?).ok_or_else(|| RuleError::Meta {
                rule: name.clone(),
                problem: "severity is not one of the four steps".to_string(),
            })?;
        let status =
            RuleStatus::parse(text(&name, &meta, "status")?).ok_or_else(|| RuleError::Meta {
                rule: name.clone(),
                problem: "status is not probation, stable or retired".to_string(),
            })?;
        let mut kinds = Vec::new();
        for spelling in text(&name, &meta, "kinds")?.split(',') {
            let spelling = spelling.trim();
            let kind = Kind::parse(spelling).ok_or_else(|| RuleError::Meta {
                rule: name.clone(),
                problem: format!("`{spelling}` is not a Surface kind"),
            })?;
            kinds.push(kind);
        }

        let rule_meta = RuleMeta {
            origin,
            id,
            title: text(&name, &meta, "title")?.to_string(),
            tier,
            category,
            severity,
            class: integer(&name, &meta, "class")?,
            kinds,
            status,
            plain: text(&name, &meta, "plain")?.to_string(),
            description: text(&name, &meta, "description")?.to_string(),
            references: text(&name, &meta, "references")?.to_string(),
            sensitive: boolean(&name, &meta, "sensitive")?,
            weight: match meta.get("weight") {
                Some(MetaValue::Integer(weight)) => Some(*weight),
                _ => None,
            },
            reviewer_directed: matches!(meta.get("reviewer_directed"), Some(MetaValue::Bool(true))),
            name: name.clone(),
        };
        lint(&rule_meta, &meta)?;
        index.insert(name, rule_meta);
    }
    Ok(index)
}

/// The meta lint. Every required key is already enforced by [`read_index`],
/// which cannot build a [`RuleMeta`] without one; what is left is the keys
/// that belong to one tier and not the other, and the ranges the contract in
/// `rules/README.md` fixes.
fn lint(rule: &RuleMeta, meta: &BTreeMap<&str, MetaValue<'_>>) -> Result<(), RuleError> {
    let reject = |problem: String| {
        Err(RuleError::Meta {
            rule: rule.name.clone(),
            problem,
        })
    };

    if !(1..=6).contains(&rule.class) {
        return reject(format!(
            "class {} is not one of the six ranked attack classes",
            rule.class
        ));
    }

    let declares_weight = meta.contains_key("weight");
    match rule.tier {
        Tier::Rules => {
            if declares_weight {
                return reject(
                    "`weight` belongs to a tier 2 threat rule; a tier 1 rule carries none"
                        .to_string(),
                );
            }
            if meta.contains_key("reviewer_directed") {
                return reject("`reviewer_directed` is a tier 2 key".to_string());
            }
            if rule.category == Category::Threat
                && !matches!(rule.severity, Severity::Critical | Severity::High)
            {
                return reject(format!(
                    "a tier 1 threat rule is critical or high, never {}",
                    rule.severity
                ));
            }
        }
        Tier::Heuristics => match rule.category {
            Category::Threat => match rule.weight {
                Some(weight) if (1..=3).contains(&weight) => {}
                Some(weight) => {
                    return reject(format!("`weight` {weight} is not 1, 2 or 3"));
                }
                None if declares_weight => {
                    return reject("`weight` is not an integer".to_string());
                }
                None => {
                    return reject("a tier 2 threat rule declares a `weight`".to_string());
                }
            },
            Category::Exposure => {
                if declares_weight {
                    return reject(
                        "a tier 2 exposure rule carries no `weight`; it raises its own Finding"
                            .to_string(),
                    );
                }
            }
        },
        _ => {
            return reject(format!("tier {} is neither 1 nor 2", rule.tier));
        }
    }

    Ok(())
}

fn text<'m>(
    rule: &str,
    meta: &BTreeMap<&str, MetaValue<'m>>,
    key: &str,
) -> Result<&'m str, RuleError> {
    match meta.get(key) {
        Some(MetaValue::String(value)) => Ok(value),
        Some(_) => Err(RuleError::Meta {
            rule: rule.to_string(),
            problem: format!("`{key}` is not a string"),
        }),
        None => Err(RuleError::Meta {
            rule: rule.to_string(),
            problem: format!("`{key}` is missing"),
        }),
    }
}

fn integer(rule: &str, meta: &BTreeMap<&str, MetaValue<'_>>, key: &str) -> Result<i64, RuleError> {
    match meta.get(key) {
        Some(MetaValue::Integer(value)) => Ok(*value),
        Some(_) => Err(RuleError::Meta {
            rule: rule.to_string(),
            problem: format!("`{key}` is not an integer"),
        }),
        None => Err(RuleError::Meta {
            rule: rule.to_string(),
            problem: format!("`{key}` is missing"),
        }),
    }
}

fn boolean(rule: &str, meta: &BTreeMap<&str, MetaValue<'_>>, key: &str) -> Result<bool, RuleError> {
    match meta.get(key) {
        Some(MetaValue::Bool(value)) => Ok(*value),
        Some(_) => Err(RuleError::Meta {
            rule: rule.to_string(),
            problem: format!("`{key}` is not a boolean"),
        }),
        None => Err(RuleError::Meta {
            rule: rule.to_string(),
            problem: format!("`{key}` is missing"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_pack_carries_every_rule_of_the_corpus() {
        assert!(
            BUNDLED_RULES.len() >= 11,
            "the corpus has at least eleven rules"
        );
        assert!(
            BUNDLED_RULES
                .iter()
                .any(|rule| rule.origin.starts_with("0001-"))
        );
        assert!(
            BUNDLED_RULES
                .iter()
                .any(|rule| rule.origin.starts_with("0900-"))
        );
    }

    #[test]
    fn every_bundled_rule_compiles_against_the_view_globals() {
        let pack = RulePack::bundled().expect("the bundled pack compiles");
        assert_eq!(pack.len(), BUNDLED_RULES.len());
    }

    #[test]
    fn every_bundled_rule_carries_the_required_meta() {
        let pack = RulePack::bundled().expect("the bundled pack compiles");
        for meta in pack.metas() {
            assert!(
                meta.name.starts_with("as_"),
                "{} is not named as_<nnnn>_<slug>",
                meta.name
            );
            assert!(!meta.title.is_empty());
            assert!(!meta.plain.is_empty());
            assert!(!meta.description.is_empty());
            assert!(!meta.references.is_empty());
            assert!(!meta.kinds.is_empty());
            assert!(meta.class >= 1 && meta.class <= 6);
        }
    }

    #[test]
    fn every_rule_of_the_v1_pack_ships_on_probation() {
        let pack = RulePack::bundled().expect("the bundled pack compiles");
        for meta in pack.metas() {
            assert_eq!(
                meta.status,
                RuleStatus::Probation,
                "{} does not ship on probation",
                meta.name
            );
        }
    }

    #[test]
    fn the_pack_pre_filters_on_kinds() {
        let pack = RulePack::bundled().expect("the bundled pack compiles");
        let instruction_file = pack
            .rules_for(Kind::InstructionFile)
            .expect("rules apply to an instruction file");
        let names: Vec<&str> = instruction_file
            .iter()
            .map(|rule| rule.identifier())
            .collect();
        assert!(names.contains(&"as_0001_decode_pipe_exec"));
        assert!(
            !names.contains(&"as_0009_repository_metadata_execution"),
            "a repository metadata rule may not reach an instruction file"
        );

        let repository = pack
            .rules_for(Kind::RepositoryMetadata)
            .expect("rules apply to repository metadata");
        let names: Vec<&str> = repository.iter().map(|rule| rule.identifier()).collect();
        assert!(names.contains(&"as_0009_repository_metadata_execution"));
        assert!(!names.contains(&"as_0004_html_comment_role_tags"));
    }

    /// A rule source built from the full meta block, with the keys a test
    /// wants changed replaced and the keys it wants gone removed. The lint is
    /// what is under test, so every other key stays valid.
    fn meta_variant(lines: &[(&str, Option<&str>)]) -> String {
        let mut block: Vec<(&str, String)> = vec![
            ("id", "21".to_string()),
            ("title", "\"A rule under lint\"".to_string()),
            ("tier", "1".to_string()),
            ("category", "\"threat\"".to_string()),
            ("severity", "\"critical\"".to_string()),
            ("class", "1".to_string()),
            ("kinds", "\"Generic\"".to_string()),
            ("status", "\"probation\"".to_string()),
            ("plain", "\"A rule under lint.\"".to_string()),
            ("description", "\"A rule under lint.\"".to_string()),
            ("references", "\"none\"".to_string()),
            ("sensitive", "false".to_string()),
        ];
        for (key, value) in lines {
            match (block.iter_mut().find(|(name, _)| name == key), value) {
                (Some(entry), Some(value)) => entry.1 = (*value).to_string(),
                (Some(_), None) => block.retain(|(name, _)| name != key),
                (None, Some(value)) => block.push((key, (*value).to_string())),
                (None, None) => {}
            }
        }
        let meta: String = block
            .iter()
            .map(|(key, value)| format!("    {key} = {value}\n"))
            .collect();
        format!("rule as_0021_under_lint {{\n  meta:\n{meta}  condition:\n    false\n}}\n")
    }

    /// Compiles one rule source as a pack of its own and returns what the lint
    /// said about it.
    fn lint_of(source: String) -> Result<(), String> {
        let leaked: &'static str = Box::leak(source.into_boxed_str());
        let sources = vec![RuleSource {
            origin: "0021-under-lint/rule.yar",
            source: leaked,
        }];
        match RulePack::compile(&sources) {
            Ok(_) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    #[test]
    fn a_rule_missing_a_required_meta_key_is_rejected() {
        for key in [
            "id",
            "title",
            "tier",
            "category",
            "severity",
            "class",
            "kinds",
            "status",
            "plain",
            "description",
            "references",
            "sensitive",
        ] {
            let problem = lint_of(meta_variant(&[(key, None)]))
                .expect_err("a rule missing a required key does not load");
            assert!(
                problem.contains(key),
                "the rejection of a missing `{key}` does not name it: {problem}"
            );
        }
    }

    #[test]
    fn a_weight_on_a_tier_1_rule_is_rejected() {
        let problem = lint_of(meta_variant(&[("weight", Some("2"))]))
            .expect_err("a tier 1 rule carries no weight");
        assert!(problem.contains("weight"), "{problem}");
        assert!(problem.contains("as_0021_under_lint"), "{problem}");
    }

    #[test]
    fn a_reviewer_directed_flag_on_a_tier_1_rule_is_rejected() {
        let problem = lint_of(meta_variant(&[("reviewer_directed", Some("true"))]))
            .expect_err("reviewer_directed is a tier 2 key");
        assert!(problem.contains("reviewer_directed"), "{problem}");
    }

    #[test]
    fn a_tier_2_threat_rule_without_a_weight_is_rejected() {
        let problem = lint_of(meta_variant(&[
            ("tier", Some("2")),
            ("severity", Some("\"high\"")),
        ]))
        .expect_err("a tier 2 threat rule declares a weight");
        assert!(problem.contains("weight"), "{problem}");
    }

    #[test]
    fn a_tier_2_exposure_rule_with_a_weight_is_rejected() {
        let problem = lint_of(meta_variant(&[
            ("tier", Some("2")),
            ("category", Some("\"exposure\"")),
            ("severity", Some("\"medium\"")),
            ("weight", Some("2")),
        ]))
        .expect_err("an exposure heuristic carries no weight");
        assert!(problem.contains("weight"), "{problem}");
    }

    #[test]
    fn a_tier_2_threat_rule_with_its_weight_loads() {
        lint_of(meta_variant(&[
            ("tier", Some("2")),
            ("severity", Some("\"medium\"")),
            ("weight", Some("3")),
            ("reviewer_directed", Some("true")),
        ]))
        .expect("a heuristic with a weight passes the lint");
    }

    #[test]
    fn a_tier_1_threat_rule_below_high_is_rejected() {
        let problem = lint_of(meta_variant(&[("severity", Some("\"medium\""))]))
            .expect_err("a tier 1 threat rule is critical or high");
        assert!(problem.contains("critical or high"), "{problem}");
    }

    #[test]
    fn a_class_outside_the_threat_model_is_rejected() {
        let problem = lint_of(meta_variant(&[("class", Some("7"))]))
            .expect_err("the threat model ranks six classes");
        assert!(problem.contains("class"), "{problem}");
    }

    #[test]
    fn a_rule_id_that_does_not_match_its_directory_is_rejected() {
        static WRONG: &[RuleSource] = &[RuleSource {
            origin: "0042-mislabelled/rule.yar",
            source: r#"
rule as_0043_mislabelled {
  meta:
    id = 43
    title = "Mislabelled"
    tier = 1
    category = "threat"
    severity = "high"
    class = 1
    kinds = "Generic"
    status = "probation"
    plain = "Mislabelled."
    description = "Mislabelled."
    references = "none"
    sensitive = false
  condition:
    false
}
"#,
        }];
        let error = RulePack::compile(WRONG).expect_err("the id does not match the directory");
        assert!(matches!(error, RuleError::Meta { .. }), "{error}");
    }
}
