//! The Heuristic tier (T2): the Score, the Bands and what comes out of them.
//!
//! A Heuristic raises suspicion instead of deciding, so no single one is worth
//! showing. The unit is the Item: every `tier = 2`, `category = "threat"`
//! Heuristic that fires contributes its Weight once, however many matches it
//! made and however many files of a tree it landed on, and the sum is the
//! Score. Where the Score falls decides the Band, and the two thresholds come
//! from the Rule Pack manifest so a pack release can retune them.
//!
//! What each Band produces (spec section 4.3, `rules/README.md`):
//!
//! - Clear: nothing. The fired Heuristics are Item detail for the Developer
//!   Posture and no more.
//! - Ambiguous: no Finding either. The Item is what AI Judgement is asked
//!   about, and the Simple Posture never sees it.
//! - Suspicious: one Threat Finding for the whole Item, carrying the fired
//!   Heuristics so the user reads their `plain` lines rather than a number.
//!
//! Two things override that. Under a Probation Rule hit the fired Heuristics
//! are supporting detail of that Finding, never a second Finding; and an Item
//! a stable Rule settled is not a Heuristic's business at all. Exposure
//! Heuristics stand outside the Score: they carry no Weight and each raises
//! its own Exposure Finding.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt;

use crate::finding::{Category, Finding, FiredHeuristic, RuleStatus, Severity, Source, Tier};
use crate::item::{Item, ItemId};
use crate::pack::Bands;
use crate::rules::{RuleMeta, RulePack};
use crate::scan::{RuleHit, ScanFailure, Scanners};
use crate::views::Views;

/// The developer-facing one line of a Suspicious Finding.
pub const SUSPICIOUS_TITLE: &str = "Several Heuristics fired on one Item";

/// The one sentence the Simple Posture shows above the fired Heuristics'
/// `plain` lines. It never names a Score, a Weight or a threshold.
pub const SUSPICIOUS_PLAIN: &str = "Several things about this item look wrong at once, and together they are more \
     than one odd habit.";

/// Where an Item's Score falls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Band {
    /// Below the first threshold: nothing to say.
    Clear,
    /// Between the thresholds: the AI Judgement queue, no Finding, invisible
    /// in the Simple Posture.
    Ambiguous,
    /// At the second threshold and up: one Threat Finding the user may
    /// quarantine by hand.
    Suspicious,
}

impl Band {
    /// Where a Score falls, under the thresholds the Rule Pack states.
    pub fn of(score: i64, bands: Bands) -> Band {
        if score >= bands.suspicious_at {
            Band::Suspicious
        } else if score >= bands.ambiguous_at {
            Band::Ambiguous
        } else {
            Band::Clear
        }
    }

    /// The name the Developer Posture and the CLI print.
    pub fn as_str(self) -> &'static str {
        match self {
            Band::Clear => "Clear",
            Band::Ambiguous => "Ambiguous",
            Band::Suspicious => "Suspicious",
        }
    }
}

impl fmt::Display for Band {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the detection ladder made of one Item: its Findings, its Score and the
/// Band that Score puts it in.
#[derive(Clone, Debug)]
pub struct Assessment {
    /// The Item the Assessment is about. An Ambiguous Item raises no Finding,
    /// so this is the only place its id is named.
    pub item_id: ItemId,
    /// The Score: the sum of the Weights of the Threat Heuristics that fired,
    /// each counted once.
    pub score: i64,
    /// Where that Score falls.
    pub band: Band,
    /// The Threat Heuristics that fired, once each, in id order. Empty when a
    /// stable Rule settled the Item, because then the Heuristic tier does not
    /// run on it.
    pub fired: Vec<FiredHeuristic>,
    /// Everything the user is shown about the Item.
    pub findings: Vec<Finding>,
}

impl Assessment {
    /// True when the Score fell between the thresholds.
    pub fn is_ambiguous(&self) -> bool {
        self.band == Band::Ambiguous
    }

    /// True when the Item belongs in the AI Judgement queue: its Score is
    /// Ambiguous and nothing else has anything to say about it. An Item whose
    /// Heuristics folded into a Rule Finding is already flagged, so asking an
    /// engine about it would change nothing.
    pub fn awaits_judgement(&self) -> bool {
        self.band == Band::Ambiguous && self.findings.is_empty()
    }
}

impl<'p> Scanners<'p> {
    /// Runs every Rule and Heuristic that applies to the Item over every unit
    /// of it, then scores what fired and places the Item in a Band.
    ///
    /// This is the whole detection ladder below AI Judgement for one Item, and
    /// the path a Scan takes. [`Scanners::run`] stays the seam for the corpus
    /// runner, which wants the bare hits.
    pub fn assess(&mut self, item: &Item) -> Result<Assessment, ScanFailure> {
        let pack: &'p RulePack = self.pack();
        let bands = self.bands();
        let mut hits = Vec::new();
        for unit in item.scan_units() {
            let globals = Views::of(item, &unit).globals();
            hits.extend(self.run(item.kind, &globals, &unit)?);
        }
        Ok(assess_hits(pack, bands, item, &hits))
    }
}

/// Turns the Rules and Heuristics that fired on one Item into an Assessment.
/// Separate from the scan so a test can state the hits instead of producing
/// them.
pub fn assess_hits(pack: &RulePack, bands: Bands, item: &Item, hits: &[RuleHit]) -> Assessment {
    let mut rule_findings: Vec<Finding> = Vec::new();
    let mut exposures: BTreeMap<i64, Finding> = BTreeMap::new();
    let mut fired: BTreeMap<i64, FiredHeuristic> = BTreeMap::new();

    for hit in hits {
        let Some(meta) = pack.meta(&hit.rule) else {
            continue;
        };
        match (meta.tier, meta.category) {
            (Tier::Rules, _) => rule_findings.push(finding_of(item, meta, hit)),
            (Tier::Heuristics, Category::Exposure) => {
                exposures
                    .entry(meta.id)
                    .or_insert_with(|| finding_of(item, meta, hit));
            }
            (Tier::Heuristics, Category::Threat) => {
                fired
                    .entry(meta.id)
                    .or_insert_with(|| fired_heuristic_of(meta, hit));
            }
            _ => {}
        }
    }

    // A stable Rule quarantines the Item; the Heuristic tier runs on what is
    // left undecided and this Item is not that.
    let settled = rule_findings.iter().any(|finding| {
        finding.category == Category::Threat && finding.status == RuleStatus::Stable
    });
    if settled {
        rule_findings.sort_by_key(order);
        return Assessment {
            item_id: item.id.clone(),
            score: 0,
            band: Band::Clear,
            fired: Vec::new(),
            findings: rule_findings,
        };
    }

    let fired: Vec<FiredHeuristic> = fired.into_values().collect();
    let score: i64 = fired.iter().map(|heuristic| heuristic.weight).sum();
    let band = Band::of(score, bands);

    let mut findings = rule_findings;
    findings.extend(exposures.into_values());
    findings.sort_by_key(order);

    match (fold_into(&findings), band) {
        (Some(index), _) => findings[index].heuristics = fired.clone(),
        (None, Band::Suspicious) => findings.push(suspicious_finding(item, score, &fired)),
        (None, _) => {}
    }

    Assessment {
        item_id: item.id.clone(),
        score,
        band,
        fired,
        findings,
    }
}

/// The Finding the fired Heuristics fold into as "Also noticed": the Probation
/// Rule Threat Finding with the most to say, the lowest id breaking a tie.
/// None when no Rule fired, which is when the Band speaks for itself.
fn fold_into(findings: &[Finding]) -> Option<usize> {
    findings
        .iter()
        .enumerate()
        .filter(|(_, finding)| finding.tier == Tier::Rules && finding.category == Category::Threat)
        // The Findings arrive in Rule order, so the first of equal severity is
        // the lowest id.
        .min_by_key(|(_, finding)| Reverse(finding.severity))
        .map(|(index, _)| index)
}

/// The one Threat Finding a Suspicious Item raises. It is about the Item, not
/// about one file or one pattern: what it carries is the Heuristics that
/// fired, each with its own `plain` line.
fn suspicious_finding(item: &Item, score: i64, fired: &[FiredHeuristic]) -> Finding {
    Finding {
        item_id: item.id.clone(),
        source: Source::Score(score),
        content_hash: item.content_hash.clone(),
        category: Category::Threat,
        severity: fired
            .iter()
            .map(|heuristic| heuristic.severity)
            .max()
            .unwrap_or(Severity::Low),
        tier: Tier::Heuristics,
        status: RuleStatus::Stable,
        title: SUSPICIOUS_TITLE.to_string(),
        plain: SUSPICIOUS_PLAIN.to_string(),
        sensitive: fired.iter().any(|heuristic| heuristic.sensitive),
        file: String::new(),
        matches: Vec::new(),
        heuristics: fired.to_vec(),
        // Drift is the Scan pass's to fold in: it is a condition on the Item,
        // not something a Rule or a Heuristic saw in the bytes.
        drift: None,
    }
}

/// One Finding from one Rule or Exposure Heuristic that fired.
fn finding_of(item: &Item, meta: &RuleMeta, hit: &RuleHit) -> Finding {
    Finding {
        item_id: item.id.clone(),
        source: Source::Rule(meta.id),
        content_hash: item.content_hash.clone(),
        category: meta.category,
        severity: meta.severity,
        tier: meta.tier,
        status: meta.status,
        title: meta.title.clone(),
        plain: meta.plain.clone(),
        sensitive: meta.sensitive,
        file: hit.file.clone(),
        matches: hit.matches.clone(),
        heuristics: Vec::new(),
        drift: None,
    }
}

/// One fired Threat Heuristic, with the Weight it contributes to the Score.
fn fired_heuristic_of(meta: &RuleMeta, hit: &RuleHit) -> FiredHeuristic {
    FiredHeuristic {
        id: meta.id,
        weight: meta.weight.unwrap_or(0),
        title: meta.title.clone(),
        plain: meta.plain.clone(),
        severity: meta.severity,
        sensitive: meta.sensitive,
        reviewer_directed: meta.reviewer_directed,
        file: hit.file.clone(),
        matches: hit.matches.clone(),
    }
}

/// Findings read in Rule order, with the Item's own Band Finding last. A
/// Problem never reaches this: it belongs to no Item and the Scan appends it.
fn order(finding: &Finding) -> (u8, i64) {
    match finding.source {
        Source::Rule(id) => (0, id),
        Source::Score(score) => (1, score),
        Source::Drift => (2, 0),
        Source::Problem(_) => (3, 0),
        Source::KeepsComingBack => (4, 0),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::item::{Activation, Kind, Provenance, Scope};
    use crate::pack::Manifest;
    use crate::rules::{RulePack, RuleSource};

    fn an_item(content: &str) -> Item {
        Item::file(
            "claude-code",
            Scope::Project(PathBuf::from("/src/demo")),
            Kind::InstructionFile,
            "CLAUDE.md",
            PathBuf::from("/src/demo/CLAUDE.md"),
            Provenance::Unknown,
            Activation::Active,
            content.as_bytes().to_vec(),
        )
    }

    /// A pack of rules written for one test. The sources are leaked because a
    /// [`RuleSource`] travels for the life of the pack and a test's pack lives
    /// as long as the test.
    fn pack_of(sources: Vec<(&'static str, String)>) -> RulePack {
        let leaked: Vec<RuleSource> = sources
            .into_iter()
            .map(|(origin, source)| RuleSource {
                origin,
                source: Box::leak(source.into_boxed_str()),
            })
            .collect();
        RulePack::compile(&leaked).expect("the test pack compiles")
    }

    /// One rule under test: the meta a test cares about, and the string it
    /// fires on.
    struct UnderTest {
        id: i64,
        slug: &'static str,
        tier: i64,
        category: &'static str,
        severity: &'static str,
        weight: Option<i64>,
        status: &'static str,
        marker: &'static str,
    }

    impl UnderTest {
        /// The rule source, with every other meta key left valid.
        fn source(&self) -> String {
            let UnderTest {
                id,
                slug,
                tier,
                category,
                severity,
                status,
                marker,
                ..
            } = self;
            let weight = self
                .weight
                .map(|weight| format!("    weight = {weight}\n"))
                .unwrap_or_default();
            format!(
                "rule as_{id:04}_{slug} {{\n  meta:\n    id = {id}\n\
                     title = \"Heuristic {id}\"\n    tier = {tier}\n\
                     category = \"{category}\"\n    severity = \"{severity}\"\n\
{weight}    class = 1\n    kinds = \"InstructionFile\"\n    status = \"{status}\"\n\
                 plain = \"Plain {id}.\"\n    description = \"Under test.\"\n\
                 references = \"none\"\n    sensitive = false\n\
               strings:\n    $m = \"{marker}\"\n  condition:\n    $m\n}}\n"
            )
        }
    }

    /// Two Rules, one on Probation and one stable, three Threat Heuristics of
    /// Weight 2, 2 and 1, and one Exposure Heuristic.
    fn a_pack() -> RulePack {
        let under_test = [
            (
                "0001-under-test/rule.yar",
                UnderTest {
                    id: 1,
                    slug: "under_test",
                    tier: 1,
                    category: "threat",
                    severity: "critical",
                    weight: None,
                    status: "probation",
                    marker: "RULE-ONE",
                },
            ),
            (
                "0002-stable-rule/rule.yar",
                UnderTest {
                    id: 2,
                    slug: "stable_rule",
                    tier: 1,
                    category: "threat",
                    severity: "high",
                    weight: None,
                    status: "stable",
                    marker: "RULE-TWO",
                },
            ),
            (
                "0500-first/rule.yar",
                UnderTest {
                    id: 500,
                    slug: "first",
                    tier: 2,
                    category: "threat",
                    severity: "high",
                    weight: Some(2),
                    status: "stable",
                    marker: "WEIGHT-TWO-A",
                },
            ),
            (
                "0501-second/rule.yar",
                UnderTest {
                    id: 501,
                    slug: "second",
                    tier: 2,
                    category: "threat",
                    severity: "medium",
                    weight: Some(2),
                    status: "stable",
                    marker: "WEIGHT-TWO-B",
                },
            ),
            (
                "0502-weak/rule.yar",
                UnderTest {
                    id: 502,
                    slug: "weak",
                    tier: 2,
                    category: "threat",
                    severity: "low",
                    weight: Some(1),
                    status: "stable",
                    marker: "WEIGHT-ONE",
                },
            ),
            (
                "0506-exposed/rule.yar",
                UnderTest {
                    id: 506,
                    slug: "exposed",
                    tier: 2,
                    category: "exposure",
                    severity: "medium",
                    weight: None,
                    status: "stable",
                    marker: "EXPOSED",
                },
            ),
        ];
        pack_of(
            under_test
                .iter()
                .map(|(origin, rule)| (*origin, rule.source()))
                .collect(),
        )
    }

    fn assess(pack: &RulePack, bands: Bands, content: &str) -> Assessment {
        let mut scanners = Scanners::with_bands(pack, bands);
        scanners.assess(&an_item(content)).expect("the scan runs")
    }

    #[test]
    fn a_score_below_the_first_threshold_is_clear_and_says_nothing() {
        let pack = a_pack();
        let assessment = assess(&pack, Bands::V1, "WEIGHT-ONE\n");
        assert_eq!(assessment.score, 1);
        assert_eq!(assessment.band, Band::Clear);
        assert_eq!(assessment.fired.len(), 1);
        assert!(assessment.findings.is_empty());
    }

    #[test]
    fn a_score_between_the_thresholds_is_ambiguous_and_raises_no_finding() {
        let pack = a_pack();
        let assessment = assess(&pack, Bands::V1, "WEIGHT-TWO-A\n");
        assert_eq!(assessment.score, 2);
        assert_eq!(assessment.band, Band::Ambiguous);
        assert!(assessment.is_ambiguous());
        assert!(assessment.findings.is_empty());
    }

    #[test]
    fn a_score_at_the_second_threshold_is_one_finding_listing_the_heuristics() {
        let pack = a_pack();
        let assessment = assess(&pack, Bands::V1, "WEIGHT-TWO-A and WEIGHT-TWO-B\n");
        assert_eq!(assessment.score, 4);
        assert_eq!(assessment.band, Band::Suspicious);
        assert_eq!(assessment.findings.len(), 1);

        let finding = &assessment.findings[0];
        assert_eq!(finding.source, Source::Score(4));
        assert_eq!(finding.tier, Tier::Heuristics);
        assert_eq!(finding.category, Category::Threat);
        assert_eq!(finding.severity, Severity::High, "the worst of the two");
        assert_eq!(finding.plain, SUSPICIOUS_PLAIN);
        let listed: Vec<i64> = finding.heuristics.iter().map(|h| h.id).collect();
        assert_eq!(listed, vec![500, 501]);
        assert_eq!(finding.heuristics[0].plain, "Plain 500.");
    }

    /// The Weight of a Heuristic counts once per Item, whatever it matched.
    #[test]
    fn one_heuristic_that_fires_many_times_still_counts_once() {
        let pack = a_pack();
        let assessment = assess(
            &pack,
            Bands::V1,
            "WEIGHT-TWO-A WEIGHT-TWO-A WEIGHT-TWO-A WEIGHT-TWO-A\n",
        );
        assert_eq!(assessment.score, 2);
        assert_eq!(assessment.band, Band::Ambiguous);
    }

    #[test]
    fn the_thresholds_come_from_the_manifest_and_not_from_the_code() {
        let pack = a_pack();
        let retuned = Manifest::parse(
            r#"{"pack_version":2,"minimum_engine_version":"0.1.0",
                "released_at":"2026-09-25T08:00:00Z",
                "heuristics":{"ambiguous_at":1,"suspicious_at":2},"files":{}}"#,
        )
        .expect("the retuned manifest reads back")
        .bands;

        let content = "WEIGHT-TWO-A\n";
        assert_eq!(assess(&pack, Bands::V1, content).band, Band::Ambiguous);
        assert_eq!(assess(&pack, retuned, content).band, Band::Suspicious);
        assert_eq!(assess(&pack, retuned, content).findings.len(), 1);

        let quiet = Manifest::parse(
            r#"{"pack_version":3,"minimum_engine_version":"0.1.0",
                "released_at":"2026-09-25T08:00:00Z",
                "heuristics":{"ambiguous_at":6,"suspicious_at":9},"files":{}}"#,
        )
        .expect("the quiet manifest reads back")
        .bands;
        assert_eq!(assess(&pack, quiet, content).band, Band::Clear);
    }

    #[test]
    fn a_probation_rule_hit_folds_the_heuristics_in_instead_of_raising_a_second_finding() {
        let pack = a_pack();
        let assessment = assess(
            &pack,
            Bands::V1,
            "RULE-ONE with WEIGHT-TWO-A and WEIGHT-TWO-B\n",
        );
        assert_eq!(assessment.band, Band::Suspicious);
        assert_eq!(assessment.findings.len(), 1, "never a second Finding");

        let finding = &assessment.findings[0];
        assert_eq!(finding.source, Source::Rule(1));
        assert_eq!(finding.tier, Tier::Rules);
        assert!(finding.on_probation());
        let noticed: Vec<i64> = finding.also_noticed().iter().map(|h| h.id).collect();
        assert_eq!(noticed, vec![500, 501]);
    }

    #[test]
    fn a_probation_rule_hit_folds_an_ambiguous_score_in_as_well() {
        let pack = a_pack();
        let assessment = assess(&pack, Bands::V1, "RULE-ONE with WEIGHT-TWO-A\n");
        assert_eq!(assessment.band, Band::Ambiguous);
        assert_eq!(assessment.findings.len(), 1);
        assert_eq!(assessment.findings[0].also_noticed().len(), 1);
    }

    /// An Item a stable Rule settles is quarantined; the Heuristic tier runs
    /// on what is left undecided, so it contributes nothing here.
    #[test]
    fn a_stable_rule_hit_keeps_the_heuristic_tier_off_the_item() {
        let pack = a_pack();
        let assessment = assess(
            &pack,
            Bands::V1,
            "RULE-TWO with WEIGHT-TWO-A and WEIGHT-TWO-B and EXPOSED\n",
        );
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.band, Band::Clear);
        assert!(assessment.fired.is_empty());
        assert_eq!(assessment.findings.len(), 1);
        assert_eq!(assessment.findings[0].source, Source::Rule(2));
        assert!(assessment.findings[0].also_noticed().is_empty());
    }

    #[test]
    fn an_exposure_heuristic_raises_its_own_finding_and_carries_no_weight() {
        let pack = a_pack();
        let assessment = assess(&pack, Bands::V1, "EXPOSED and WEIGHT-ONE\n");
        assert_eq!(assessment.score, 1, "an Exposure Heuristic is not scored");
        assert_eq!(assessment.band, Band::Clear);
        assert_eq!(assessment.findings.len(), 1);

        let finding = &assessment.findings[0];
        assert_eq!(finding.source, Source::Rule(506));
        assert_eq!(finding.category, Category::Exposure);
        assert_eq!(finding.tier, Tier::Heuristics);
        assert!(finding.heuristics.is_empty());
    }

    #[test]
    fn an_exposure_finding_stands_beside_a_suspicious_one() {
        let pack = a_pack();
        let assessment = assess(
            &pack,
            Bands::V1,
            "EXPOSED with WEIGHT-TWO-A and WEIGHT-TWO-B\n",
        );
        assert_eq!(assessment.band, Band::Suspicious);
        let sources: Vec<Source> = assessment
            .findings
            .iter()
            .map(|finding| finding.source)
            .collect();
        assert_eq!(sources, vec![Source::Rule(506), Source::Score(4)]);
    }

    #[test]
    fn a_band_reads_the_thresholds_it_is_given() {
        let bands = Bands {
            ambiguous_at: 2,
            suspicious_at: 4,
        };
        assert_eq!(Band::of(0, bands), Band::Clear);
        assert_eq!(Band::of(1, bands), Band::Clear);
        assert_eq!(Band::of(2, bands), Band::Ambiguous);
        assert_eq!(Band::of(3, bands), Band::Ambiguous);
        assert_eq!(Band::of(4, bands), Band::Suspicious);
        assert_eq!(Band::of(40, bands), Band::Suspicious);
        assert_eq!(Band::Ambiguous.to_string(), "Ambiguous");
    }
}
