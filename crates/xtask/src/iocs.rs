//! Rendering the Indicator Lists into their generated Rules.
//!
//! An Indicator List is a plain list of hosts, addresses, package names or
//! file names known from published incidents. It is edited as a list and never
//! as a Rule (`iocs/README.md`), and the pack build renders it into the
//! generated Rule that carries its fixed id. Both the list and the generated
//! Rule are committed, and the corpus test fails when the committed Rule is
//! not what the list renders to.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// What a generated Rule states besides its entries. Everything here is fixed
/// by the v1 Rule list (spec section 4.2.1) and by `iocs/README.md`.
#[derive(Clone, Copy, Debug)]
pub struct Generated {
    /// The Rule id, 0900 to 0999.
    pub id: i64,
    /// The slug of the Rule directory, after the id.
    pub slug: &'static str,
    /// The Indicator List the Rule is rendered from.
    pub list: &'static str,
    /// The developer-facing one line.
    pub title: &'static str,
    /// The kinds the Rule applies to.
    pub kinds: &'static str,
    /// The one sentence the Simple Posture shows.
    pub plain: &'static str,
    /// What fires and why.
    pub description: &'static str,
    /// The letter the patterns are named after.
    pub tag: char,
    /// The pattern modifiers every entry carries, when it is matched in the
    /// bytes.
    pub modifiers: &'static str,
    /// What an entry is matched against.
    pub matched: Matched,
}

/// What a generated Rule matches an entry against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Matched {
    /// The bytes under scan and nothing else.
    Bytes,
    /// The bytes under scan, or the package an MCP server entry installs,
    /// which is a view field and not part of the bytes of every Item the
    /// entry reaches.
    BytesOrMcpPackage,
    /// The file of a tree the scan is on, or the path of the Item, and never
    /// the bytes (owner decision 3 of 2026-09-28). A dropped file is caught
    /// by its name when its own bytes say nothing, and a `.gitignore` or a
    /// README that only names it is not the file.
    NameOrPath,
}

/// Every kind a generated Rule scans: the "text" column of the v1 Rule list.
const TEXT_KINDS: &str =
    "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Workflow,ExecPolicy,Generic";

/// The four generated Rules, one per Indicator List.
pub const GENERATED: [Generated; 4] = [
    Generated {
        id: 900,
        slug: "ioc-hosts",
        list: "hosts.txt",
        title: "Known malicious host",
        kinds: "Skill,InstructionFile,Hook,McpServer,Plugin,Subagent,Marketplace,Workflow,ExecPolicy,Generic",
        plain: "This file contacts a server that is known to distribute malware.",
        description: "Exact host names taken from published incident reports (iocs/hosts.txt). Regenerated on every pack build.",
        tag: 'h',
        modifiers: "nocase fullword",
        matched: Matched::Bytes,
    },
    Generated {
        id: 901,
        slug: "ioc-ips",
        list: "ips.txt",
        title: "Known command-and-control address",
        kinds: TEXT_KINDS,
        plain: "This file contacts a machine that attackers are known to control.",
        description: "Exact addresses taken from published incident reports (iocs/ips.txt). An address that only contains an entry, such as one digit longer, is not a whole word and stays silent. Regenerated on every pack build.",
        tag: 'i',
        modifiers: "fullword",
        matched: Matched::Bytes,
    },
    Generated {
        id: 902,
        slug: "ioc-packages",
        list: "packages.txt",
        title: "Known malicious package",
        kinds: TEXT_KINDS,
        plain: "This configuration installs a package that is known to be malicious.",
        description: "Package names taken from published incident reports (iocs/packages.txt), matched as a whole word in the bytes under scan and against the package an MCP server entry installs. A longer name that merely starts with an entry is not a whole word and stays silent. Regenerated on every pack build.",
        tag: 'p',
        modifiers: "fullword",
        matched: Matched::BytesOrMcpPackage,
    },
    Generated {
        id: 903,
        slug: "ioc-files",
        list: "files.txt",
        title: "File name dropped by a known campaign",
        kinds: TEXT_KINDS,
        plain: "This item carries a file that a known attack campaign drops.",
        description: "File names taken from published incident reports (iocs/files.txt), matched as the last path component of the file of a tree the scan is on or of the Item's own path, which is what catches a dropped file whose own bytes say nothing. The content is never read: a .gitignore or a README that names a listed file is not that file and stays silent, and so does a longer name that merely ends with an entry, such as tsconfig.tsbuildinfo. Regenerated on every pack build.",
        tag: 'f',
        // No pattern is rendered: the entries are matched against names only.
        modifiers: "",
        matched: Matched::NameOrPath,
    },
];

/// What went wrong while rendering.
#[derive(Debug)]
pub struct RenderError {
    /// The Indicator List the problem is about.
    pub list: String,
    /// What is wrong with it.
    pub problem: String,
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "indicator list {}: {}", self.list, self.problem)
    }
}

impl Error for RenderError {}

impl Generated {
    /// The Rule directory name, such as `0900-ioc-hosts`.
    pub fn directory(&self) -> String {
        format!("{:04}-{}", self.id, self.slug)
    }

    /// The YARA name, such as `as_0900_ioc_hosts`.
    pub fn name(&self) -> String {
        format!("as_{:04}_{}", self.id, self.slug.replace('-', "_"))
    }

    /// Where the generated Rule is committed, under a repository root.
    pub fn rule_path(&self, root: &Path) -> PathBuf {
        root.join("rules").join(self.directory()).join("rule.yar")
    }

    /// Where the Indicator List is committed, under a repository root.
    pub fn list_path(&self, root: &Path) -> PathBuf {
        root.join("iocs").join(self.list)
    }

    /// Renders the Rule from the list as it is committed.
    pub fn render_from(&self, root: &Path) -> Result<String, RenderError> {
        let text = fs::read_to_string(self.list_path(root)).map_err(|error| RenderError {
            list: self.list.to_string(),
            problem: format!("could not be read: {error}"),
        })?;
        let entries = entries(&text);
        if entries.is_empty() {
            return Err(RenderError {
                list: self.list.to_string(),
                problem: "holds no entry, and a rule with no pattern does not compile".to_string(),
            });
        }
        Ok(self.render(&entries))
    }

    /// Renders the Rule from a list of entries.
    pub fn render(&self, entries: &[String]) -> String {
        let mut rule = format!(
            "// GENERATED from iocs/{} by the pack build. Do not edit by hand.\nrule {} {{\n  meta:\n",
            self.list,
            self.name()
        );
        for (key, value) in [
            ("id", self.id.to_string()),
            ("title", quoted(self.title)),
            ("tier", "1".to_string()),
            ("category", quoted("threat")),
            ("severity", quoted("critical")),
            ("class", "1".to_string()),
            ("kinds", quoted(self.kinds)),
            ("status", quoted("probation")),
            ("plain", quoted(self.plain)),
            ("description", quoted(self.description)),
            ("references", quoted("docs/research/attack-catalogue.md#3")),
            ("sensitive", "false".to_string()),
        ] {
            rule.push_str(&format!("    {key:<11} = {value}\n"));
        }

        if self.matched == Matched::NameOrPath {
            // A path component: the whole name at the end of the file of a
            // tree or of the Item's path, so tsconfig.tsbuildinfo is not
            // .tsbuildinfo.
            rule.push_str("\n  condition:");
            for (index, entry) in entries.iter().enumerate() {
                let component = format!("/(^|\\/){}$/", escaped(entry));
                rule.push_str(if index == 0 { "\n    " } else { "\n    or " });
                rule.push_str(&format!(
                    "item.file matches {component}\n    or item.path matches {component}"
                ));
            }
            rule.push_str("\n}\n");
            return rule;
        }

        rule.push_str("\n  strings:\n");
        for (index, entry) in entries.iter().enumerate() {
            rule.push_str(&format!(
                "    ${}{index} = {} {}\n",
                self.tag,
                quoted(entry),
                self.modifiers
            ));
        }

        rule.push_str("\n  condition:\n    any of them");
        if self.matched == Matched::BytesOrMcpPackage {
            for entry in entries {
                rule.push_str(&format!("\n    or mcp.package == {}", quoted(entry)));
            }
        }
        rule.push_str("\n}\n");
        rule
    }
}

/// The entries of an Indicator List: one per line, `#` comments and blank
/// lines left out, in the order the list has them.
pub fn entries(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// One entry as a YARA string literal.
fn quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// One entry as a YARA regular expression, with every character that means
/// something to the engine escaped.
fn escaped(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if "\\^$.|?*+()[]{}/-".contains(character) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_blank_lines_are_not_entries() {
        let list = "# a comment\n\nsocifiapp.com\n  angelic.su  \n";
        assert_eq!(entries(list), vec!["socifiapp.com", "angelic.su"]);
    }

    #[test]
    fn every_generated_rule_has_its_own_id_and_directory() {
        let mut seen = Vec::new();
        for generated in GENERATED {
            assert!(!seen.contains(&generated.id), "{} is reused", generated.id);
            assert!((900..=999).contains(&generated.id));
            seen.push(generated.id);
        }
        assert_eq!(GENERATED[0].directory(), "0900-ioc-hosts");
        assert_eq!(GENERATED[0].name(), "as_0900_ioc_hosts");
    }

    #[test]
    fn a_regular_expression_entry_escapes_what_the_engine_reads() {
        assert_eq!(escaped(".tsbuildinfo"), "\\.tsbuildinfo");
        assert_eq!(escaped("setup_bun.js"), "setup_bun\\.js");
    }

    #[test]
    fn the_rendering_carries_the_entries_and_the_required_meta() {
        let rule = GENERATED[0].render(&["host.example.invalid".to_string()]);
        assert!(rule.starts_with("// GENERATED from iocs/hosts.txt"));
        assert!(rule.contains("    id          = 900\n"));
        assert!(rule.contains("    $h0 = \"host.example.invalid\" nocase fullword\n"));
        assert!(rule.ends_with("  condition:\n    any of them\n}\n"));
    }

    /// A file name is matched against the file of a tree and the path of the
    /// Item, never against the bytes: a `.gitignore` or a README that names a
    /// listed file is not that file (owner decision 3).
    #[test]
    fn a_file_name_list_renders_into_path_conditions_and_no_pattern() {
        let files = GENERATED
            .iter()
            .find(|generated| generated.id == 903)
            .expect("rule 0903");
        let rule = files.render(&[".tsbuildinfo".to_string(), "setup_bun.js".to_string()]);
        assert!(!rule.contains("strings:"), "{rule}");
        assert!(!rule.contains("any of them"), "{rule}");
        assert!(
            rule.ends_with(
                "  condition:\n    item.file matches /(^|\\/)\\.tsbuildinfo$/\n    or item.path matches /(^|\\/)\\.tsbuildinfo$/\n    or item.file matches /(^|\\/)setup_bun\\.js$/\n    or item.path matches /(^|\\/)setup_bun\\.js$/\n}\n"
            ),
            "{rule}"
        );
    }

    /// Only the file name list changed how it matches; hosts, addresses and
    /// packages keep matching the bytes under scan.
    #[test]
    fn the_other_lists_keep_matching_content() {
        for generated in GENERATED.iter().filter(|generated| generated.id != 903) {
            let rule = generated.render(&["entry".to_string()]);
            assert!(rule.contains("  strings:\n"), "{rule}");
            assert!(rule.contains("  condition:\n    any of them"), "{rule}");
        }
    }
}
