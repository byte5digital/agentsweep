//! The defanging lint of the bad corpus.
//!
//! Every sample under `corpus/bad/` is modelled on a documented incident and
//! must never work as one. Spec section 4.2 fixes what defanged means: hosts end
//! in `.invalid` and every encoded payload decodes to `echo`. This lint holds
//! every file of every source to that, and holds every source to its
//! `PROVENANCE.md`, before the corpus runner lays a single sample out.
//!
//! What the lint reads as a host: the host of anything written as a URL, and
//! every bare dotted name whose last label is a public top-level domain. A
//! dotted name that ends in a file extension (`setup.sh`, `server.py`) is a
//! file, not a host, and stays silent. An IPv4 literal is a host too; only the
//! documentation ranges of RFC 5737 and the loopback and private ranges may
//! appear, because a sample that reaches a machine by its number needs a number
//! nobody can route to.
//!
//! What the lint reads as an encoded payload: a base64 run, a run of `\x`
//! escapes and a bare hex string, each long enough to carry a command. One that
//! decodes to text must decode to a single `echo` with nothing chained to it.
//! One that decodes to bytes that are not text carries no command and stays
//! silent.
//!
//! A file that is not UTF-8 text is a problem of its own: a sample the lint
//! cannot read is a sample nobody has proven defanged.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// The provenance file every source directory carries.
pub const PROVENANCE: &str = "PROVENANCE.md";

/// The description every sample directory carries.
pub const SAMPLE: &str = "sample.toml";

/// The two headings a provenance file must have: where the sample comes from
/// and what was changed to defang it.
pub const PROVENANCE_HEADINGS: [&str; 2] = ["## Public source", "## Defanged"];

/// The top-level domains a bare dotted name is read as a host for. File
/// extensions that are also country domains (`sh`, `py`, `md`, `rs`, `pl`) are
/// left out on purpose: in a sample they are files far more often than hosts.
const PUBLIC_TLDS: &[&str] = &[
    "ai", "app", "biz", "cc", "cloud", "cn", "co", "com", "de", "dev", "eu", "gg", "gl", "info",
    "io", "link", "lt", "ly", "me", "net", "online", "org", "page", "pub", "ru", "run", "site",
    "so", "store", "su", "tech", "tk", "top", "uk", "us", "xyz",
];

/// One thing wrong with the corpus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LintProblem {
    /// The file or directory, relative to `corpus/bad/`.
    pub path: String,
    /// What is wrong with it.
    pub problem: String,
}

impl fmt::Display for LintProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.problem)
    }
}

/// Lints a whole `corpus/bad/` directory: every source has its provenance
/// file and at least one sample, every sample has its description and
/// something laid out, and every file is defanged. A corpus with no source
/// yet is clean: the samples are written by a person, and until they are the
/// runner reports the bad set as insufficient rather than failing.
pub fn lint(corpus: &Path) -> Vec<LintProblem> {
    let mut problems = Vec::new();
    let Ok(entries) = fs::read_dir(corpus) else {
        problems.push(LintProblem {
            path: corpus.display().to_string(),
            problem: "the bad corpus could not be read".to_string(),
        });
        return problems;
    };
    let mut sources: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    sources.sort();
    for source in sources {
        lint_source(corpus, &source, &mut problems);
    }
    problems
}

fn lint_source(corpus: &Path, source: &Path, problems: &mut Vec<LintProblem>) {
    let name = relative(corpus, source);
    match fs::read_to_string(source.join(PROVENANCE)) {
        Ok(text) => {
            for heading in PROVENANCE_HEADINGS {
                if !text.lines().any(|line| line.trim_end() == heading) {
                    problems.push(LintProblem {
                        path: format!("{name}/{PROVENANCE}"),
                        problem: format!("the provenance file has no `{heading}` section"),
                    });
                }
            }
        }
        Err(_) => problems.push(LintProblem {
            path: name.clone(),
            problem: format!(
                "the source has no {PROVENANCE} naming its public source and how it was defanged"
            ),
        }),
    }

    let mut samples: Vec<_> = fs::read_dir(source)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect()
        })
        .unwrap_or_default();
    samples.sort();
    if samples.is_empty() {
        problems.push(LintProblem {
            path: name.clone(),
            problem: "the source holds no sample".to_string(),
        });
    }
    for sample in &samples {
        let sample_name = relative(corpus, sample);
        if !sample.join(SAMPLE).is_file() {
            problems.push(LintProblem {
                path: sample_name.clone(),
                problem: format!("the sample has no {SAMPLE}"),
            });
        }
        if !sample.join("home").is_dir() && !sample.join("project").is_dir() {
            problems.push(LintProblem {
                path: sample_name,
                problem: "the sample lays nothing out: it needs a `home/` or a `project/`"
                    .to_string(),
            });
        }
    }

    let mut files = Vec::new();
    collect_files(source, &mut files);
    files.sort();
    for file in files {
        let path = relative(corpus, &file);
        match fs::read(&file).map(String::from_utf8) {
            Ok(Ok(text)) => {
                for problem in defanging_problems(&text) {
                    problems.push(LintProblem {
                        path: path.clone(),
                        problem,
                    });
                }
            }
            Ok(Err(_)) => problems.push(LintProblem {
                path,
                problem: "the file is not UTF-8 text, so the lint cannot prove it defanged"
                    .to_string(),
            }),
            Err(error) => problems.push(LintProblem {
                path,
                problem: format!("the file could not be read: {error}"),
            }),
        }
    }
}

/// Everything in one text that is not defanged, one sentence each.
pub fn defanging_problems(text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for host in hosts(text) {
        problems.push(format!(
            "names the host `{host}`, and a sample's hosts end in `.invalid`"
        ));
    }
    for decoded in payloads(text) {
        problems.push(format!(
            "carries an encoded payload that decodes to `{}`, and every payload decodes to `echo`",
            shorten(&decoded)
        ));
    }
    problems
}

/// Every host in a text that a sample may not name.
pub fn hosts(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut push = |host: String| {
        if !found.contains(&host) {
            found.push(host);
        }
    };

    // The host of anything written as a URL, whatever its last label.
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let after = &rest[at + 3..];
        let end = after
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        '/' | '?' | '#' | '"' | '\'' | ')' | ']' | '>' | '`' | '\\' | ',' | ';'
                    )
            })
            .unwrap_or(after.len());
        let authority = &after[..end];
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let host = strip_port(host).trim_end_matches('.').to_ascii_lowercase();
        if host.contains('.') && !host_allowed(&host) {
            push(host);
        }
        rest = after;
    }

    // Every bare dotted name that ends in a public top-level domain, and every
    // IPv4 literal.
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
    {
        let token = token.trim_matches(|c| c == '.' || c == '-');
        if !token.contains('.') || token.contains('_') {
            continue;
        }
        let labels: Vec<&str> = token.split('.').collect();
        if labels.iter().any(|label| label.is_empty()) {
            continue;
        }
        let host = token.to_ascii_lowercase();
        if host_allowed(&host) {
            continue;
        }
        let last = labels
            .last()
            .map(|label| label.to_ascii_lowercase())
            .unwrap_or_default();
        if parse_ipv4(&host).is_some() || PUBLIC_TLDS.contains(&last.as_str()) {
            push(host);
        }
    }
    found
}

/// Strips a trailing `:port` from a URL host.
fn strip_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    }
}

/// True for a host a sample may name: anything under `.invalid`, and an IPv4
/// literal nobody can route to from the internet.
fn host_allowed(host: &str) -> bool {
    if host == "invalid" || host.ends_with(".invalid") {
        return true;
    }
    match parse_ipv4(host) {
        Some([a, b, c, _]) => {
            matches!(
                (a, b, c),
                (192, 0, 2)
                    | (198, 51, 100)
                    | (203, 0, 113)
                    | (127, _, _)
                    | (10, _, _)
                    | (192, 168, _)
                    | (169, 254, _)
                    | (0, 0, 0)
            ) || (a == 172 && (16..=31).contains(&b))
        }
        None => false,
    }
}

fn parse_ipv4(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (octet, part) in octets.iter_mut().zip(parts) {
        if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    Some(octets)
}

/// The decoded text of every encoded payload in a text that is not a lone
/// `echo`.
pub fn payloads(text: &str) -> Vec<String> {
    let mut bad: Vec<String> = Vec::new();
    let mut judge = |bytes: Vec<u8>| {
        if let Some(decoded) = as_text(&bytes)
            && !is_lone_echo(&decoded)
            && !bad.contains(&decoded)
        {
            bad.push(decoded);
        }
    };
    for run in runs(text, |c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
    }) {
        let run = run.trim_start_matches('=');
        if run.len() >= 16
            && let Some(bytes) = decode_base64(run)
        {
            judge(bytes);
        }
    }
    for run in runs(text, |c| c.is_ascii_hexdigit()) {
        if run.len() >= 8
            && run.len() % 2 == 0
            && let Some(bytes) = decode_hex(run)
        {
            judge(bytes);
        }
    }
    for bytes in escape_runs(text) {
        judge(bytes);
    }
    bad
}

/// Maximal runs of characters that satisfy a predicate.
fn runs(text: &str, keep: impl Fn(char) -> bool) -> Vec<&str> {
    text.split(|c: char| !keep(c))
        .filter(|run| !run.is_empty())
        .collect()
}

/// The bytes of every run of four or more `\xNN` escapes.
fn escape_runs(text: &str) -> Vec<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut current = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let escape = at + 3 < bytes.len()
            && bytes[at] == b'\\'
            && bytes[at + 1] == b'x'
            && bytes[at + 2].is_ascii_hexdigit()
            && bytes[at + 3].is_ascii_hexdigit();
        if escape {
            let pair = std::str::from_utf8(&bytes[at + 2..at + 4]).unwrap_or("00");
            current.push(u8::from_str_radix(pair, 16).unwrap_or(0));
            at += 4;
            continue;
        }
        if current.len() >= 4 {
            found.push(std::mem::take(&mut current));
        } else {
            current.clear();
        }
        at += 1;
    }
    if current.len() >= 4 {
        found.push(current);
    }
    found
}

/// Decodes standard base64, padded or not. `None` for a run that cannot be
/// base64 at all.
fn decode_base64(run: &str) -> Option<Vec<u8>> {
    let body = run.trim_end_matches('=');
    if body.contains('=') || body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    for c in body.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn decode_hex(run: &str) -> Option<Vec<u8>> {
    (0..run.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&run[at..at + 2], 16).ok())
        .collect()
}

/// The bytes as text when they read the way a command would: printable ASCII
/// and line breaks, at least four of them.
fn as_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 {
        return None;
    }
    let printable = bytes
        .iter()
        .all(|b| (0x20..0x7f).contains(b) || matches!(b, b'\n' | b'\r' | b'\t'));
    if !printable {
        return None;
    }
    String::from_utf8(bytes.to_vec()).ok()
}

/// True for a single `echo` with nothing chained, piped or substituted.
fn is_lone_echo(decoded: &str) -> bool {
    let trimmed = decoded.trim();
    let Some(rest) = trimmed.strip_prefix("echo") else {
        return false;
    };
    (rest.is_empty() || rest.starts_with(' '))
        && !rest.contains([';', '|', '&', '`', '$', '<', '>', '\n', '\r'])
}

fn shorten(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() > 60 {
        format!("{}...", flat.chars().take(60).collect::<String>())
    } else {
        flat
    }
}

fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, files);
        } else {
            files.push(path);
        }
    }
}

fn relative(corpus: &Path, path: &Path) -> String {
    path.strip_prefix(corpus)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_under_invalid_and_a_documentation_address_are_defanged() {
        assert!(hosts("see https://hello.example.invalid/greeting").is_empty());
        assert!(hosts("the printer at 192.0.2.10 says hello").is_empty());
        assert!(hosts("see setup.sh and server.py and .claude/settings.json").is_empty());
        assert!(hosts("mcp_servers.tools.command").is_empty());
    }

    #[test]
    fn a_real_host_is_named_wherever_it_stands() {
        assert_eq!(
            hosts("read https://www.example.com/hello"),
            vec!["www.example.com"]
        );
        assert_eq!(hosts("write to hello@greetings.net"), vec!["greetings.net"]);
        assert_eq!(hosts("open http://45.9.8.7:8080/a"), vec!["45.9.8.7"]);
        assert_eq!(hosts("https://intranet.corp/x"), vec!["intranet.corp"]);
    }

    #[test]
    fn only_a_lone_echo_is_a_defanged_payload() {
        // "echo defanged corpus sample"
        assert!(payloads("ZWNobyBkZWZhbmdlZCBjb3JwdXMgc2FtcGxl").is_empty());
        // "hello there friend"
        assert_eq!(
            payloads("aGVsbG8gdGhlcmUgZnJpZW5k"),
            vec!["hello there friend"]
        );
        // "echo hi; echo bye": an echo with something chained to it.
        assert_eq!(
            payloads("ZWNobyBoaTsgZWNobyBieWU="),
            vec!["echo hi; echo bye"]
        );
        // Escapes and a bare hex string, both spelling a greeting.
        assert_eq!(payloads(r"\x68\x65\x6c\x6c\x6f"), vec!["hello"]);
        assert_eq!(payloads("68656c6c6f20667269656e64"), vec!["hello friend"]);
    }

    #[test]
    fn a_word_or_a_digest_that_only_looks_encoded_stays_silent() {
        assert!(payloads("PreToolUseAndSessionStart /usr/local/bin/something").is_empty());
        assert!(
            payloads("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").is_empty()
        );
    }

    #[test]
    fn a_corpus_with_no_source_yet_is_clean() {
        let corpus = tempfile::tempdir().expect("a temporary directory");
        fs::write(corpus.path().join("README.md"), "# The bad corpus\n").expect("a README");
        assert_eq!(lint(corpus.path()), Vec::new());
    }
}
