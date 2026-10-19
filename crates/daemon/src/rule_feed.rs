//! The Rule Feed client: the one outbound request the daemon makes.
//!
//! Spec section 9.4 and ADR 0006. The index, `rules/latest.json` on the
//! repository's `feed` branch, is fetched from raw.githubusercontent.com at
//! daemon start and once a day with the due check, after up to an hour of
//! jitter, as a conditional request: the `ETag` and `Last-Modified` of the last
//! answer that was acted on go back as `If-None-Match` and `If-Modified-Since`,
//! so an unchanged index is one small answer and nothing else.
//!
//! The index is deliberately unsigned and says one thing: the newest pack
//! version, `{"pack_version": N}`. When that is newer than the pack in use,
//! the client downloads the assets of the release `rules-v<N>`, whose names are
//! fixed rather than read off the index: `manifest.json`, one `<KEY ID>.minisig`
//! per pinned key, and `pack.tar`. The signature is verified before the
//! manifest is read; the version compared is the signed manifest's, never the
//! index's, so a forged index can make a client download something and throw
//! it away, or freeze it, and never downgrade it. The archive is downloaded
//! only for a pack that is accepted.
//!
//! What goes out is the request and nothing else (spec section 1.1): no
//! machine name, no user, no identifier, no query string, and a User-Agent
//! that names the product and its version. A log line names the feed's host
//! and never a full address.

use std::collections::BTreeMap;
use std::time::Duration;

use agentsweep_core::pack::MANIFEST_FILE;
use agentsweep_core::pack_archive::{ARCHIVE_FILE, LARGEST_PACK};
use agentsweep_core::pack_signature::PINNED_KEYS;
use agentsweep_core::packs::{LoadedPack, PackStore, SignedManifest, Verdict, judge};
use agentsweep_core::state::IgnoredPack;

/// Where the index lives: `rules/latest.json` on the `feed` branch of the
/// project's repository.
pub const FEED_INDEX: &str =
    "https://raw.githubusercontent.com/byte5digital/agentsweep/feed/rules/latest.json";

/// Where the pack releases are: one `rules-v<N>` release per pack.
pub const FEED_RELEASES: &str = "https://github.com/byte5digital/agentsweep/releases/download";

/// The most a fetch waits before it asks, drawn afresh every time.
pub const JITTER_AT_MOST: Duration = Duration::from_secs(60 * 60);

/// How long after one fetch the due check asks for the next.
pub const FETCH_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// How long one request may take altogether, the pack archive included.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The largest index this client reads. It holds one number.
const LARGEST_INDEX: u64 = 64 * 1024;

/// The largest manifest: one hash per file of the pack.
const LARGEST_MANIFEST: u64 = 4 * 1024 * 1024;

/// The largest signature file. A minisign signature is four short lines.
const LARGEST_SIGNATURE: u64 = 4 * 1024;

/// Where the Rule Feed is asked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoints {
    /// The index.
    pub index: String,
    /// The base the release assets hang off: `<releases>/rules-v<N>/<asset>`.
    pub releases: String,
}

impl Endpoints {
    /// The project's own feed on GitHub, which is the only one a shipped
    /// daemon ever asks.
    pub fn github() -> Endpoints {
        Endpoints {
            index: FEED_INDEX.to_string(),
            releases: FEED_RELEASES.to_string(),
        }
    }

    /// The same layout under another origin, which is how a test points the
    /// daemon at a fixture server on the loopback address.
    pub fn under(origin: &str) -> Endpoints {
        let origin = origin.trim_end_matches('/');
        Endpoints {
            index: format!("{origin}/byte5digital/agentsweep/feed/rules/latest.json"),
            releases: format!("{origin}/byte5digital/agentsweep/releases/download"),
        }
    }

    /// The address of one asset of the release of one pack version.
    pub fn asset(&self, pack_version: u64, name: &str) -> String {
        format!(
            "{}/rules-v{pack_version}/{name}",
            self.releases.trim_end_matches('/')
        )
    }

    /// The host of the index, which is all a log line says about where the
    /// request went.
    pub fn host(&self) -> String {
        host_of(&self.index)
    }
}

/// The host part of an address, without scheme, path or anything else.
fn host_of(address: &str) -> String {
    let rest = address.split_once("://").map_or(address, |(_, rest)| rest);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// How the fetch is timed, so a test runs a day of fetches in a second.
#[derive(Clone, Debug)]
pub struct FeedTuning {
    /// Where to ask. Absent means the project's own feed for the installed
    /// daemon and no feed at all for a developer run, so a test or a hand run
    /// never reaches GitHub unless it names an endpoint.
    pub endpoints: Option<Endpoints>,
    /// The most a fetch waits before it asks.
    pub jitter: Duration,
    /// How long after one fetch the next one is due.
    pub every: Duration,
    /// How long a daemon that starts with no settings file holds its first
    /// fetch for the app's first settings hand-over: one hour, the jitter
    /// window (the owner's decision of 2026-10-14). Zero holds nothing.
    pub first_hold: Duration,
}

impl Default for FeedTuning {
    fn default() -> FeedTuning {
        FeedTuning {
            endpoints: None,
            jitter: JITTER_AT_MOST,
            every: FETCH_EVERY,
            first_hold: JITTER_AT_MOST,
        }
    }
}

/// A wait of up to `at_most`, drawn from the operating system's generator.
pub fn jitter(at_most: Duration) -> Duration {
    let millis = at_most.as_millis() as u64;
    if millis == 0 {
        return Duration::ZERO;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return at_most / 2;
    }
    Duration::from_millis(u64::from_le_bytes(bytes) % millis)
}

/// The validators of the last index answer that was acted on.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Validators {
    /// The `ETag`, sent back as `If-None-Match`.
    pub etag: String,
    /// The `Last-Modified`, sent back as `If-Modified-Since`.
    pub last_modified: String,
}

/// What one fetch came to.
#[derive(Debug)]
pub enum Fetched {
    /// The index has not changed since the last answer that was acted on.
    Unchanged,
    /// The feed offers nothing newer than the pack in use. `offered` is the
    /// version that was compared: the index's when nothing was downloaded,
    /// the signed manifest's when it was.
    NothingNewer {
        /// The version the feed offered.
        offered: u64,
        /// The version in use.
        in_use: u64,
    },
    /// A newer pack that needs a newer AgentSweep, ignored.
    NeedsNewerEngine(IgnoredPack),
    /// A newer pack verified, installed and ready to be put in force.
    Accepted(Box<LoadedPack>),
    /// A pack that was refused: a signature that does not verify, a manifest
    /// that is not one, an archive that does not match it.
    Refused(String),
    /// The feed answered, but an asset of the release was not there. Asked
    /// again at the next fetch.
    Incomplete(String),
    /// Nothing answered.
    Unreachable(String),
}

impl Fetched {
    /// True when the answer is settled for this index, so its validators are
    /// kept and the next fetch is conditional on them. A pack that could not
    /// be downloaded is not settled and is asked for again.
    fn settles(&self) -> bool {
        !matches!(self, Fetched::Incomplete(_) | Fetched::Unreachable(_))
    }
}

/// The HTTP side: one agent, one feed.
pub struct FeedClient {
    agent: ureq::Agent,
    endpoints: Endpoints,
}

/// What asking for the index came to.
enum Index {
    /// `304 Not Modified`.
    NotModified,
    /// A fresh index, with the validators it came with.
    Fresh {
        pack_version: u64,
        validators: Validators,
    },
}

/// Why a request came to nothing, as a short phrase with no address in it.
#[derive(Debug)]
enum Problem {
    /// Nothing answered, or the answer was cut off.
    Unreachable(String),
    /// The answer was not what was asked for.
    Refused(String),
}

impl FeedClient {
    /// A client for one feed. Status codes are answers, not errors: a `304`
    /// and a `404` both mean something here.
    pub fn new(endpoints: Endpoints) -> FeedClient {
        let https = endpoints.index.starts_with("https://");
        let config = ureq::Agent::config_builder()
            .user_agent(user_agent())
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .https_only(https)
            .max_redirects(5)
            .build();
        FeedClient {
            agent: ureq::Agent::new_with_config(config),
            endpoints,
        }
    }

    /// Where this client asks.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    fn index(&self, validators: &Validators) -> Result<Index, Problem> {
        let mut request = self.agent.get(&self.endpoints.index);
        if !validators.etag.is_empty() {
            request = request.header("If-None-Match", validators.etag.as_str());
        }
        if !validators.last_modified.is_empty() {
            request = request.header("If-Modified-Since", validators.last_modified.as_str());
        }
        let mut response = request.call().map_err(unreachable)?;
        match response.status().as_u16() {
            304 => Ok(Index::NotModified),
            200 => {
                let header = |name: &str| {
                    response
                        .headers()
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string()
                };
                let validators = Validators {
                    etag: header("etag"),
                    last_modified: header("last-modified"),
                };
                let body = response
                    .body_mut()
                    .with_config()
                    .limit(LARGEST_INDEX)
                    .read_to_vec()
                    .map_err(unreachable)?;
                let pack_version = parse_index(&body)
                    .ok_or_else(|| Problem::Refused("the index is not one".to_string()))?;
                Ok(Index::Fresh {
                    pack_version,
                    validators,
                })
            }
            status => Err(Problem::Unreachable(format!("the index answered {status}"))),
        }
    }

    /// One asset of one release. Nothing when the release does not have it.
    fn asset(&self, pack_version: u64, name: &str, limit: u64) -> Result<Option<Vec<u8>>, Problem> {
        let mut response = self
            .agent
            .get(&self.endpoints.asset(pack_version, name))
            .call()
            .map_err(unreachable)?;
        match response.status().as_u16() {
            200 => response
                .body_mut()
                .with_config()
                .limit(limit)
                .read_to_vec()
                .map(Some)
                .map_err(unreachable),
            404 => Ok(None),
            status => Err(Problem::Unreachable(format!("{name} answered {status}"))),
        }
    }
}

/// The User-Agent: the product and its version, nothing else.
pub fn user_agent() -> String {
    format!("{}/{}", agentsweep_core::NAME, agentsweep_core::VERSION)
}

/// What a failed request says in a log line: its kind, never the address or
/// anything the error carries beside it.
fn unreachable(error: ureq::Error) -> Problem {
    Problem::Unreachable(
        match error {
            ureq::Error::Timeout(_) => "timed out",
            ureq::Error::HostNotFound => "the host was not found",
            ureq::Error::ConnectionFailed => "the connection failed",
            ureq::Error::Io(_) => "the connection broke off",
            ureq::Error::BodyExceedsLimit(_) => "the answer was larger than it may be",
            ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => {
                "the redirects went nowhere"
            }
            ureq::Error::RequireHttpsOnly(_) => "a redirect left https",
            _ => "the request failed",
        }
        .to_string(),
    )
}

/// Reads the index: a JSON object whose `pack_version` is the newest pack.
/// Anything else it says is ignored; nothing in it is trusted beyond being a
/// reason to look.
pub fn parse_index(bytes: &[u8]) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value.get("pack_version")?.as_u64()
}

/// One fetch: the index, and if it offers something newer, the signed
/// manifest, and if that is acceptable, the archive, installed into the store.
/// Answers with what it came to and, when that is settled, the validators to
/// keep.
pub fn fetch(
    client: &FeedClient,
    store: &PackStore,
    in_use: u64,
    engine: &str,
    validators: &Validators,
) -> (Fetched, Option<Validators>) {
    let (pack_version, fresh) = match client.index(validators) {
        Ok(Index::NotModified) => return (Fetched::Unchanged, None),
        Ok(Index::Fresh {
            pack_version,
            validators,
        }) => (pack_version, validators),
        Err(Problem::Unreachable(why)) => return (Fetched::Unreachable(why), None),
        Err(Problem::Refused(why)) => return (Fetched::Refused(why), None),
    };
    let fetched = offered(client, store, pack_version, in_use, engine);
    let keep = fetched.settles().then_some(fresh);
    (fetched, keep)
}

/// What the release of one offered version comes to.
fn offered(
    client: &FeedClient,
    store: &PackStore,
    pack_version: u64,
    in_use: u64,
    engine: &str,
) -> Fetched {
    // The index is unsigned, so this only decides whether to look. A forged
    // index that names an older version costs nothing; one that names a newer
    // version is caught by the signed manifest below.
    if pack_version <= in_use {
        return Fetched::NothingNewer {
            offered: pack_version,
            in_use,
        };
    }
    let asked = |name: &str, limit: u64| -> Result<Option<Vec<u8>>, Fetched> {
        client
            .asset(pack_version, name, limit)
            .map_err(|problem| match problem {
                Problem::Unreachable(why) => Fetched::Unreachable(why),
                Problem::Refused(why) => Fetched::Refused(why),
            })
    };

    let manifest = match asked(MANIFEST_FILE, LARGEST_MANIFEST) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Fetched::Incomplete(format!("rules-v{pack_version} has no manifest")),
        Err(fetched) => return fetched,
    };
    let mut signatures = BTreeMap::new();
    for key in PINNED_KEYS {
        match asked(&key.signature_file(), LARGEST_SIGNATURE) {
            Ok(Some(bytes)) => {
                if let Ok(text) = String::from_utf8(bytes) {
                    signatures.insert(key.key_id(), text);
                }
            }
            Ok(None) => {}
            Err(fetched) => return fetched,
        }
    }
    let signed = match SignedManifest::verify(manifest, signatures) {
        Ok(signed) => signed,
        Err(error) => return Fetched::Refused(error.to_string()),
    };
    match judge(&signed.manifest, in_use, engine) {
        Verdict::Accept => {}
        Verdict::NotNewer { offered, in_use } => {
            return Fetched::NothingNewer { offered, in_use };
        }
        Verdict::NeedsNewerEngine { offered, minimum } => {
            return Fetched::NeedsNewerEngine(IgnoredPack {
                pack_version: offered,
                minimum_engine_version: minimum,
            });
        }
    }
    let archive = match asked(ARCHIVE_FILE, LARGEST_PACK) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Fetched::Incomplete(format!("rules-v{pack_version} has no archive")),
        Err(fetched) => return fetched,
    };
    match store.install(&signed, &archive) {
        Ok(pack) => Fetched::Accepted(Box::new(pack)),
        Err(error) => Fetched::Refused(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_project_feed_is_on_github_and_a_test_feed_keeps_its_layout() {
        let github = Endpoints::github();
        assert_eq!(github.host(), "raw.githubusercontent.com");
        assert_eq!(
            github.asset(7, "manifest.json"),
            "https://github.com/byte5digital/agentsweep/releases/download/rules-v7/manifest.json"
        );
        let local = Endpoints::under("http://127.0.0.1:4711");
        assert_eq!(local.host(), "127.0.0.1:4711");
        assert!(local.index.ends_with("/feed/rules/latest.json"));
        assert_eq!(
            local.asset(3, "pack.tar"),
            "http://127.0.0.1:4711/byte5digital/agentsweep/releases/download/rules-v3/pack.tar"
        );
    }

    /// The index says one number; anything else in it is noise.
    #[test]
    fn the_index_is_read_for_its_pack_version_alone() {
        assert_eq!(parse_index(br#"{"pack_version": 4}"#), Some(4));
        assert_eq!(
            parse_index(br#"{"pack_version": 4, "note": "anything"}"#),
            Some(4)
        );
        assert_eq!(parse_index(br#"{"pack_version": "4"}"#), None);
        assert_eq!(parse_index(b"not json"), None);
    }

    #[test]
    fn the_user_agent_names_the_product_and_its_version_only() {
        assert_eq!(
            user_agent(),
            format!("agentsweep/{}", agentsweep_core::VERSION)
        );
    }

    #[test]
    fn jitter_stays_under_its_bound() {
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
        for _ in 0..100 {
            assert!(jitter(Duration::from_secs(3600)) < Duration::from_secs(3600));
        }
        assert_eq!(FeedTuning::default().jitter, Duration::from_secs(3600));
        assert!(FeedTuning::default().endpoints.is_none());
    }

    #[test]
    fn a_log_line_names_the_host_and_nothing_after_it() {
        assert_eq!(
            host_of("https://user@example.invalid:8443/a/b?c#d"),
            "example.invalid:8443"
        );
        assert_eq!(host_of("example.invalid/x"), "example.invalid");
    }
}
