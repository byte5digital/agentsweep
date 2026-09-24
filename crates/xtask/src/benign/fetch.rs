//! Fetching the benign corpus over plain HTTPS, and the cache that makes a
//! second run offline-capable.
//!
//! Nothing here runs a git binary and nothing here authenticates: every URL is
//! a public archive or a public file at a pinned commit. A download lands in
//! `target/agentsweep-benign-corpus/cache` under a name that carries the
//! commit, so a re-pin never reads the previous content and a machine that has
//! run once can run again with the network unplugged.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// How large one download may be. The largest archive in the corpus is tens of
/// megabytes; a source that grew past this wants a smaller `take`, not a
/// bigger cap.
const MAX_BYTES: u64 = 192 * 1024 * 1024;

/// What went wrong while fetching.
#[derive(Debug)]
pub enum Problem {
    /// The network did not answer. This is the one case the corpus is allowed
    /// to skip over, because a developer on a train is not a failing Rule.
    Offline(String),
    /// Something else: a status code, a digest that does not match, a cache
    /// that could not be written.
    Refused(String),
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::Offline(what) => write!(f, "{what}"),
            Problem::Refused(what) => write!(f, "{what}"),
        }
    }
}

impl Error for Problem {}

/// The download cache.
#[derive(Clone, Debug)]
pub struct Cache {
    directory: PathBuf,
}

impl Cache {
    /// The cache under one directory, created on first use.
    pub fn at(directory: PathBuf) -> Cache {
        Cache { directory }
    }

    /// Where the cache keeps its downloads.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The bytes behind one URL: the cached copy when there is one, otherwise
    /// one HTTPS request whose answer is cached.
    pub fn bytes(&self, url: &str, name: &str) -> Result<Vec<u8>, Problem> {
        let path = self.directory.join(name);
        if let Ok(cached) = fs::read(&path) {
            return Ok(cached);
        }
        let fetched = download(url)?;
        fs::create_dir_all(&self.directory).map_err(|error| {
            Problem::Refused(format!(
                "the cache {} could not be created: {error}",
                self.directory.display()
            ))
        })?;
        // Written under a temporary name and renamed, so an interrupted run
        // never leaves half a download behind for the next one to trust.
        let partial = path.with_extension("partial");
        fs::write(&partial, &fetched)
            .and_then(|()| fs::rename(&partial, &path))
            .map_err(|error| {
                Problem::Refused(format!("the download could not be cached: {error}"))
            })?;
        Ok(fetched)
    }
}

/// One HTTPS request. A network failure is [`Problem::Offline`]; everything
/// the server did answer is [`Problem::Refused`].
fn download(url: &str) -> Result<Vec<u8>, Problem> {
    let mut response = ureq::get(url).call().map_err(|error| match error {
        ureq::Error::Io(_)
        | ureq::Error::HostNotFound
        | ureq::Error::ConnectionFailed
        | ureq::Error::Timeout(_) => {
            Problem::Offline(format!("{url} could not be reached: {error}"))
        }
        other => Problem::Refused(format!("{url} answered {other}")),
    })?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_BYTES)
        .read_to_vec()
        .map_err(|error| match error {
            ureq::Error::Io(_) | ureq::Error::Timeout(_) => {
                Problem::Offline(format!("{url} stopped answering: {error}"))
            }
            other => Problem::Refused(format!("{url} could not be read: {other}")),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cached download is read back without a request, which is what makes a
    /// second run offline-capable.
    #[test]
    fn a_cached_download_is_read_without_reaching_the_network() {
        let directory = std::env::temp_dir().join(format!(
            "agentsweep-benign-cache-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("a cache directory");
        fs::write(directory.join("demo"), b"cached").expect("a cached download");

        let cache = Cache::at(directory.clone());
        let bytes = cache
            .bytes("https://nothing.example.invalid/demo", "demo")
            .expect("the cache answers");
        assert_eq!(bytes, b"cached");

        fs::remove_dir_all(&directory).expect("the cache goes away");
    }

    /// A host that does not resolve is the offline case, not a failing corpus.
    #[test]
    fn a_host_that_does_not_resolve_reads_as_offline() {
        let directory = std::env::temp_dir().join(format!(
            "agentsweep-benign-cache-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&directory);
        let cache = Cache::at(directory.clone());
        let problem = cache
            .bytes("https://corpus.example.invalid/nothing", "nothing")
            .expect_err("nothing answers");
        assert!(matches!(problem, Problem::Offline(_)), "{problem:?}");
        let _ = fs::remove_dir_all(&directory);
    }
}
