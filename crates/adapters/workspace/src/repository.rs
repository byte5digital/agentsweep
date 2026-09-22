//! Repository Provenance, read in process.
//!
//! Whether git tracks a file, and which commit the checkout stands on, is read
//! straight from `.git/index`, `HEAD` and the refs with the gitoxide crates.
//! No git binary is executed and no repository configuration is interpreted
//! while doing it: `git ls-files` inside a cloned repository is itself the
//! GitSpawn attack, and the configuration is the very thing this adapter is
//! scanning. An index that cannot be read yields Provenance Unknown and a
//! Problem, never a guess.

use std::path::Path;

use agentsweep_core::provenance::RepositoryProvenance;

use crate::git::Layout;

/// Why a project root has no Repository Provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Failure {
    /// The root is not a repository, or its gitdir pointer left the standard
    /// layout and was deliberately not followed.
    NotAReadableRepository,
    /// The index, `HEAD` or a ref could not be read.
    Unreadable(String),
}

/// What git tracks in one project root and which commit it stands on.
pub fn read(layout: &Layout) -> Result<RepositoryProvenance, Failure> {
    if !layout.readable() {
        return Err(Failure::NotAReadableRepository);
    }
    let tracked = tracked_paths(&layout.git_dir)?;
    let commit = head_commit(layout)?;
    Ok(RepositoryProvenance::new(commit, tracked))
}

/// Every path the index tracks, relative to the repository root.
fn tracked_paths(git_dir: &Path) -> Result<Vec<String>, Failure> {
    let path = git_dir.join("index");
    if !path.exists() {
        // A repository whose index was never written tracks nothing. That is
        // an answer, not a failure.
        return Ok(Vec::new());
    }
    let index = open_index(&path)?;
    Ok(index
        .entries()
        .iter()
        .map(|entry| String::from_utf8_lossy(entry.path(&index)).to_string())
        .collect())
}

/// The header and the trailing checksum of the shortest index there can be.
const SHORTEST_INDEX: u64 = 12 + 20;

/// Opens the index of a repository that hashes its objects with SHA-1, which
/// every repository git writes by default does. The checksum is verified, so an
/// index that was tampered with, and the index of an experimental SHA-256
/// repository, are both unreadable rather than half read: the Provenance is
/// then Unknown and a Problem says so.
///
/// The index is a binary file inside a repository someone else wrote, so it is
/// read defensively. A file too short to hold a header and a checksum never
/// reaches the decoder, and a decoder that panics on what it is given yields
/// the same Problem as one that returns an error. A scanner that falls over on
/// a planted file would be a way to switch it off.
fn open_index(path: &Path) -> Result<gix_index::File, Failure> {
    // The decoder memory-maps the index itself, which is why the file is
    // reached here by path rather than through the Host's reader.
    let length = std::fs::metadata(path)
        .map_err(|error| Failure::Unreadable(error.to_string()))?
        .len();
    if length < SHORTEST_INDEX {
        return Err(Failure::Unreadable(
            "the index is too short to hold a header and its checksum".to_string(),
        ));
    }
    let decoded = std::panic::catch_unwind(|| {
        gix_index::File::at(
            path,
            gix_hash::Kind::Sha1,
            false,
            gix_index::decode::Options::default(),
        )
    })
    .map_err(|_| Failure::Unreadable("the index could not be decoded".to_string()))?;
    decoded.map_err(|error| Failure::Unreadable(error.to_string()))
}

/// The commit `HEAD` stands on, empty on a branch that has no commit yet.
fn head_commit(layout: &Layout) -> Result<String, Failure> {
    let store = if layout.common_dir == layout.git_dir {
        gix_ref::file::Store::at(layout.git_dir.clone(), gix_hash::Kind::Sha1)
    } else {
        gix_ref::file::Store::for_linked_worktree(
            layout.git_dir.clone(),
            layout.common_dir.clone(),
            gix_hash::Kind::Sha1,
        )
    };

    let mut name = "HEAD".to_string();
    // A symbolic ref that points at a symbolic ref is legal; a chain that goes
    // on forever is not, and is not followed.
    for _ in 0..8 {
        let found = store
            .try_find(name.as_str())
            .map_err(|error| Failure::Unreadable(error.to_string()))?;
        let Some(reference) = found else {
            // `HEAD` names a branch that has no commit yet.
            return Ok(String::new());
        };
        match reference.target {
            gix_ref::Target::Object(id) => return Ok(id.to_string()),
            gix_ref::Target::Symbolic(target) => {
                name = String::from_utf8_lossy(target.as_bstr()).to_string();
            }
        }
    }
    Err(Failure::Unreadable(
        "HEAD points at itself through too many symbolic refs".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TemporaryRepository;

    #[test]
    fn a_committed_file_is_tracked_and_the_head_commit_is_read() {
        let repository = TemporaryRepository::new("provenance-tracked");
        let layout = repository.layout();
        let provenance = read(&layout).expect("the repository is readable");

        assert_eq!(provenance.commit(), TemporaryRepository::HEAD_COMMIT);
        assert!(provenance.tracks(".env"));
        assert!(provenance.tracks("README.md"));
        assert!(!provenance.tracks(".env.local"));
    }

    #[test]
    fn an_unreadable_index_is_a_failure_and_never_a_guess() {
        let repository = TemporaryRepository::new("provenance-broken");
        repository.break_index();
        let failure = read(&repository.layout()).expect_err("the index does not decode");
        assert!(matches!(failure, Failure::Unreadable(_)), "{failure:?}");
    }

    /// A planted index is attacker-controlled input, and the answer to it is a
    /// Problem rather than a crash.
    #[test]
    fn an_index_long_enough_to_decode_but_wrong_is_a_failure_too() {
        let repository = TemporaryRepository::new("provenance-garbage");
        repository.write_git(
            "index",
            &[b'D', b'I', b'R', b'C', 0xff, 0x11][..].repeat(16),
        );
        let failure = read(&repository.layout()).expect_err("the index does not decode");
        assert!(matches!(failure, Failure::Unreadable(_)), "{failure:?}");
    }

    #[test]
    fn a_repository_whose_index_was_never_written_tracks_nothing() {
        let repository = TemporaryRepository::new("provenance-no-index");
        std::fs::remove_file(repository.root().join(".git").join("index"))
            .expect("the index goes away");
        let provenance = read(&repository.layout()).expect("the repository is readable");
        assert_eq!(provenance.tracked_paths(), 0);
        assert_eq!(provenance.commit(), TemporaryRepository::HEAD_COMMIT);
    }

    #[test]
    fn a_root_that_is_not_a_repository_has_no_provenance() {
        let repository = TemporaryRepository::new("provenance-none");
        repository.remove_git_directory();
        let layout = crate::git::layout(repository.root(), false, None);
        assert!(layout.is_none());
    }
}
