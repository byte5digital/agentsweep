//! A repository in a temporary directory, built without git.
//!
//! Tests never run against the real home and never shell out, so the files a
//! repository is made of are written here: the index in its documented binary
//! form, `HEAD`, one ref and whatever configuration or hook the test needs.
//! That keeps the promise the adapter itself makes, in the tests as well: no
//! git binary is ever executed.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::git::{self, Layout};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A project root with a repository in it, removed again when it goes out of
/// scope.
#[derive(Debug)]
pub struct TemporaryRepository {
    root: PathBuf,
}

impl TemporaryRepository {
    /// The commit `HEAD` stands on in every repository this builder makes.
    pub const HEAD_COMMIT: &'static str = "0badc0ffee0badc0ffee0badc0ffee0badc0ffee";

    /// A repository with a committed `README.md` and a committed `.env`, plus
    /// an untracked `.env.local`, which is the shape the re-pointing Rules are
    /// about.
    pub fn new(name: &str) -> TemporaryRepository {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-workspace-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".git").join("refs").join("heads"))
            .expect("a temporary repository");
        let repository = TemporaryRepository { root };
        repository.write(".env", b"DATABASE_URL=postgres://localhost/demo\n");
        repository.write(".env.local", b"DATABASE_URL=postgres://localhost/local\n");
        repository.write("README.md", b"# demo\n");
        repository.write_git("HEAD", b"ref: refs/heads/main\n");
        repository.write_git(
            "refs/heads/main",
            format!("{}\n", TemporaryRepository::HEAD_COMMIT).as_bytes(),
        );
        repository.write_config("[core]\n\trepositoryformatversion = 0\n\tbare = false\n");
        repository.track(&[".env", "README.md"]);
        repository
    }

    /// The project root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The layout the adapter would read for this root.
    pub fn layout(&self) -> Layout {
        let dot_git = self.root.join(".git");
        let pointer = fs::read(&dot_git).ok();
        git::layout(&self.root, dot_git.is_dir(), pointer).expect("a repository")
    }

    /// Writes a file in the project.
    pub fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("a directory in the project");
        }
        fs::write(path, bytes).expect("a file in the project");
    }

    /// Writes a file inside the git directory.
    pub fn write_git(&self, relative: &str, bytes: &[u8]) {
        self.write(&format!(".git/{relative}"), bytes);
    }

    /// Replaces the repository's configuration.
    pub fn write_config(&self, text: &str) {
        self.write_git("config", text.as_bytes());
    }

    /// Writes a hook, with or without the execute bit git needs to run it.
    pub fn write_hook(&self, name: &str, bytes: &[u8], executable: bool) {
        self.write_git(&format!("hooks/{name}"), bytes);
        let path = self.root.join(".git").join("hooks").join(name);
        set_mode(&path, if executable { 0o755 } else { 0o644 });
    }

    /// Rewrites the index so that exactly these paths are tracked.
    pub fn track(&self, paths: &[&str]) {
        fs::write(self.root.join(".git").join("index"), index_bytes(paths))
            .expect("an index in the repository");
    }

    /// Leaves an index behind that no reader can decode.
    pub fn break_index(&self) {
        fs::write(self.root.join(".git").join("index"), b"DIRC not an index")
            .expect("a broken index");
    }

    /// Turns the root into a directory that is not a repository.
    pub fn remove_git_directory(&self) {
        let _ = fs::remove_dir_all(self.root.join(".git"));
        let _ = fs::remove_file(self.root.join(".git"));
    }

    /// Replaces the git directory with a pointer at another one, which is what
    /// a linked worktree looks like.
    pub fn point_git_at(&self, target: &Path) {
        self.remove_git_directory();
        fs::write(
            self.root.join(".git"),
            format!("gitdir: {}\n", target.display()).as_bytes(),
        )
        .expect("a gitdir pointer");
    }
}

impl Drop for TemporaryRepository {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("a mode on a hook");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// The bytes of a version 2 index tracking these paths, with the trailing
/// checksum a reader verifies.
pub fn index_bytes(paths: &[&str]) -> Vec<u8> {
    let mut sorted: Vec<&str> = paths.to_vec();
    sorted.sort_unstable();

    let mut out = Vec::new();
    out.extend_from_slice(b"DIRC");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for path in sorted {
        // ctime, its nanoseconds, mtime, its nanoseconds, device, inode.
        for _ in 0..6 {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        // A regular file, mode 644.
        out.extend_from_slice(&0o100644u32.to_be_bytes());
        // Owner, group, size.
        for _ in 0..3 {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        out.extend_from_slice(&blob_id(path));
        out.extend_from_slice(&(path.len().min(0xfff) as u16).to_be_bytes());
        out.extend_from_slice(path.as_bytes());
        let padding = 8 - ((62 + path.len()) % 8);
        out.extend(std::iter::repeat_n(0u8, padding));
    }

    let mut hasher = gix_hash::hasher(gix_hash::Kind::Sha1);
    hasher.update(&out);
    let checksum = hasher.try_finalize().expect("the index checksum");
    out.extend_from_slice(checksum.as_slice());
    out
}

/// A stand-in object id for a path. Nothing ever looks the object up, so what
/// matters is only that the same path always gets the same twenty bytes.
fn blob_id(path: &str) -> [u8; 20] {
    let mut hasher = gix_hash::hasher(gix_hash::Kind::Sha1);
    hasher.update(path.as_bytes());
    let id = hasher.try_finalize().expect("a stand-in object id");
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&id.as_slice()[..20]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_this_builder_writes_is_the_one_a_reader_expects() {
        let repository = TemporaryRepository::new("index-round-trip");
        let provenance =
            crate::repository::read(&repository.layout()).expect("the repository is readable");
        assert!(provenance.tracks(".env"));
        assert!(provenance.tracks("README.md"));
        assert_eq!(provenance.tracked_paths(), 2);
    }

    #[test]
    fn the_temporary_repository_goes_away_with_its_value() {
        let root = {
            let repository = TemporaryRepository::new("dropped");
            repository.root().to_path_buf()
        };
        assert!(!root.exists());
    }
}
