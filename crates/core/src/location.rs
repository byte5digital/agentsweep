//! Location classes: where a path lies, as far as the operating system's
//! consent is concerned (spec section 9.7).
//!
//! macOS guards a handful of locations with a consent of their own:
//! Documents, Desktop, Downloads, iCloud Drive and other File Provider
//! storage, removable volumes and network volumes. The class is decided from
//! the path alone, so nothing inside it is touched to decide it. The daemon
//! uses it to hold back the first read into a class it has not read before;
//! the app uses it on onboarding screen 5, to say that macOS will ask once.

use std::path::{Component, Path, PathBuf};

/// Where a path lies, as far as the operating system's consent is concerned.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LocationClass {
    /// Nowhere the operating system asks about: the home's own directories
    /// such as `~/Developer`, and the rest of the disk.
    Unprotected,
    /// The home's Documents folder.
    Documents,
    /// The home's Desktop folder.
    Desktop,
    /// The home's Downloads folder.
    Downloads,
    /// iCloud Drive (`~/Library/Mobile Documents`) and every other File
    /// Provider's storage (`~/Library/CloudStorage/<provider>`).
    FileProvider,
    /// A volume mounted under `/Volumes`.
    RemovableVolumes,
    /// A share mounted under `/Network` or `/net`.
    NetworkVolumes,
}

impl LocationClass {
    /// Every protected class, in the order the state file lists them.
    pub const PROTECTED: [LocationClass; 6] = [
        LocationClass::Documents,
        LocationClass::Desktop,
        LocationClass::Downloads,
        LocationClass::FileProvider,
        LocationClass::RemovableVolumes,
        LocationClass::NetworkVolumes,
    ];

    /// The spelling the state file carries.
    pub fn as_str(self) -> &'static str {
        match self {
            LocationClass::Unprotected => "unprotected",
            LocationClass::Documents => "documents",
            LocationClass::Desktop => "desktop",
            LocationClass::Downloads => "downloads",
            LocationClass::FileProvider => "file_provider",
            LocationClass::RemovableVolumes => "removable_volumes",
            LocationClass::NetworkVolumes => "network_volumes",
        }
    }

    /// Reads back a protected class's spelling. The unprotected class is
    /// never remembered, so it never reads back.
    pub fn parse(text: &str) -> Option<LocationClass> {
        LocationClass::PROTECTED
            .into_iter()
            .find(|class| class.as_str() == text)
    }

    /// True for every class the operating system asks the user about.
    pub fn is_protected(self) -> bool {
        self != LocationClass::Unprotected
    }
}

/// The location class of one path, decided from the path alone.
///
/// Names are compared without regard to ASCII case, as the default macOS
/// volume compares them, so `~/documents/app` is Documents too: reading too
/// much into a name only ever withholds a root, never reads one. The prefix
/// `/System/Volumes/Data`, under which the data volume is also reachable, is
/// taken off first. A home that lives on a volume of its own keeps its
/// Documents, Desktop and Downloads classes.
pub fn classify(home: &Path, path: &Path) -> LocationClass {
    let path = on_the_data_volume(&lexical(path));
    let home = on_the_data_volume(&lexical(home));
    if let Some(rest) = below(&path, &home) {
        let first = rest.first().map(String::as_str).unwrap_or_default();
        let second = rest.get(1).map(String::as_str).unwrap_or_default();
        if first.eq_ignore_ascii_case("Documents") {
            return LocationClass::Documents;
        }
        if first.eq_ignore_ascii_case("Desktop") {
            return LocationClass::Desktop;
        }
        if first.eq_ignore_ascii_case("Downloads") {
            return LocationClass::Downloads;
        }
        if first.eq_ignore_ascii_case("Library")
            && (second.eq_ignore_ascii_case("Mobile Documents")
                || second.eq_ignore_ascii_case("CloudStorage"))
        {
            return LocationClass::FileProvider;
        }
    }
    let names = names(&path);
    match names.first().map(String::as_str) {
        Some(first) if first.eq_ignore_ascii_case("Volumes") && names.len() > 1 => {
            LocationClass::RemovableVolumes
        }
        Some(first)
            if (first.eq_ignore_ascii_case("Network") || first.eq_ignore_ascii_case("net"))
                && names.len() > 1 =>
        {
            LocationClass::NetworkVolumes
        }
        _ => LocationClass::Unprotected,
    }
}

/// The path with `.` dropped and `..` taken back, without asking the disk.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The names of an absolute path's components, root left out.
fn names(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// The path without the data volume's own prefix.
fn on_the_data_volume(path: &Path) -> PathBuf {
    let names = names(path);
    let data = ["System", "Volumes", "Data"];
    if path.is_absolute()
        && names.len() >= data.len()
        && names
            .iter()
            .zip(data)
            .all(|(name, wanted)| name.eq_ignore_ascii_case(wanted))
    {
        let mut out = PathBuf::from("/");
        out.extend(&names[data.len()..]);
        return out;
    }
    path.to_path_buf()
}

/// The names of `path` below `base`, compared without regard to ASCII case;
/// nothing when `path` is not below `base`.
fn below(path: &Path, base: &Path) -> Option<Vec<String>> {
    let path = names(path);
    let base = names(base);
    if base.is_empty() || path.len() < base.len() {
        return None;
    }
    path.iter()
        .zip(&base)
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
        .then(|| path[base.len()..].to_vec())
}
