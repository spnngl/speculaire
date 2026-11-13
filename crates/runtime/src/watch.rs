//! Change detection for files the agent reads again when they change: the agent's config and the registry config
//! (D93).
//!
//! A [`Watch`] holds a stamp of every watched path, taken before the read it belongs to. A path has changed when its
//! stamp now differs, whatever the clocks say: a kernel's file clock is coarser than the agent's, so a modification
//! time is compared with an earlier stamp, never with a time the agent took.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// How far below a watched directory a change is looked for: `hosts.toml` is two below its root, a drop-in one.
const DEPTH: usize = 4;

/// What a path is, as `stat` sees it through symlinks: a file replaced, even with its modification time kept, gets
/// another inode or length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
    dev: u64,
    ino: u64,
}

/// Watched paths and their stamps. A directory's stamp covers what is below it down to four levels, each entry with its
/// own, so an entry that appears or goes is a change; a path that cannot be looked at has no stamp until it can.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Watch {
    roots: Vec<PathBuf>,
    stamps: BTreeMap<PathBuf, Option<Stamp>>,
}

impl Watch {
    /// Stamps `roots` now; take it before reading them, so that a write during the read is a change.
    #[must_use]
    pub fn new(roots: Vec<PathBuf>) -> Self {
        let mut stamps = BTreeMap::new();
        for root in &roots {
            stamp(root, DEPTH, &mut stamps);
        }
        Self { roots, stamps }
    }

    /// Whether a watched path differs from its stamp, or appeared or went.
    #[must_use]
    pub fn changed(&self) -> bool {
        *self != self.again()
    }

    /// The same paths, stamped now; take it before reading them again.
    #[must_use]
    pub fn again(&self) -> Self {
        Self::new(self.roots.clone())
    }

    /// `self`, taken before a read, once the read named `roots`: the paths it watched keep their stamps from before the
    /// read; the others, first named by the read, are stamped now.
    pub(crate) fn follow(self, roots: Vec<PathBuf>) -> Self {
        let mut next = Self::new(roots);
        for (path, stamp) in &mut next.stamps {
            if let Some(before) = self.stamps.get(path) {
                *stamp = *before;
            }
        }
        next
    }

    /// The paths watched.
    pub(crate) fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Whether `path` has a stamp: it is watched, or was below a watched directory.
    pub(crate) fn stamped(&self, path: &Path) -> bool {
        self.stamps.contains_key(path)
    }
}

fn stamp(path: &Path, depth: usize, stamps: &mut BTreeMap<PathBuf, Option<Stamp>>) {
    let meta = std::fs::metadata(path).ok();
    stamps.insert(
        path.to_owned(),
        meta.as_ref().map(|meta| Stamp {
            modified: meta.modified().ok(),
            len: meta.len(),
            dev: meta.dev(),
            ino: meta.ino(),
        }),
    );
    if depth == 0 || !meta.is_some_and(|meta| meta.is_dir()) {
        return;
    }
    for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
        stamp(&entry.path(), depth - 1, stamps);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn set_modified(path: &Path, time: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("the file")
            .set_modified(time)
            .expect("a modification time");
    }

    #[test]
    fn a_write_dated_before_the_stamp_is_a_change() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("file");
        std::fs::write(&file, "a").expect("a file");
        let old = SystemTime::now() - Duration::from_secs(3600);
        set_modified(&file, old);
        let watch = Watch::new(vec![file.clone()]);
        assert!(!watch.changed());
        // Written in place, as a coarse file clock dates it, or as `cp -p` keeps it.
        std::fs::write(&file, "ab").expect("a write");
        set_modified(&file, old);
        assert!(watch.changed());
        // Replaced by another file of the same length and time, as `rsync -t` does.
        let watch = Watch::new(vec![file.clone()]);
        let other = dir.path().join("other");
        std::fs::write(&other, "cd").expect("a file");
        set_modified(&other, old);
        std::fs::rename(&other, &file).expect("a rename");
        assert!(watch.changed());
    }

    #[test]
    fn a_path_that_appears_or_goes_is_a_change() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("file");
        let watch = Watch::new(vec![file.clone()]);
        std::fs::write(&file, "a").expect("a file");
        assert!(watch.changed());
        let watch = Watch::new(vec![file.clone()]);
        std::fs::remove_file(&file).expect("removed");
        assert!(watch.changed());
    }

    #[test]
    fn a_change_is_seen_down_to_four_levels_below_a_directory_and_no_further() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let third = dir.path().join("1/2/3");
        std::fs::create_dir_all(third.join("4")).expect("directories");
        let watch = Watch::new(vec![dir.path().to_owned()]);
        // A file that appears four levels below, even dated in the past, is a change.
        let fourth = third.join("file");
        std::fs::write(&fourth, "a").expect("a file");
        set_modified(&fourth, SystemTime::now() - Duration::from_secs(3600));
        assert!(watch.changed());
        // A write five levels below is not looked for.
        let fifth = third.join("4/file");
        std::fs::write(&fifth, "a").expect("a file");
        let watch = Watch::new(vec![dir.path().to_owned()]);
        std::fs::write(&fifth, "ab").expect("a write");
        assert!(!watch.changed());
    }

    #[test]
    fn a_path_watched_before_a_read_keeps_its_stamp_from_before() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (kept, new) = (dir.path().join("kept"), dir.path().join("new"));
        std::fs::write(&kept, "a").expect("a file");
        let before = Watch::new(vec![kept.clone()]);
        // The read: `kept` changes during it, and names `new`.
        std::fs::write(&kept, "ab").expect("a write");
        std::fs::write(&new, "a").expect("a file");
        let after = before.follow(vec![kept, new]);
        assert!(after.changed());
        assert_eq!(after.roots().len(), 2);
    }
}
