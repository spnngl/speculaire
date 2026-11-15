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
    /// The change time, seconds and nanoseconds: no syscall sets it back, so it sees a write whose modification time
    /// was restored (D96).
    ctime: (i64, i64),
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
    pub fn new(mut roots: Vec<PathBuf>) -> Self {
        roots.sort_unstable();
        roots.dedup();
        let stamps = stamps(&roots);
        Self { roots, stamps }
    }

    /// The same paths stamped now, when a watched path differs from its stamp, or appeared or went; take it before
    /// reading them again.
    #[must_use]
    pub fn changed(&self) -> Option<Self> {
        let stamps = stamps(&self.roots);
        (stamps != self.stamps).then(|| Self {
            roots: self.roots.clone(),
            stamps,
        })
    }

    /// The same paths, stamped now; take it before reading them again.
    #[must_use]
    pub fn again(&self) -> Self {
        Self::new(self.roots.clone())
    }

    /// `self`, taken before a read, once the read named `roots`, each with a stamp in `self`: the stamps from before the
    /// read of `roots` and of what is below them, with no new `stat`. A root that `self` stamped below another keeps
    /// the levels stamped there; the next poll finds any deeper entry new, and reads again.
    pub(crate) fn follow(self, mut roots: Vec<PathBuf>) -> Self {
        roots.sort_unstable();
        roots.dedup();
        let mut stamps = self.stamps;
        stamps.retain(|path, _| {
            roots.iter().any(|root| {
                path.strip_prefix(root)
                    .is_ok_and(|below| below.components().count() <= DEPTH)
            })
        });
        Self { roots, stamps }
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

fn stamps(roots: &[PathBuf]) -> BTreeMap<PathBuf, Option<Stamp>> {
    let mut stamps = BTreeMap::new();
    for root in roots {
        stamp(root, DEPTH, &mut stamps);
    }
    stamps
}

fn stamp(path: &Path, depth: usize, stamps: &mut BTreeMap<PathBuf, Option<Stamp>>) {
    let meta = std::fs::metadata(path).ok();
    stamps.insert(
        path.to_owned(),
        meta.as_ref().map(|meta| Stamp {
            modified: meta.modified().ok(),
            ctime: (meta.ctime(), meta.ctime_nsec()),
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
        assert!(watch.changed().is_none());
        // Written in place, as a coarse file clock dates it, or as `cp -p` keeps it.
        std::fs::write(&file, "ab").expect("a write");
        set_modified(&file, old);
        assert!(watch.changed().is_some());
        // Replaced by another file of the same length and time, as `rsync -t` does.
        let watch = Watch::new(vec![file.clone()]);
        let other = dir.path().join("other");
        std::fs::write(&other, "cd").expect("a file");
        set_modified(&other, old);
        std::fs::rename(&other, &file).expect("a rename");
        assert!(watch.changed().is_some());
    }

    #[test]
    fn a_write_in_place_with_its_modification_time_restored_is_a_change() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("file");
        std::fs::write(&file, "a").expect("a file");
        let old = std::fs::metadata(&file)
            .and_then(|meta| meta.modified())
            .expect("a modification time");
        let watch = Watch::new(vec![file.clone()]);
        next_tick(dir.path(), &file);
        // Same length, same inode, and the old time put back, as `touch -r` or an editor that keeps it does.
        std::fs::write(&file, "b").expect("a write");
        set_modified(&file, old);
        assert!(watch.changed().is_some());
    }

    /// Waits until the file clock has ticked past `file`'s change time: a coarse one dates writes within one tick alike
    /// (D93), and a kernel with fine-grained timestamps returns at once.
    fn next_tick(dir: &Path, file: &Path) {
        let ctime = |path: &Path| {
            let meta = std::fs::metadata(path).expect("a file");
            (meta.ctime(), meta.ctime_nsec())
        };
        let stamped = ctime(file);
        let probe = dir.join("probe");
        loop {
            std::fs::write(&probe, "x").expect("a probe");
            if ctime(&probe) > stamped {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn a_path_that_appears_or_goes_is_a_change() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("file");
        let watch = Watch::new(vec![file.clone()]);
        std::fs::write(&file, "a").expect("a file");
        assert!(watch.changed().is_some());
        let watch = Watch::new(vec![file.clone()]);
        std::fs::remove_file(&file).expect("removed");
        assert!(watch.changed().is_some());
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
        assert!(watch.changed().is_some());
        // A write five levels below is not looked for.
        let fifth = third.join("4/file");
        std::fs::write(&fifth, "a").expect("a file");
        let watch = Watch::new(vec![dir.path().to_owned()]);
        std::fs::write(&fifth, "ab").expect("a write");
        assert!(watch.changed().is_none());
    }

    #[test]
    fn a_path_watched_before_a_read_keeps_its_stamp_from_before() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (kept, dropped) = (dir.path().join("kept"), dir.path().join("dropped"));
        std::fs::write(&kept, "a").expect("a file");
        let before = Watch::new(vec![kept.clone(), dropped]);
        // The read: `kept` changes during it, and is all it names, twice.
        std::fs::write(&kept, "ab").expect("a write");
        let after = before.follow(vec![kept.clone(), kept.clone()]);
        assert!(after.changed().is_some());
        assert_eq!(after.roots(), [kept]);
    }

    #[test]
    fn a_read_that_names_the_paths_watched_keeps_every_stamp() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let third = dir.path().join("1/2/3");
        std::fs::create_dir_all(&third).expect("directories");
        std::fs::write(third.join("file"), "a").expect("a file");
        let before = Watch::new(vec![dir.path().to_owned()]);
        assert_eq!(before.clone().follow(vec![dir.path().to_owned()]), before);
    }
}
