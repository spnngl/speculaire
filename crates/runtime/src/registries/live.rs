//! A registry config read once and handed to every request without a lock, read again when a file of it changes (D91).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use arc_swap::ArcSwap;

use super::Error;

/// How far below a watched directory a change is looked for: `hosts.toml` is two below its root, a drop-in one.
const DEPTH: usize = 4;

/// What a [`Live`] value was read from, and when it last changed.
#[derive(Debug, Default)]
pub(crate) struct Watch(Vec<PathBuf>);

impl Watch {
    pub(crate) fn new(paths: Vec<PathBuf>) -> Self {
        Self(paths)
    }

    /// Whether a watched file, or a directory with its entries, was modified at or after `since`. What cannot be
    /// looked at has not changed.
    fn changed_since(&self, since: SystemTime) -> bool {
        self.0
            .iter()
            .any(|path| newest(path, DEPTH).is_some_and(|modified| modified >= since))
    }
}

/// The latest modification of `path` and, when it is a directory, of what is below it.
fn newest(path: &Path, depth: usize) -> Option<SystemTime> {
    let meta = std::fs::metadata(path).ok()?;
    let own = meta.modified().ok();
    if !meta.is_dir() || depth == 0 {
        return own;
    }
    let below = std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| newest(&entry.path(), depth - 1));
    below.chain(own).max()
}

struct Loaded<T> {
    watch: Watch,
    /// The text of why the last read failed, when no read has worked since.
    value: Result<Arc<T>, String>,
}

/// A value read from files: every reader gets the last one that was valid, and a reader never waits.
pub(crate) struct Live<T> {
    state: ArcSwap<Loaded<T>>,
}

impl<T> Live<T> {
    /// Nothing read yet: [`Live::get`] fails until [`Live::reload`] works.
    pub(crate) fn new() -> Self {
        Self {
            state: ArcSwap::from_pointee(Loaded {
                watch: Watch::default(),
                value: Err("not read yet".to_owned()),
            }),
        }
    }

    /// The value as last read.
    ///
    /// # Errors
    ///
    /// When no read has worked yet.
    pub(crate) fn get(&self) -> Result<Arc<T>, Error> {
        match &self.state.load().value {
            Ok(value) => Ok(Arc::clone(value)),
            Err(why) => Err(Error::Config(why.clone())),
        }
    }

    /// Reads again by `read`, which returns the paths its result depends on, and the result. With `since`, only when a
    /// watched path was modified at or after it. A read that fails keeps the value held, if there is one, and adds the
    /// paths it returns to those watched.
    ///
    /// Returns whether the value was replaced.
    ///
    /// # Errors
    ///
    /// When the read fails.
    pub(crate) fn reload(
        &self,
        since: Option<SystemTime>,
        read: impl FnOnce() -> (Vec<PathBuf>, Result<T, Error>),
    ) -> Result<bool, Error> {
        let current = self.state.load();
        if since.is_some_and(|since| !current.watch.changed_since(since)) {
            return Ok(false);
        }
        let (paths, value) = read();
        match value {
            Ok(value) => {
                self.state.store(Arc::new(Loaded {
                    watch: Watch::new(paths),
                    value: Ok(Arc::new(value)),
                }));
                Ok(true)
            }
            Err(error) => {
                // The held value's files and those the failed read named: a fix to either is read by the next poll.
                let mut watched = current.watch.0.clone();
                watched.extend(paths);
                watched.sort_unstable();
                watched.dedup();
                self.state.store(Arc::new(Loaded {
                    watch: Watch::new(watched),
                    value: current
                        .value
                        .as_ref()
                        .map(Arc::clone)
                        .map_err(|_| error.to_string()),
                }));
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn ok(value: u32) -> (Vec<PathBuf>, Result<u32, Error>) {
        (Vec::new(), Ok(value))
    }

    fn broken(paths: Vec<PathBuf>) -> (Vec<PathBuf>, Result<u32, Error>) {
        (paths, Err(Error::Config("bad".to_owned())))
    }

    #[test]
    fn nothing_is_read_until_a_read_works() {
        let live = Live::<u32>::new();
        assert!(matches!(live.get(), Err(Error::Config(_))));
        assert!(live.reload(None, || broken(Vec::new())).is_err());
        assert!(matches!(live.get(), Err(Error::Config(why)) if why == "registry config: bad"));
        assert!(live.reload(None, || ok(1)).expect("a read"));
        assert_eq!(*live.get().expect("a value"), 1);
    }

    #[test]
    fn a_read_that_fails_keeps_the_value_held() {
        let live = Live::new();
        live.reload(None, || ok(1)).expect("a read");
        assert!(live.reload(None, || broken(Vec::new())).is_err());
        assert_eq!(*live.get().expect("a value"), 1);
        live.reload(None, || ok(2)).expect("a read");
        assert_eq!(*live.get().expect("a value"), 2);
    }

    #[test]
    fn a_read_since_a_time_happens_only_when_a_watched_path_changed() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("sub/file");
        std::fs::create_dir(dir.path().join("sub")).expect("a directory");
        std::fs::write(&file, "a").expect("a file");
        let live = Live::new();
        live.reload(None, || (vec![dir.path().to_owned()], Ok(1)))
            .expect("a read");
        let past = SystemTime::now() - Duration::from_secs(3600);
        let future = SystemTime::now() + Duration::from_secs(3600);
        assert!(!live.reload(Some(future), || ok(2)).expect("no read"));
        assert_eq!(*live.get().expect("a value"), 1);
        // The files are newer than `past`: even one deep below the watched directory counts.
        assert!(
            live.reload(Some(past), || (vec![file.clone()], Ok(3)))
                .expect("a read")
        );
        assert_eq!(*live.get().expect("a value"), 3);
        // A path that is gone has not changed.
        std::fs::remove_file(&file).expect("removed");
        assert!(!live.reload(Some(future), || ok(4)).expect("no read"));
    }

    #[test]
    fn a_change_is_seen_down_to_the_depth_that_is_asked_and_no_further() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("sub/file");
        std::fs::create_dir(dir.path().join("sub")).expect("a directory");
        std::fs::write(&file, "a").expect("a file");
        let future = SystemTime::now() + Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&file)
            .expect("the file")
            .set_modified(future)
            .expect("a modification time");
        let own = |path: &Path| std::fs::metadata(path).and_then(|m| m.modified()).ok();
        // The directory itself at depth 0, what is in it at 1, what is in that at 2.
        assert_eq!(newest(dir.path(), 0), own(dir.path()));
        assert_eq!(
            newest(dir.path(), 1),
            own(&dir.path().join("sub")).max(own(dir.path()))
        );
        assert_eq!(newest(dir.path(), 2), Some(future));
        assert_eq!(newest(&file, 0), Some(future));
        assert_eq!(newest(&dir.path().join("none"), 3), None);
    }

    #[test]
    fn the_paths_of_a_failed_first_read_are_still_watched() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let live = Live::<u32>::new();
        let past = SystemTime::now() - Duration::from_secs(3600);
        assert!(
            live.reload(None, || broken(vec![dir.path().to_owned()]))
                .is_err()
        );
        assert!(live.reload(Some(past), || ok(5)).expect("a read"));
        assert_eq!(*live.get().expect("a value"), 5);
    }

    #[test]
    fn a_failed_read_while_a_value_is_held_adds_its_paths_to_those_watched() {
        let held = tempfile::tempdir().expect("a temporary directory");
        let new = tempfile::tempdir().expect("a temporary directory");
        let future = SystemTime::now() + Duration::from_secs(3600);
        // A change to what the held value was read from, or to what the failed read named, is read by the next poll.
        for changed in [&held, &new] {
            let live = Live::new();
            live.reload(None, || (vec![held.path().to_owned()], Ok(1)))
                .expect("a read");
            assert!(
                live.reload(None, || broken(vec![new.path().to_owned()]))
                    .is_err()
            );
            assert_eq!(*live.get().expect("a value"), 1);
            assert!(!live.reload(Some(future), || ok(2)).expect("no read"));
            let file = changed.path().join("file");
            std::fs::write(&file, "a").expect("a file");
            std::fs::File::options()
                .write(true)
                .open(&file)
                .expect("the file")
                .set_modified(future)
                .expect("a modification time");
            assert!(live.reload(Some(future), || ok(2)).expect("a read"));
            std::fs::remove_file(&file).expect("removed");
        }
    }
}
