//! A registry config read once and handed to every request without a lock, read again when a file of it changes (D91).

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;

use super::Error;
use crate::watch::Watch;

struct Loaded<T> {
    /// What the value was read from, stamped before the read (D93).
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

    /// Whether a watched path changed since the last read began.
    pub(crate) fn changed(&self) -> bool {
        self.state.load().watch.changed()
    }

    /// Reads again by `read`, which returns the paths its result depends on, and the result. A read that fails keeps
    /// the value held, if there is one, and watches the paths it returns with those already watched: a fix to either is
    /// a change, the same failure is not.
    ///
    /// # Errors
    ///
    /// When the read fails.
    pub(crate) fn reload(
        &self,
        read: impl FnOnce() -> (Vec<PathBuf>, Result<T, Error>),
    ) -> Result<(), Error> {
        let current = self.state.load();
        let before = current.watch.again();
        let (mut paths, value) = read();
        match value {
            Ok(value) => {
                self.state.store(Arc::new(Loaded {
                    watch: before.follow(paths),
                    value: Ok(Arc::new(value)),
                }));
                Ok(())
            }
            Err(error) => {
                paths.extend_from_slice(before.roots());
                paths.sort_unstable();
                paths.dedup();
                self.state.store(Arc::new(Loaded {
                    watch: before.follow(paths),
                    value: match &current.value {
                        Ok(held) => Ok(Arc::clone(held)),
                        Err(_) => Err(error.to_string()),
                    },
                }));
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
        assert!(live.reload(|| broken(Vec::new())).is_err());
        assert!(matches!(live.get(), Err(Error::Config(why)) if why == "registry config: bad"));
        live.reload(|| ok(1)).expect("a read");
        assert_eq!(*live.get().expect("a value"), 1);
    }

    #[test]
    fn a_read_that_fails_keeps_the_value_held() {
        let live = Live::new();
        live.reload(|| ok(1)).expect("a read");
        assert!(live.reload(|| broken(Vec::new())).is_err());
        assert_eq!(*live.get().expect("a value"), 1);
        live.reload(|| ok(2)).expect("a read");
        assert_eq!(*live.get().expect("a value"), 2);
    }

    #[test]
    fn a_change_is_a_watched_path_that_differs_from_before_the_read() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("file");
        std::fs::write(&file, "a").expect("a file");
        let live = Live::new();
        live.reload(|| (vec![dir.path().to_owned()], Ok(0)))
            .expect("a read");
        assert!(!live.changed());
        // A write during the read: the read saw the old file, so the next look finds a change.
        live.reload(|| {
            std::fs::write(&file, "ab").expect("a write");
            (vec![dir.path().to_owned()], Ok(1))
        })
        .expect("a read");
        assert!(live.changed());
        live.reload(|| (vec![dir.path().to_owned()], Ok(2)))
            .expect("a read");
        assert!(!live.changed());
    }

    #[test]
    fn the_paths_of_a_failed_read_are_watched_with_those_of_the_value_held() {
        let held = tempfile::tempdir().expect("a temporary directory");
        let new = tempfile::tempdir().expect("a temporary directory");
        for changed in [&held, &new] {
            let live = Live::new();
            live.reload(|| (vec![held.path().to_owned()], Ok(1)))
                .expect("a read");
            assert!(live.reload(|| broken(vec![new.path().to_owned()])).is_err());
            // The failure is not a change: the next poll says nothing more.
            assert!(!live.changed());
            let file = changed.path().join("file");
            std::fs::write(&file, "a").expect("a file");
            assert!(live.changed());
            std::fs::remove_file(&file).expect("removed");
        }
    }
}
