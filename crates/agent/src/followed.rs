//! Files the verifier reads again as the agent's config is (D30, D93): the policy file and a pinned trust root. A
//! change swaps in the new content whole, and the verdict engine verifies again (D21).

use std::path::{Path, PathBuf};

use speculaire_runtime::watch::Watch;
use tokio::sync::watch;
use tracing::error;

use crate::telemetry;

/// A file read into a `T` its readers hold, with the stamp taken before its last read.
#[derive(Debug)]
pub(crate) struct Followed<T> {
    what: &'static str,
    /// The path read last.
    path: PathBuf,
    watch: Watch,
    holder: watch::Sender<T>,
    load: fn(&Path) -> anyhow::Result<T>,
}

impl<T> Followed<T> {
    /// Reads `path` with `load`, stamped just before.
    ///
    /// # Errors
    ///
    /// When `load` refuses the file: the agent does not start (D30).
    pub(crate) fn read(
        what: &'static str,
        path: &Path,
        load: fn(&Path) -> anyhow::Result<T>,
    ) -> anyhow::Result<Self> {
        let watch = Watch::new(vec![path.to_owned()]);
        let value = load(path)?;
        Ok(Self {
            what,
            path: path.to_owned(),
            watch,
            holder: watch::Sender::new(value),
            load,
        })
    }

    /// What the file holds, as each read swaps it in.
    pub(crate) fn subscribe(&self) -> watch::Receiver<T> {
        self.holder.subscribe()
    }

    /// Reads `path` again, as SIGHUP does.
    pub(crate) fn reload(&mut self, path: &Path) {
        self.again(Watch::new(vec![path.to_owned()]), path);
    }

    /// Reads `path` again when it is not the path read last, or its stamp differs from the one taken before (D93).
    pub(crate) fn poll(&mut self, path: &Path) {
        if path != self.path {
            self.reload(path);
        } else if let Some(now) = self.watch.changed() {
            self.again(now, path);
        }
    }

    /// Reads `path`, stamped `now` just before. A refused file is logged and counted once, and what was read before
    /// stays (D30).
    fn again(&mut self, now: Watch, path: &Path) {
        self.watch = now;
        path.clone_into(&mut self.path);
        match (self.load)(path) {
            Ok(value) => {
                self.holder.send_replace(value);
            }
            Err(err) => {
                metrics::counter!(telemetry::CONFIG_RELOAD_FAILURES).increment(1);
                error!(
                    error = format_args!("{err:#}"),
                    "{} reload failed; the previous one stays in use", self.what
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn number(path: &Path) -> anyhow::Result<u32> {
        Ok(fs::read_to_string(path)?.trim().parse()?)
    }

    #[test]
    fn a_change_swaps_the_content_in_and_a_refused_file_keeps_the_previous() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (path, other) = (dir.path().join("a"), dir.path().join("b"));
        fs::write(&path, "1").expect("written");
        fs::write(&other, "3").expect("written");
        let mut file = Followed::read("the number", &path, number).expect("it parses");
        let held = file.subscribe();
        file.poll(&path);
        assert!(!held.has_changed().expect("held"), "unchanged");

        fs::write(&path, "2").expect("written");
        file.poll(&path);
        assert_eq!(*held.borrow(), 2);

        fs::write(&path, "two").expect("written");
        file.poll(&path);
        file.poll(&path);
        assert_eq!(*held.borrow(), 2, "the previous stays");
        file.reload(&path);
        assert_eq!(*held.borrow(), 2, "the previous stays");

        file.poll(&other);
        assert_eq!(*held.borrow(), 3, "another path is read");
    }
}
