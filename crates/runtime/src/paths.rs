//! Where the files of a node are: the real root, or a directory standing in for it.

use std::path::{Path, PathBuf};

/// The root the node's files are read and written below, so that tests run on a temporary directory.
#[derive(Clone, Debug, Default)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    /// The node itself.
    #[must_use]
    pub fn system() -> Self {
        Self::default()
    }

    /// A directory standing for `/`.
    #[must_use]
    pub fn under(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory standing for `/`; empty for the node itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The absolute `path` of the node, below the stand-in root.
    #[must_use]
    pub fn at(&self, path: &str) -> PathBuf {
        if self.root.as_os_str().is_empty() {
            PathBuf::from(path)
        } else {
            self.root.join(path.trim_start_matches('/'))
        }
    }
}
