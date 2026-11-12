//! The *blob cache* of a CRI-O node (D67, D88): every manifest and blob the mirror served, by digest, on disk.
//!
//! `<directory>/blobs/<algorithm>/<hex>` holds what is kept; `<directory>/tmp/` holds what is being written. A file
//! enters `blobs/` by rename once its digest matches, so no file there is partial or wrong. The cache is bounded:
//! above `max_size` it evicts the least recently served blobs first, and the blobs of the images CRI-O lists last.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use speculaire_oci::reference::Digest;
use tokio::io::AsyncWriteExt as _;
use tracing::{debug, warn};

use crate::content::{Blob, Content, Error};
use crate::metrics;

struct Entry {
    size: u64,
    /// The tick of the last time the blob was served, or was kept.
    last: u64,
}

#[derive(Default)]
struct State {
    entries: HashMap<Digest, Entry>,
    total: u64,
    clock: u64,
}

impl State {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }
}

/// The cache.
pub struct Cache {
    directory: PathBuf,
    max_size: AtomicU64,
    state: Mutex<State>,
    parts: AtomicU64,
}

/// A blob being written: a file in `tmp/` that [`Writer::commit`] moves into the cache, and that is deleted otherwise.
pub struct Writer {
    file: tokio::fs::File,
    path: PathBuf,
    written: u64,
    committed: bool,
}

impl Cache {
    /// Opens the cache in `directory`: deletes what an earlier run left in `tmp/`, and counts what is kept.
    ///
    /// # Errors
    ///
    /// When the directories cannot be made or read.
    pub fn open(directory: impl Into<PathBuf>, max_size: u64) -> io::Result<Self> {
        let directory = directory.into();
        let blobs = directory.join("blobs");
        std::fs::create_dir_all(&blobs)?;
        let tmp = directory.join("tmp");
        match std::fs::remove_dir_all(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        std::fs::create_dir_all(&tmp)?;
        let mut found: Vec<(std::time::SystemTime, Digest, u64)> = Vec::new();
        for algorithm in std::fs::read_dir(&blobs)? {
            let algorithm = algorithm?;
            if !algorithm.file_type()?.is_dir() {
                continue;
            }
            let name = algorithm.file_name().to_string_lossy().into_owned();
            for blob in std::fs::read_dir(algorithm.path())? {
                let blob = blob?;
                let meta = blob.metadata()?;
                let hex = blob.file_name().to_string_lossy().into_owned();
                // Whatever else is in the directory is not ours to count or to delete.
                let Ok(digest) = Digest::parse(&format!("{name}:{hex}")) else {
                    continue;
                };
                if meta.is_file() {
                    found.push((
                        meta.modified().unwrap_or(std::time::UNIX_EPOCH),
                        digest,
                        meta.len(),
                    ));
                }
            }
        }
        // The files' times stand for when each was last served: touching on a hit keeps them so.
        found.sort_by_key(|(time, ..)| *time);
        let mut state = State::default();
        for (_, digest, size) in found {
            let last = state.tick();
            state.total += size;
            state.entries.insert(digest, Entry { size, last });
        }
        let cache = Self {
            directory,
            max_size: AtomicU64::new(max_size),
            state: Mutex::new(state),
            parts: AtomicU64::new(0),
        };
        cache.report();
        Ok(cache)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn path(&self, digest: &Digest) -> PathBuf {
        self.directory
            .join("blobs")
            .join(digest.algorithm())
            .join(digest.encoded())
    }

    fn report(&self) {
        metrics::cache_bytes(self.state().total);
    }

    /// Bytes kept.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.state().total
    }

    /// The bound above which the cache evicts.
    #[must_use]
    pub fn max_size(&self) -> u64 {
        self.max_size.load(Ordering::Relaxed)
    }

    /// Changes the bound (`blob_cache.max_size` reloads live, D30). Call [`Cache::evict`] to apply it.
    pub fn set_max_size(&self, max_size: u64) {
        self.max_size.store(max_size, Ordering::Relaxed);
    }

    /// Whether the cache is above its bound.
    #[must_use]
    pub fn over(&self) -> bool {
        self.size() > self.max_size()
    }

    /// Whether the cache holds `digest`.
    #[must_use]
    pub fn contains(&self, digest: &Digest) -> bool {
        self.state().entries.contains_key(digest)
    }

    /// Every digest the cache holds.
    #[must_use]
    pub fn digests(&self) -> Vec<Digest> {
        self.state().entries.keys().cloned().collect()
    }

    /// A file to write a blob to.
    ///
    /// # Errors
    ///
    /// When the file cannot be created.
    pub async fn writer(&self) -> io::Result<Writer> {
        let n = self.parts.fetch_add(1, Ordering::Relaxed);
        let path = self
            .directory
            .join("tmp")
            .join(format!("{}-{n}.part", std::process::id()));
        let file = tokio::fs::File::create(&path).await?;
        Ok(Writer {
            file,
            path,
            written: 0,
            committed: false,
        })
    }

    /// Evicts until the cache is within its bound: the least recently served blobs first, except those in
    /// `protected`, which go only when nothing else is left.
    ///
    /// Returns the digests evicted.
    pub fn evict(&self, protected: &HashSet<Digest>) -> Vec<Digest> {
        let mut evicted = Vec::new();
        let max = self.max_size();
        loop {
            let victim = {
                let state = self.state();
                if state.total <= max {
                    break;
                }
                state
                    .entries
                    .iter()
                    .min_by_key(|(digest, entry)| (protected.contains(*digest), entry.last))
                    .map(|(digest, _)| digest.clone())
            };
            let Some(digest) = victim else {
                break;
            };
            match std::fs::remove_file(self.path(&digest)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    // A file that cannot be deleted stays in the count: stop, rather than loop.
                    warn!(error = %e, digest = %digest, "the blob cache could not delete a blob");
                    break;
                }
            }
            let mut state = self.state();
            if let Some(entry) = state.entries.remove(&digest) {
                state.total -= entry.size;
                metrics::cache_eviction();
                evicted.push(digest);
            }
        }
        self.report();
        if !evicted.is_empty() {
            debug!(count = evicted.len(), "the blob cache evicted blobs");
        }
        evicted
    }
}

impl Writer {
    /// Appends a chunk.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub async fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.file.write_all(chunk).await?;
        self.written += chunk.len() as u64;
        Ok(())
    }

    /// Keeps the file as the blob `digest`, by rename: the caller has checked the digest.
    ///
    /// # Errors
    ///
    /// When the file cannot be flushed or moved; it is deleted then.
    pub async fn commit(mut self, cache: &Cache, digest: &Digest) -> io::Result<()> {
        self.file.flush().await?;
        let target = cache.path(digest);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&self.path, &target).await?;
        self.committed = true;
        let mut state = cache.state();
        let last = state.tick();
        // A blob kept twice, by two pulls at once, is the same file: count it once.
        if let Some(old) = state.entries.insert(
            digest.clone(),
            Entry {
                size: self.written,
                last,
            },
        ) {
            state.total -= old.size;
        }
        state.total += self.written;
        drop(state);
        cache.report();
        Ok(())
    }

    /// How many bytes were written.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.written
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if !self.committed {
            // A file that is gone already is the goal; one that cannot be deleted is cleared at the next start.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Content for Cache {
    async fn open(&self, digest: &Digest) -> Result<Option<Blob>, Error> {
        let size = {
            let mut state = self.state();
            let last = state.tick();
            let Some(entry) = state.entries.get_mut(digest) else {
                return Ok(None);
            };
            entry.last = last;
            entry.size
        };
        let path = self.path(digest);
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.is_file() && meta.len() == size => {
                touch(&path);
                Ok(Some(Blob::from_file(path, size)))
            }
            // Deleted or changed behind our back: it is not in the cache.
            Ok(_) => {
                self.forget(digest);
                Ok(None)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.forget(digest);
                Ok(None)
            }
            Err(e) => Err(Error::Io(e)),
        }
    }
}

impl Cache {
    fn forget(&self, digest: &Digest) {
        let mut state = self.state();
        if let Some(entry) = state.entries.remove(digest) {
            state.total -= entry.size;
        }
        drop(state);
        self.report();
    }
}

/// Sets the modification time of `path` to now, so that a restart orders the blobs by when they were last served.
fn touch(path: &Path) {
    // A failure only costs the order after a restart.
    let _ = std::fs::File::options()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(std::time::SystemTime::now()));
}

#[cfg(test)]
mod tests;
