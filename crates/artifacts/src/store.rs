//! The artifact store: content-addressed files in the blob cache's layout, `<dir>/blobs/<alg>/<hex>` written through
//! `<dir>/tmp/`, and per root the artifacts discovery found for it in `<dir>/roots/<alg>/<hex>.json`.
//!
//! A blob is hashed while it is written and kept only when its digest matches (D7). One blob may belong to many
//! roots, such as the empty config every Sigstore bundle names, so it is kept once.
//!
//! The node serves the store to peers: its blobs as [`Content`], announced as an [`Inventory`], and the artifacts about
//! each manifest as [`Referrers`] (D124). `Store::collect` deletes what no listed root names, and the inventory opens
//! only after the first collection, so a root removed while the agent was stopped is never announced (D131).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use speculaire_mirror::referrers::Referrers;
use speculaire_oci::hash::Hash;
use speculaire_oci::reference::Digest;
use speculaire_runtime::content::{self, Blob, Content};
use speculaire_runtime::inventory::{Change, Inventory, Update};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, info, warn};

use crate::metrics;

/// What a root's artifact is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A Sigstore bundle referrer: a signature or an attestation (D43).
    Bundle,
    /// The manifest of the legacy cosign `.sig` tag.
    Signature,
    /// A `BuildKit` attestation manifest of an index (D49).
    Attestation,
}

/// One artifact of a root: a manifest about `target`, and every blob it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    /// The root itself, or a manifest the root's index names.
    pub target: Digest,
    /// The artifact's manifest.
    pub manifest: Digest,
    /// What it is.
    pub kind: Kind,
    /// The blobs the manifest names, its config first.
    pub blobs: Vec<Digest>,
}

/// An artifact store that cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file or directory of the store cannot be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
    /// The content written is not what its digest says.
    #[error("the content of {0} does not match its digest")]
    Mismatch(Box<Digest>),
    /// A root's record is no record.
    #[error("the record {}: {message}", path.display())]
    Record {
        /// The record.
        path: PathBuf,
        /// Why it cannot be read.
        message: String,
    },
}

/// How many blobs a follower of the store may fall behind before it lists them again.
const BACKLOG: usize = 1024;

/// The artifact store below one directory.
#[derive(Debug)]
pub struct Store {
    directory: PathBuf,
    parts: AtomicU64,
    bytes: AtomicU64,
    /// The record of each root, as on disk: what [`Referrers`] reads.
    roots: Mutex<HashMap<Digest, Vec<Artifact>>>,
    /// The blobs kept and deleted, as they are.
    changes: broadcast::Sender<Change>,
    /// Whether a collection ran, which the inventory waits for.
    collected: watch::Sender<bool>,
}

impl Store {
    /// Opens the store below `directory`, creating it, deletes what an earlier run left half written, and reads the
    /// records; one that is no record is logged and left out, and discovery writes it again.
    ///
    /// # Errors
    ///
    /// When a directory cannot be created or read.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self, Error> {
        let directory = directory.into();
        let tmp = directory.join("tmp");
        // Best effort: a part left behind only takes room, and creating `tmp` below reports a directory it cannot use.
        let _ = std::fs::remove_dir_all(&tmp);
        for name in ["tmp", "blobs", "roots"] {
            let path = directory.join(name);
            std::fs::create_dir_all(&path).map_err(|e| io_error(&path, e))?;
        }
        let bytes = size_below(&directory.join("blobs"))?;
        metrics::store_bytes(bytes);
        let roots = read_records(&directory.join("roots"))?;
        Ok(Self {
            directory,
            parts: AtomicU64::new(0),
            bytes: AtomicU64::new(bytes),
            roots: Mutex::new(roots),
            changes: broadcast::channel(BACKLOG).0,
            collected: watch::channel(false).0,
        })
    }

    /// The bytes of every blob held.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Whether the blob `digest` is held.
    pub fn contains(&self, digest: &Digest) -> bool {
        self.path(digest).is_file()
    }

    /// The content of the blob `digest`, if held.
    ///
    /// # Errors
    ///
    /// When the blob is held but cannot be read.
    pub async fn read(&self, digest: &Digest) -> Result<Option<Vec<u8>>, Error> {
        let path = self.path(digest);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(&path, e)),
        }
    }

    /// A writer of the blob `digest`, which checks the digest while it writes.
    ///
    /// # Errors
    ///
    /// When the file cannot be created.
    ///
    /// # Panics
    ///
    /// Never: every algorithm a digest parses is one the store hashes.
    pub async fn writer(&self, digest: &Digest) -> Result<Writer, Error> {
        let hash =
            Hash::new(digest).expect("every algorithm a digest parses is one the store hashes");
        let n = self.parts.fetch_add(1, Ordering::Relaxed);
        let path = self
            .directory
            .join("tmp")
            .join(format!("{}-{n}.part", std::process::id()));
        let file = tokio::fs::File::create(&path)
            .await
            .map_err(|e| io_error(&path, e))?;
        Ok(Writer {
            file,
            path,
            digest: digest.clone(),
            hash,
            written: 0,
        })
    }

    /// Keeps `bytes` as the blob `digest`, as a writer would.
    ///
    /// # Errors
    ///
    /// As [`Self::writer`] and [`Writer::commit`].
    pub async fn keep(&self, digest: &Digest, bytes: &[u8]) -> Result<(), Error> {
        let mut writer = self.writer(digest).await?;
        writer.write(bytes).await?;
        writer.commit(self).await
    }

    /// Records `artifacts` as all that discovery found for `root`, in place of an earlier record.
    ///
    /// # Errors
    ///
    /// When the record cannot be written.
    ///
    /// # Panics
    ///
    /// Never: a record of strings is always JSON.
    pub async fn record(&self, root: &Digest, artifacts: &[Artifact]) -> Result<(), Error> {
        let record = Record {
            artifacts: artifacts.iter().map(RawArtifact::from).collect(),
        };
        let text = serde_json::to_vec(&record).expect("a record of strings is always JSON");
        let path = self.record_path(root);
        let n = self.parts.fetch_add(1, Ordering::Relaxed);
        let part = self
            .directory
            .join("tmp")
            .join(format!("{}-{n}.json", std::process::id()));
        tokio::fs::write(&part, text)
            .await
            .map_err(|e| io_error(&part, e))?;
        create_parent(&path).await?;
        tokio::fs::rename(&part, &path)
            .await
            .map_err(|e| io_error(&path, e))?;
        self.roots().insert(root.clone(), artifacts.to_vec());
        Ok(())
    }

    /// What discovery last recorded for `root`, if it did.
    ///
    /// # Errors
    ///
    /// When the record cannot be read or is not one.
    pub async fn recorded(&self, root: &Digest) -> Result<Option<Vec<Artifact>>, Error> {
        let path = self.record_path(root);
        let text = match tokio::fs::read(&path).await {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(&path, e)),
        };
        parse_record(&path, &text).map(Some)
    }

    /// Deletes what no root of `listed` names, and withdraws each blob deleted.
    ///
    /// The record of each root not in `listed` goes first, then each blob that is neither a listed root nor named by a
    /// listed root's record. The first collection, done or failed, opens the [`Inventory`].
    ///
    /// Discovery keeps a root's blobs before its record, so it must not run meanwhile: [`crate::follow()`] does both in
    /// turn.
    ///
    /// # Errors
    ///
    /// When a record or a blob cannot be listed or deleted; the next collection tries again.
    pub(crate) async fn collect(self: &Arc<Self>, listed: HashSet<Digest>) -> Result<(), Error> {
        let store = Arc::clone(self);
        let collected = tokio::task::spawn_blocking(move || store.collect_blocking(&listed))
            .await
            .unwrap_or_else(|err| Err(io_error(&self.directory, io::Error::other(err))));
        // Here rather than in the blocking task, whose thread may record to another recorder.
        metrics::store_bytes(self.bytes());
        self.collected.send_replace(true);
        collected
    }

    fn collect_blocking(&self, listed: &HashSet<Digest>) -> Result<(), Error> {
        // Records go first: a crash in between leaves blobs that no record names, which the next collection deletes,
        // and never a record naming a blob gone.
        for (root, path) in named(&self.directory.join("roots"), ".json")? {
            let Some(root) = root.filter(|root| !listed.contains(root)) else {
                continue;
            };
            std::fs::remove_file(&path).map_err(|e| io_error(&path, e))?;
            self.roots().remove(&root);
            info!(%root, "the artifacts of a root no longer listed are deleted");
        }
        // A listed root is a blob too: discovery keeps its index (D126).
        let mut named_by_listed = listed.clone();
        for artifact in self.roots().values().flatten() {
            named_by_listed.insert(artifact.manifest.clone());
            named_by_listed.extend(artifact.blobs.iter().cloned());
        }
        for (digest, path) in named(&self.directory.join("blobs"), "")? {
            let Some(digest) = digest.filter(|digest| !named_by_listed.contains(digest)) else {
                continue;
            };
            let meta = std::fs::metadata(&path).map_err(|e| io_error(&path, e))?;
            // The store writes only files there: anything else came by hand, and stays.
            if !meta.is_file() {
                continue;
            }
            let size = meta.len();
            std::fs::remove_file(&path).map_err(|e| io_error(&path, e))?;
            // Saturating: a blob replaced by hand may be larger than counted.
            self.bytes
                .update(Ordering::Relaxed, Ordering::Relaxed, |bytes| {
                    bytes.saturating_sub(size)
                });
            debug!(%digest, size, "a blob no listed root names is deleted");
            let _ = self.changes.send(Change::Removed(digest));
        }
        Ok(())
    }

    /// Every blob held.
    fn digests(&self) -> Result<HashSet<Digest>, Error> {
        let named = named(&self.directory.join("blobs"), "")?;
        Ok(named.into_iter().filter_map(|(digest, _)| digest).collect())
    }

    fn roots(&self) -> MutexGuard<'_, HashMap<Digest, Vec<Artifact>>> {
        self.roots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn path(&self, digest: &Digest) -> PathBuf {
        self.directory
            .join("blobs")
            .join(digest.algorithm())
            .join(digest.encoded())
    }

    fn record_path(&self, root: &Digest) -> PathBuf {
        self.directory
            .join("roots")
            .join(root.algorithm())
            .join(format!("{}.json", root.encoded()))
    }
}

/// A blob being written to the store, deleted unless committed.
pub struct Writer {
    file: tokio::fs::File,
    path: PathBuf,
    digest: Digest,
    hash: Hash,
    written: u64,
}

impl Writer {
    /// Appends `chunk`.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub async fn write(&mut self, chunk: &[u8]) -> Result<(), Error> {
        self.hash.update(chunk);
        self.file
            .write_all(chunk)
            .await
            .map_err(|e| io_error(&self.path, e))?;
        self.written += chunk.len() as u64;
        Ok(())
    }

    /// The bytes written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Keeps the file as its blob when the content matches the digest.
    ///
    /// # Errors
    ///
    /// When it does not match, or the file cannot be flushed or moved.
    pub async fn commit(mut self, store: &Store) -> Result<(), Error> {
        if !self.hash.matches() {
            return Err(Error::Mismatch(Box::new(self.digest.clone())));
        }
        self.file
            .flush()
            .await
            .map_err(|e| io_error(&self.path, e))?;
        let target = store.path(&self.digest);
        create_parent(&target).await?;
        // A link fails on a blob held already, which a rename would replace while another root reads it.
        match tokio::fs::hard_link(&self.path, &target).await {
            Ok(()) => {
                let bytes = store.bytes.fetch_add(self.written, Ordering::Relaxed) + self.written;
                metrics::store_bytes(bytes);
                // With no follower, the change is dropped: a follower starts from a listing.
                let _ = store.changes.send(Change::Added(self.digest.clone()));
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(io_error(&target, e)),
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Committed or not, the part goes: a file that cannot be deleted is cleared at the next start.
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Content for Store {
    async fn open(&self, digest: &Digest) -> Result<Option<Blob>, content::Error> {
        let path = self.path(digest);
        let opened = tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(path)?;
            let size = file.metadata()?.len();
            Ok::<_, io::Error>((file, size))
        })
        .await
        .unwrap_or_else(|err| Err(io::Error::other(err)));
        match opened {
            Ok((file, size)) => Ok(Some(Blob::from_open(file, size))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(content::Error::Io(e)),
        }
    }
}

impl Inventory for Store {
    fn follow(
        self: Arc<Self>,
        updates: mpsc::Sender<Update>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        // A send fails only once the receiver is gone, which ends the follow.
        Box::pin(async move {
            let _ = self.send_updates(&updates).await;
        })
    }
}

impl Store {
    /// [`Inventory::follow`], until the receiver closes: `None`.
    async fn send_updates(self: Arc<Self>, updates: &mpsc::Sender<Update>) -> Option<()> {
        let mut collected = self.collected.subscribe();
        tokio::select! {
            () = updates.closed() => return None,
            // The store holds the sender, so the wait ends only once a collection ran.
            _ = collected.wait_for(|collected| *collected) => {}
        }
        // Subscribed before the listing: a blob kept meanwhile comes again after it, which changes nothing.
        let mut changes = self.changes.subscribe();
        loop {
            let store = Arc::clone(&self);
            let listed = tokio::task::spawn_blocking(move || store.digests())
                .await
                .unwrap_or_else(|err| Err(io_error(&self.directory, io::Error::other(err))));
            let listing = listed.unwrap_or_else(|err| {
                // The blobs kept from now on are still announced.
                warn!(error = %err, "the artifact store cannot be listed: its blobs are not announced");
                HashSet::new()
            });
            updates.send(Update::Listing(listing)).await.ok()?;
            loop {
                let change = tokio::select! {
                    () = updates.closed() => return None,
                    change = changes.recv() => change,
                };
                match change {
                    Ok(change) => updates.send(Update::Change(change)).await.ok()?,
                    // Changes were missed: list again. The store holds the sender, so it is never closed.
                    Err(_) => break,
                }
            }
        }
    }
}

impl Referrers for Store {
    fn referrers(&self, target: &Digest) -> Vec<Digest> {
        let mut manifests: Vec<Digest> = Vec::new();
        for artifact in self.roots().values().flatten() {
            if artifact.target == *target && !manifests.contains(&artifact.manifest) {
                manifests.push(artifact.manifest.clone());
            }
        }
        manifests
    }
}

/// The record of each root below `roots`; one that cannot be read is logged and left out.
fn read_records(roots: &Path) -> Result<HashMap<Digest, Vec<Artifact>>, Error> {
    let mut records = HashMap::new();
    for (root, path) in named(roots, ".json")? {
        let Some(root) = root else {
            warn!(path = %path.display(), "a file in the roots of the artifact store names no root");
            continue;
        };
        let read = std::fs::read(&path)
            .map_err(|e| io_error(&path, e))
            .and_then(|text| parse_record(&path, &text));
        match read {
            Ok(artifacts) => {
                records.insert(root, artifacts);
            }
            Err(err) => warn!(error = %err, "a record of the artifact store is left out"),
        }
    }
    Ok(records)
}

/// Each file `<directory>/<algorithm>/<hex><suffix>`, with the digest its name gives, if it gives one.
fn named(directory: &Path, suffix: &str) -> Result<Vec<(Option<Digest>, PathBuf)>, Error> {
    let mut named = Vec::new();
    for algorithm in std::fs::read_dir(directory).map_err(|e| io_error(directory, e))? {
        let algorithm = algorithm.map_err(|e| io_error(directory, e))?;
        let path = algorithm.path();
        if !path.is_dir() {
            continue;
        }
        let algorithm = algorithm.file_name();
        for file in std::fs::read_dir(&path).map_err(|e| io_error(&path, e))? {
            let file = file.map_err(|e| io_error(&path, e))?;
            let name = file.file_name();
            let digest = name.to_string_lossy().strip_suffix(suffix).and_then(|hex| {
                Digest::parse(&format!("{}:{hex}", algorithm.to_string_lossy())).ok()
            });
            named.push((digest, file.path()));
        }
    }
    Ok(named)
}

/// The artifacts of the record `text`, read from `path`.
fn parse_record(path: &Path, text: &[u8]) -> Result<Vec<Artifact>, Error> {
    let invalid = |message: String| Error::Record {
        path: path.to_owned(),
        message,
    };
    let record: Record = serde_json::from_slice(text).map_err(|e| invalid(e.to_string()))?;
    record
        .artifacts
        .into_iter()
        .map(|raw| raw.parse().map_err(|e| invalid(e.to_string())))
        .collect()
}

#[derive(Serialize, Deserialize)]
struct Record {
    artifacts: Vec<RawArtifact>,
}

#[derive(Serialize, Deserialize)]
struct RawArtifact {
    target: String,
    manifest: String,
    kind: Kind,
    blobs: Vec<String>,
}

impl From<&Artifact> for RawArtifact {
    fn from(artifact: &Artifact) -> Self {
        Self {
            target: artifact.target.to_string(),
            manifest: artifact.manifest.to_string(),
            kind: artifact.kind,
            blobs: artifact.blobs.iter().map(ToString::to_string).collect(),
        }
    }
}

impl RawArtifact {
    fn parse(self) -> Result<Artifact, speculaire_oci::reference::ReferenceError> {
        Ok(Artifact {
            target: Digest::parse(&self.target)?,
            manifest: Digest::parse(&self.manifest)?,
            kind: self.kind,
            blobs: self
                .blobs
                .iter()
                .map(|blob| Digest::parse(blob))
                .collect::<Result<_, _>>()?,
        })
    }
}

async fn create_parent(path: &Path) -> Result<(), Error> {
    let parent = path.parent().expect("a path below the store has a parent");
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|e| io_error(parent, e))
}

/// The bytes of the files one level below each directory below `blobs`, `<alg>/<hex>`.
fn size_below(blobs: &Path) -> Result<u64, Error> {
    let mut bytes = 0;
    for algorithm in std::fs::read_dir(blobs).map_err(|e| io_error(blobs, e))? {
        let algorithm = algorithm.map_err(|e| io_error(blobs, e))?.path();
        let Ok(files) = std::fs::read_dir(&algorithm) else {
            continue;
        };
        for file in files {
            let file = file.map_err(|e| io_error(&algorithm, e))?;
            if let Ok(meta) = file.metadata()
                && meta.is_file()
            {
                bytes += meta.len();
            }
        }
    }
    Ok(bytes)
}

fn io_error(path: &Path, source: io::Error) -> Error {
    Error::Io {
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests;
