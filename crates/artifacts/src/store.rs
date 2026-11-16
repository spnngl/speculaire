//! The artifact store: content-addressed files in the blob cache's layout, `<dir>/blobs/<alg>/<hex>` written through
//! `<dir>/tmp/`, and per root the artifacts discovery found for it in `<dir>/roots/<alg>/<hex>.json`.
//!
//! A blob is hashed while it is written and kept only when its digest matches (D7). One blob may belong to many
//! roots, such as the empty config every Sigstore bundle names, so it is kept once.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use speculaire_oci::hash::Hash;
use speculaire_oci::reference::Digest;
use tokio::io::AsyncWriteExt as _;

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

/// The artifact store below one directory.
#[derive(Debug)]
pub struct Store {
    directory: PathBuf,
    parts: AtomicU64,
    bytes: AtomicU64,
}

impl Store {
    /// Opens the store below `directory`, creating it, and deletes what an earlier run left half written.
    ///
    /// # Errors
    ///
    /// When a directory cannot be created or read.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self, Error> {
        let directory = directory.into();
        let tmp = directory.join("tmp");
        match std::fs::remove_dir_all(&tmp) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(io_error(&tmp, e)),
            _ => {}
        }
        for name in ["tmp", "blobs", "roots"] {
            let path = directory.join(name);
            std::fs::create_dir_all(&path).map_err(|e| io_error(&path, e))?;
        }
        let bytes = size_below(&directory.join("blobs"))?;
        metrics::store_bytes(bytes);
        Ok(Self {
            directory,
            parts: AtomicU64::new(0),
            bytes: AtomicU64::new(bytes),
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
            .map_err(|e| io_error(&path, e))
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
        let invalid = |message: String| Error::Record {
            path: path.clone(),
            message,
        };
        let record: Record = serde_json::from_slice(&text).map_err(|e| invalid(e.to_string()))?;
        record
            .artifacts
            .into_iter()
            .map(|raw| raw.parse().map_err(|e| invalid(e.to_string())))
            .collect::<Result<_, _>>()
            .map(Some)
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
