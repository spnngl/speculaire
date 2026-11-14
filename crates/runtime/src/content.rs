//! Where the mirror finds what it serves: the runtime's own content (D5, D90).
//!
//! On containerd that is the content directory, `blobs/<algorithm>/<hex>` under its root, read directly and read-only
//! (Spegel's proven path); containerd's `Content` gRPC service answers for a blob that file is missing for, as when
//! containerd's root is not the default one. CRI-O keeps its layers in a store the mirror cannot serve from; it
//! serves what its own blob cache holds (D67), which the mirror makes into [`Blob`]s.

use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;

use bytes::Bytes;
use containerd_client::services::v1::ReadContentRequest;
use containerd_client::services::v1::content_client::ContentClient;
use containerd_client::tonic::transport::Channel;
use containerd_client::tonic::{Request, Status};
use futures_util::{Stream, StreamExt as _, TryStreamExt as _};
use speculaire_oci::reference::Digest;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio_util::io::ReaderStream;

use crate::containerd::with_namespace;

/// The size of a read from a file.
const CHUNK: usize = 256 * 1024;

/// A chunk of a blob.
pub type Chunks = Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send>>;

/// A blob could not be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file could not be read.
    #[error("reading content: {0}")]
    Io(#[from] io::Error),
    /// containerd's content service failed.
    #[error("containerd's content service: {0}")]
    Grpc(#[from] Status),
    /// The relay could not find where to fetch from.
    #[error("the relay: {0}")]
    Relay(String),
    /// The blob is longer than the reader accepts.
    #[error("content of {size} bytes is over the limit of {limit}")]
    TooLarge {
        /// Its size.
        size: u64,
        /// The limit.
        limit: u64,
    },
}

/// A blob the mirror holds, not yet read.
#[derive(Debug)]
pub struct Blob {
    size: u64,
    source: Source,
}

enum Source {
    File(PathBuf),
    /// A file already open, such as one with no name that goes when it is closed.
    Open(std::fs::File),
    Grpc {
        channel: Channel,
        digest: String,
    },
    Memory(Bytes),
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => write!(f, "File({})", path.display()),
            Self::Open(_) => write!(f, "Open"),
            Self::Grpc { digest, .. } => write!(f, "Grpc({digest})"),
            Self::Memory(bytes) => write!(f, "Memory({} bytes)", bytes.len()),
        }
    }
}

impl Blob {
    /// A blob that is a file of `size` bytes.
    #[must_use]
    pub fn from_file(path: PathBuf, size: u64) -> Self {
        Self {
            size,
            source: Source::File(path),
        }
    }

    /// A blob that is the first `size` bytes of an open file.
    #[must_use]
    pub fn from_open(file: std::fs::File, size: u64) -> Self {
        Self {
            size,
            source: Source::Open(file),
        }
    }

    /// A blob held in memory.
    #[must_use]
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self {
            size: bytes.len() as u64,
            source: Source::Memory(bytes),
        }
    }

    /// A blob that containerd's content service holds.
    pub(crate) fn from_grpc(channel: Channel, digest: String, size: u64) -> Self {
        Self {
            size,
            source: Source::Grpc { channel, digest },
        }
    }

    /// Its size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// `length` bytes from offset `first`, as a stream.
    ///
    /// # Errors
    ///
    /// When the file cannot be opened or sought in, or containerd refuses the read.
    pub async fn stream(self, first: u64, length: u64) -> Result<Chunks, Error> {
        match self.source {
            Source::Memory(bytes) => {
                let start = usize::try_from(first).unwrap_or(usize::MAX);
                let end = usize::try_from(first.saturating_add(length)).unwrap_or(usize::MAX);
                let part = bytes.slice(start.min(bytes.len())..end.min(bytes.len()));
                Ok(Box::pin(futures_util::stream::once(
                    async move { Ok(part) },
                )))
            }
            Source::File(path) => {
                let mut file = tokio::fs::File::open(path).await?;
                file.seek(io::SeekFrom::Start(first)).await?;
                Ok(Box::pin(
                    ReaderStream::with_capacity(file.take(length), CHUNK).map_err(Error::Io),
                ))
            }
            Source::Open(file) => {
                let mut file = tokio::fs::File::from_std(file);
                file.seek(io::SeekFrom::Start(first)).await?;
                Ok(Box::pin(
                    ReaderStream::with_capacity(file.take(length), CHUNK).map_err(Error::Io),
                ))
            }
            Source::Grpc { channel, digest } => {
                let mut client = ContentClient::new(channel);
                let mut request = Request::new(ReadContentRequest {
                    digest,
                    offset: i64::try_from(first).unwrap_or(i64::MAX),
                    size: i64::try_from(length).unwrap_or(i64::MAX),
                });
                with_namespace(&mut request);
                let stream = client.read(request).await?.into_inner();
                Ok(Box::pin(stream.map(|message| {
                    message.map(|m| Bytes::from(m.data)).map_err(Error::Grpc)
                })))
            }
        }
    }

    /// The whole blob, when it is at most `limit` bytes.
    ///
    /// # Errors
    ///
    /// When the blob is longer, or cannot be read.
    pub async fn read_all(self, limit: u64) -> Result<Bytes, Error> {
        if self.size > limit {
            return Err(Error::TooLarge {
                size: self.size,
                limit,
            });
        }
        if self.size == 0 {
            return Ok(Bytes::new());
        }
        let size = self.size;
        let mut chunks = self.stream(0, size).await?;
        let mut all = Vec::new();
        while let Some(chunk) = chunks.next().await {
            all.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(all))
    }
}

/// A place the mirror reads blobs from.
pub trait Content: Send + Sync + 'static {
    /// The blob with `digest`, or `None` when this node does not hold it.
    ///
    /// # Errors
    ///
    /// When looking fails other than by the blob's absence.
    fn open(&self, digest: &Digest) -> impl Future<Output = Result<Option<Blob>, Error>> + Send;
}
