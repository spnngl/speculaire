//! Where the mirror finds what it serves: the runtime's own content (D5, D90).
//!
//! On containerd that is the content directory, `blobs/<algorithm>/<hex>` under its root, read directly and read-only
//! (Spegel's proven path); containerd's `Content` gRPC service answers for a blob that file is missing for, as when
//! containerd's root is not the default one. CRI-O keeps its layers in a store the mirror cannot serve from; it
//! serves what its own blob cache holds (D67), which the mirror makes into [`Blob`]s.

use std::future::Future;
use std::io::{self, Read as _, Seek as _};
use std::pin::Pin;

use bytes::Bytes;
use containerd_client::services::v1::ReadContentRequest;
use containerd_client::services::v1::content_client::ContentClient;
use containerd_client::tonic::transport::Channel;
use containerd_client::tonic::{Request, Status};
use futures_util::{Stream, StreamExt as _};
use speculaire_oci::reference::Digest;

use crate::containerd::with_namespace;

/// The size of a read from a file, at most.
const CHUNK: u64 = 256 * 1024;

/// The size of the next read of a span with `left` bytes to go: what is left, when shorter than [`CHUNK`], so that a
/// small blob such as a manifest holds no more memory than its own length.
fn chunk(left: u64) -> u64 {
    left.min(CHUNK)
}

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
    /// An open file: deleted meanwhile, as by containerd's garbage collector or the cache's eviction, it still reads
    /// until it is closed.
    File(std::fs::File),
    Grpc {
        channel: Channel,
        digest: String,
    },
    Memory(Bytes),
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(file) => f.debug_tuple("File").field(file).finish(),
            Self::Grpc { digest, .. } => write!(f, "Grpc({digest})"),
            Self::Memory(bytes) => write!(f, "Memory({} bytes)", bytes.len()),
        }
    }
}

impl Blob {
    /// A blob that is the first `size` bytes of an open file.
    #[must_use]
    pub fn from_open(file: std::fs::File, size: u64) -> Self {
        Self {
            size,
            source: Source::File(file),
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
    /// When containerd refuses the read.
    ///
    /// # Panics
    ///
    /// Never: reading a file does not panic.
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
            // A blocking read per chunk straight into the buffer the chunk is sent in: tokio's `File` reads into a
            // buffer of its own and copies out of it.
            Source::File(file) => Ok(Box::pin(futures_util::stream::try_unfold(
                (file, first, length),
                |(file, first, left)| async move {
                    if left == 0 {
                        return Ok(None);
                    }
                    let (file, read) = tokio::task::spawn_blocking(move || {
                        let read = read_span(&file, first, chunk(left));
                        (file, read)
                    })
                    .await
                    .expect("reading a file does not panic");
                    let read = read?;
                    // The file ends before the span: the reader sees the length short.
                    if read.is_empty() {
                        return Ok(None);
                    }
                    let size = read.len() as u64;
                    Ok(Some((Bytes::from(read), (file, first + size, left - size))))
                },
            ))),
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
    ///
    /// # Panics
    ///
    /// Never: reading a file does not panic.
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
        let source = match self.source {
            Source::Memory(bytes) => return Ok(bytes),
            // One blocking read into a buffer of the blob's size: no chunks to join, nor tokio's buffer to copy from.
            Source::File(file) => {
                return tokio::task::spawn_blocking(move || read_span(&file, 0, size))
                    .await
                    .expect("reading a file does not panic")
                    .map(Bytes::from)
                    .map_err(Error::Io);
            }
            source @ Source::Grpc { .. } => source,
        };
        let mut chunks = Self { size, source }.stream(0, size).await?;
        let mut all = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
        while let Some(chunk) = chunks.next().await {
            all.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(all))
    }
}

/// `length` bytes of `file` from offset `first`, wherever its offset was, or fewer where the file ends.
fn read_span(mut file: &std::fs::File, first: u64, length: u64) -> io::Result<Vec<u8>> {
    file.seek(io::SeekFrom::Start(first))?;
    let mut read = Vec::with_capacity(usize::try_from(length).unwrap_or_default());
    file.take(length).read_to_end(&mut read)?;
    Ok(read)
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

#[cfg(test)]
mod tests {
    use super::{CHUNK, chunk};

    #[test]
    fn a_span_shorter_than_a_chunk_is_read_at_its_length() {
        assert_eq!(chunk(0), 0);
        assert_eq!(chunk(2048), 2048);
        assert_eq!(chunk(u64::MAX), CHUNK);
    }
}
