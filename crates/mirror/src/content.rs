//! Where the mirror finds what it serves: the runtime's own content (D5).
//!
//! On containerd that is the content directory, `blobs/<algorithm>/<hex>` under its root, read directly and read-only
//! (Spegel's proven path); containerd's `Content` gRPC service answers for a blob that file is missing for, as when
//! containerd's root is not the default one.

use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;

use bytes::Bytes;
use containerd_client::services::v1::content_client::ContentClient;
use containerd_client::services::v1::{InfoRequest, ReadContentRequest};
use containerd_client::tonic::transport::Channel;
use containerd_client::tonic::{Code, Request, Status};
use futures_util::{Stream, StreamExt as _, TryStreamExt as _};
use speculaire_oci::reference::Digest;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio_util::io::ReaderStream;

use crate::request::Span;

/// containerd's content directory, where its root is `/var/lib/containerd`.
pub const CONTAINERD_CONTENT_DIR: &str = "/var/lib/containerd/io.containerd.content.v1.content";

/// The namespace containerd's CRI plugin keeps its images in; the content service lists a blob only for a namespace
/// that has a reference to it.
pub const CONTAINERD_NAMESPACE: &str = "k8s.io";

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
    Grpc {
        channel: Channel,
        digest: String,
        namespace: String,
    },
    Memory(Bytes),
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => write!(f, "File({})", path.display()),
            Self::Grpc { digest, .. } => write!(f, "Grpc({digest})"),
            Self::Memory(bytes) => write!(f, "Memory({} bytes)", bytes.len()),
        }
    }
}

impl Blob {
    /// A blob that is a file.
    #[must_use]
    pub(crate) fn from_file(path: PathBuf, size: u64) -> Self {
        Self {
            size,
            source: Source::File(path),
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

    /// Its size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The bytes of `span`, as a stream.
    ///
    /// # Errors
    ///
    /// When the file cannot be opened or sought in, or containerd refuses the read.
    pub async fn stream(self, span: Span) -> Result<Chunks, Error> {
        match self.source {
            Source::Memory(bytes) => {
                let first = usize::try_from(span.first).unwrap_or(usize::MAX);
                let end = usize::try_from(span.last.saturating_add(1)).unwrap_or(usize::MAX);
                let part = bytes.slice(first.min(bytes.len())..end.min(bytes.len()));
                Ok(Box::pin(futures_util::stream::once(
                    async move { Ok(part) },
                )))
            }
            Source::File(path) => {
                let mut file = tokio::fs::File::open(path).await?;
                file.seek(io::SeekFrom::Start(span.first)).await?;
                Ok(Box::pin(
                    ReaderStream::with_capacity(file.take(span.bytes()), CHUNK).map_err(Error::Io),
                ))
            }
            Source::Grpc {
                channel,
                digest,
                namespace,
            } => {
                let mut client = ContentClient::new(channel);
                let mut request = Request::new(ReadContentRequest {
                    digest,
                    offset: i64::try_from(span.first).unwrap_or(i64::MAX),
                    size: i64::try_from(span.bytes()).unwrap_or(i64::MAX),
                });
                with_namespace(&mut request, &namespace);
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
        let Some(span) = Span::whole(self.size) else {
            return Ok(Bytes::new());
        };
        let mut chunks = self.stream(span).await?;
        let mut all = Vec::new();
        while let Some(chunk) = chunks.next().await {
            all.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(all))
    }
}

fn with_namespace<T>(request: &mut Request<T>, namespace: &str) {
    if let Ok(value) = namespace.parse() {
        request.metadata_mut().insert("containerd-namespace", value);
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

/// containerd's content: its directory, then its content service.
#[derive(Debug)]
pub struct Containerd {
    directory: PathBuf,
    socket: PathBuf,
    namespace: String,
    channel: tokio::sync::Mutex<Option<Channel>>,
}

impl Containerd {
    /// The content under `directory` (the content store's root, holding `blobs/`), and the service at `socket`.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>, socket: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            socket: socket.into(),
            namespace: CONTAINERD_NAMESPACE.to_owned(),
            channel: tokio::sync::Mutex::new(None),
        }
    }

    fn path(&self, digest: &Digest) -> PathBuf {
        self.directory
            .join("blobs")
            .join(digest.algorithm())
            .join(digest.encoded())
    }

    /// A channel to containerd, made once and kept; `None` while there is no containerd to connect to.
    async fn channel(&self) -> Option<Channel> {
        let mut held = self.channel.lock().await;
        if held.is_none() {
            *held = containerd_client::connect(&self.socket).await.ok();
        }
        held.clone()
    }

    async fn forget_channel(&self) {
        *self.channel.lock().await = None;
    }

    /// The size of the blob if containerd's content service has it.
    async fn info(&self, digest: &Digest) -> Result<Option<(Channel, u64)>, Error> {
        let Some(channel) = self.channel().await else {
            return Ok(None);
        };
        let mut request = Request::new(InfoRequest {
            digest: digest.to_string(),
        });
        with_namespace(&mut request, &self.namespace);
        match ContentClient::new(channel.clone()).info(request).await {
            Ok(response) => Ok(response
                .into_inner()
                .info
                .and_then(|info| u64::try_from(info.size).ok())
                .map(|size| (channel, size))),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            // A containerd that went away or restarted: the next request connects again.
            Err(status) if status.code() == Code::Unavailable => {
                self.forget_channel().await;
                Ok(None)
            }
            Err(status) => Err(Error::Grpc(status)),
        }
    }
}

impl Content for Containerd {
    async fn open(&self, digest: &Digest) -> Result<Option<Blob>, Error> {
        let path = self.path(digest);
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.is_file() => {
                return Ok(Some(Blob {
                    size: meta.len(),
                    source: Source::File(path),
                }));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
        Ok(self.info(digest).await?.map(|(channel, size)| Blob {
            size,
            source: Source::Grpc {
                channel,
                digest: digest.to_string(),
                namespace: self.namespace.clone(),
            },
        }))
    }
}

#[cfg(test)]
mod tests;
