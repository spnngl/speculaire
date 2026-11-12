//! The content directory, and containerd's content service as a fake one.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use bytes::Bytes;
use containerd_client::services::v1::{
    Info, InfoRequest, InfoResponse, ReadContentRequest, ReadContentResponse,
};
use containerd_client::tonic::server::Grpc;
use containerd_client::tonic::{Code, Request, Response, Status};
use futures_util::TryStreamExt as _;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use speculaire_oci::reference::Digest;
use tonic_prost::ProstCodec;

use super::Containerd;
use crate::containerd::NAMESPACE;
use crate::content::{Blob, Chunks, Content as _, Error};
use crate::paths::Paths;

fn digest_of(bytes: &[u8]) -> Digest {
    // Any hash will do: the content store does not check names against contents.
    let seed = bytes.iter().fold(0_u8, |acc, b| acc.wrapping_add(*b));
    Digest::parse(&format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn pattern(len: usize) -> Bytes {
    Bytes::from(
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect::<Vec<_>>(),
    )
}

/// A node of containerd whose files are under `root`.
fn containerd(root: &Path, socket: impl Into<std::path::PathBuf>) -> Containerd {
    Containerd::new(Paths::under(root), socket, None)
}

fn put(root: &Path, digest: &Digest, bytes: &[u8]) {
    let path = root
        .join("var/lib/containerd/io.containerd.content.v1.content")
        .join("blobs")
        .join(digest.algorithm())
        .join(digest.encoded());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

async fn collect(chunks: Chunks) -> Vec<u8> {
    let parts: Vec<Bytes> = chunks.try_collect().await.unwrap();
    parts.concat()
}

#[tokio::test]
async fn a_blob_in_the_content_directory_is_read_by_its_digest_at_any_span() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = pattern(1_000_000);
    let digest = digest_of(&bytes);
    put(dir.path(), &digest, &bytes);
    let content = containerd(dir.path(), dir.path().join("no.sock"));
    let blob = content.open(&digest).await.unwrap().unwrap();
    assert_eq!(blob.size(), 1_000_000);
    assert_eq!(
        collect(blob.stream(0, 1_000_000).await.unwrap()).await,
        bytes
    );
    for (first, last) in [
        (0, 0),
        (5, 9),
        (262_143, 262_144),
        (999_999, 999_999),
        (500_000, 999_999),
    ] {
        let blob = content.open(&digest).await.unwrap().unwrap();
        let got = collect(blob.stream(first, last - first + 1).await.unwrap()).await;
        assert_eq!(
            got,
            bytes[usize::try_from(first).unwrap()..=usize::try_from(last).unwrap()]
        );
    }
    let blob = content.open(&digest).await.unwrap().unwrap();
    assert_eq!(blob.read_all(1_000_000).await.unwrap(), bytes);
}

#[tokio::test]
async fn a_blob_that_is_not_there_is_none_and_a_directory_is_not_a_blob() {
    let dir = tempfile::tempdir().unwrap();
    let content = containerd(dir.path(), dir.path().join("no.sock"));
    assert!(content.open(&digest_of(b"x")).await.unwrap().is_none());
    let held = digest_of(b"y");
    std::fs::create_dir_all(
        dir.path()
            .join("blobs")
            .join(held.algorithm())
            .join(held.encoded()),
    )
    .unwrap();
    assert!(content.open(&held).await.unwrap().is_none());
    let other = tempfile::tempdir().unwrap();
    let blocked = containerd(other.path(), other.path().join("no.sock"));
    std::fs::write(other.path().join("var"), "").unwrap();
    assert!(matches!(blocked.open(&held).await, Err(Error::Io(_))));
}

#[tokio::test]
async fn a_blob_over_the_limit_is_not_read_whole_and_an_empty_one_is_empty() {
    let blob = Blob::from_bytes(pattern(100));
    let err = blob.read_all(99).await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::TooLarge {
                size: 100,
                limit: 99
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("100"), "{err}");
    assert_eq!(
        Blob::from_bytes(Bytes::new()).read_all(10).await.unwrap(),
        Bytes::new()
    );
    let part = Blob::from_bytes(pattern(100)).stream(10, 10).await.unwrap();
    assert_eq!(collect(part).await, pattern(100).slice(10..20));
    let beyond = Blob::from_bytes(pattern(10)).stream(50, 11).await.unwrap();
    assert_eq!(collect(beyond).await, Vec::<u8>::new());
}

// ---- a fake of containerd's content service ----

type Blobs = Arc<HashMap<String, Bytes>>;

/// What the fake does besides serving its blobs.
#[derive(Default)]
struct Behaviour {
    /// The gRPC code `Info` answers with instead of the blob's, when not 0.
    fail: AtomicI32,
    /// How many connections it accepted.
    connections: AtomicUsize,
}

fn fake_containerd(socket: &Path, blobs: Blobs) -> Arc<Behaviour> {
    let behaviour = Arc::new(Behaviour::default());
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let seen = Arc::clone(&behaviour);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            seen.connections.fetch_add(1, Ordering::SeqCst);
            let blobs = Arc::clone(&blobs);
            let behaviour = Arc::clone(&seen);
            tokio::spawn(async move {
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let blobs = Arc::clone(&blobs);
                    let behaviour = Arc::clone(&behaviour);
                    async move {
                        Ok::<_, Infallible>(content_service(&blobs, &behaviour, request).await)
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    behaviour
}

fn namespaced<T>(request: &Request<T>) -> Result<(), Status> {
    match request.metadata().get("containerd-namespace") {
        Some(namespace) if namespace == NAMESPACE => Ok(()),
        _ => Err(Status::invalid_argument("no namespace")),
    }
}

async fn content_service(
    blobs: &Blobs,
    behaviour: &Arc<Behaviour>,
    request: hyper::Request<hyper::body::Incoming>,
) -> hyper::Response<containerd_client::tonic::body::Body> {
    let blobs = Arc::clone(blobs);
    let behaviour = Arc::clone(behaviour);
    let mut grpc_info = Grpc::new(ProstCodec::<InfoResponse, InfoRequest>::default());
    let mut grpc_read = Grpc::new(ProstCodec::<ReadContentResponse, ReadContentRequest>::default());
    if request.uri().path() == "/containerd.services.content.v1.Content/Info" {
        let svc = tower::service_fn(move |request: Request<InfoRequest>| {
            let blobs = Arc::clone(&blobs);
            let behaviour = Arc::clone(&behaviour);
            async move {
                namespaced(&request)?;
                match behaviour.fail.load(Ordering::SeqCst) {
                    0 => {}
                    code => return Err(Status::new(Code::from(code), "told to fail")),
                }
                let digest = request.into_inner().digest;
                match blobs.get(&digest) {
                    Some(bytes) => Ok(Response::new(InfoResponse {
                        info: Some(Info {
                            digest,
                            size: i64::try_from(bytes.len()).unwrap(),
                            ..Info::default()
                        }),
                    })),
                    None => Err(Status::not_found("no such blob")),
                }
            }
        });
        grpc_info.unary(svc, request).await
    } else {
        let svc = tower::service_fn(move |request: Request<ReadContentRequest>| {
            let blobs = Arc::clone(&blobs);
            async move {
                namespaced(&request)?;
                let read = request.into_inner();
                let bytes = blobs
                    .get(&read.digest)
                    .ok_or_else(|| Status::not_found("no such blob"))?;
                let start = usize::try_from(read.offset).unwrap();
                let end = if read.size == 0 {
                    bytes.len()
                } else {
                    start + usize::try_from(read.size).unwrap()
                };
                // Seven bytes at a time, as a service that sends many messages does.
                let messages: Vec<Result<ReadContentResponse, Status>> = bytes[start..end]
                    .chunks(7)
                    .scan(start, |offset, chunk| {
                        let message = ReadContentResponse {
                            offset: i64::try_from(*offset).unwrap(),
                            data: chunk.to_vec(),
                        };
                        *offset += chunk.len();
                        Some(Ok(message))
                    })
                    .collect();
                Ok(Response::new(futures_util::stream::iter(messages)))
            }
        });
        grpc_read.server_streaming(svc, request).await
    }
}

#[tokio::test]
async fn a_blob_the_directory_lacks_is_read_from_the_content_service() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = pattern(1000);
    let digest = digest_of(&bytes);
    let held = HashMap::from([(digest.to_string(), bytes.clone())]);
    let socket = dir.path().join("containerd.sock");
    fake_containerd(&socket, Arc::new(held));
    let content = containerd(&dir.path().join("empty"), &socket);
    let blob = content.open(&digest).await.unwrap().unwrap();
    assert_eq!(blob.size(), 1000);
    assert_eq!(collect(blob.stream(0, 1000).await.unwrap()).await, bytes);
    let blob = content.open(&digest).await.unwrap().unwrap();
    assert_eq!(
        collect(blob.stream(100, 100).await.unwrap()).await,
        bytes[100..200]
    );
    // What the service does not have is a miss, and the directory comes first.
    assert!(
        content
            .open(&digest_of(b"unknown"))
            .await
            .unwrap()
            .is_none()
    );
    put(&dir.path().join("empty"), &digest, b"from the directory");
    let blob = content.open(&digest).await.unwrap().unwrap();
    assert_eq!(blob.size(), 18);
}

#[tokio::test]
async fn a_service_that_went_away_is_a_miss_and_the_next_request_connects_again() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = pattern(10);
    let digest = digest_of(&bytes);
    let socket = dir.path().join("containerd.sock");
    let content = containerd(&dir.path().join("empty"), &socket);
    // No service yet.
    assert!(content.open(&digest).await.unwrap().is_none());
    fake_containerd(
        &socket,
        Arc::new(HashMap::from([(digest.to_string(), bytes)])),
    );
    assert!(content.open(&digest).await.unwrap().is_some());
}

#[tokio::test]
async fn a_service_that_is_unavailable_is_a_miss_and_the_next_request_connects_again() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = pattern(10);
    let digest = digest_of(&bytes);
    let socket = dir.path().join("containerd.sock");
    let service = fake_containerd(
        &socket,
        Arc::new(HashMap::from([(digest.to_string(), bytes)])),
    );
    let content = containerd(&dir.path().join("empty"), &socket);
    assert!(content.open(&digest).await.unwrap().is_some());
    assert!(content.open(&digest).await.unwrap().is_some());
    // The channel is kept: one connection served both.
    assert_eq!(service.connections.load(Ordering::SeqCst), 1);
    service
        .fail
        .store(Code::Unavailable as i32, Ordering::SeqCst);
    assert!(content.open(&digest).await.unwrap().is_none());
    service.fail.store(0, Ordering::SeqCst);
    assert!(content.open(&digest).await.unwrap().is_some());
    assert_eq!(service.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_service_that_fails_otherwise_is_an_error_and_keeps_its_channel() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = pattern(10);
    let digest = digest_of(&bytes);
    let socket = dir.path().join("containerd.sock");
    let service = fake_containerd(
        &socket,
        Arc::new(HashMap::from([(digest.to_string(), bytes)])),
    );
    let content = containerd(&dir.path().join("empty"), &socket);
    assert!(content.open(&digest).await.unwrap().is_some());
    service.fail.store(Code::Internal as i32, Ordering::SeqCst);
    assert!(matches!(
        content.open(&digest).await,
        Err(Error::Grpc(status)) if status.code() == Code::Internal
    ));
    service.fail.store(0, Ordering::SeqCst);
    assert!(content.open(&digest).await.unwrap().is_some());
    assert_eq!(service.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_file_is_streamed_in_chunks_of_a_quarter_mebibyte() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = pattern(1_000_000);
    let digest = digest_of(&bytes);
    put(dir.path(), &digest, &bytes);
    let content = containerd(dir.path(), dir.path().join("no.sock"));
    let blob = content.open(&digest).await.unwrap().unwrap();
    let chunks: Vec<Bytes> = blob
        .stream(0, 1_000_000)
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    let sizes: Vec<usize> = chunks.iter().map(Bytes::len).collect();
    assert_eq!(sizes, [262_144, 262_144, 262_144, 213_568]);
}

#[tokio::test]
async fn a_blob_prints_where_it_comes_from_and_not_what_it_holds() {
    let memory = format!("{:?}", Blob::from_bytes(pattern(10)));
    assert!(memory.contains("Memory(10 bytes)"), "{memory}");
    let dir = tempfile::tempdir().unwrap();
    let digest = digest_of(b"x");
    put(dir.path(), &digest, b"x");
    let content = containerd(dir.path(), dir.path().join("no.sock"));
    let blob = content.open(&digest).await.unwrap().unwrap();
    let file = format!("{blob:?}");
    assert!(
        file.contains("File(") && file.contains(digest.encoded()),
        "{file}"
    );
}
