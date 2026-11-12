//! What the runtime says about itself over the CRI: `RuntimeService.Version`, which containerd and CRI-O both answer
//! (D86).
//!
//! The calls are blocking: each runs on a runtime of its own, so none may be made from inside an async task.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use containerd_client::tonic::client::Grpc;
use containerd_client::tonic::codegen::http::uri::PathAndQuery;
use containerd_client::tonic::transport::Channel;
use containerd_client::tonic::{Request, Status};
use tonic_prost::ProstCodec;

use crate::version::Release;

/// How long a runtime may take to connect and to answer.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The method, in the CRI's `runtime.v1` package (`k8s.io/cri-api` `api.proto`).
const VERSION_METHOD: &str = "/runtime.v1.RuntimeService/Version";
const LIST_IMAGES_METHOD: &str = "/runtime.v1.ImageService/ListImages";

/// The largest answer to `ListImages` that is read: a node with thousands of images lists them in megabytes.
const MAX_LIST: usize = 64 << 20;

/// `VersionRequest`.
#[derive(Clone, PartialEq, prost::Message)]
struct VersionRequest {
    #[prost(string, tag = "1")]
    version: String,
}

/// `VersionResponse`.
#[derive(Clone, PartialEq, prost::Message)]
struct VersionResponse {
    #[prost(string, tag = "1")]
    version: String,
    #[prost(string, tag = "2")]
    runtime_name: String,
    #[prost(string, tag = "3")]
    runtime_version: String,
    #[prost(string, tag = "4")]
    runtime_api_version: String,
}

/// `ListImagesRequest`, with no filter.
#[derive(Clone, PartialEq, prost::Message)]
struct ListImagesRequest {}

/// `ListImagesResponse`.
#[derive(Clone, PartialEq, prost::Message)]
struct ListImagesResponse {
    #[prost(message, repeated, tag = "1")]
    images: Vec<Image>,
}

/// `Image`, of which the agent reads the names.
#[derive(Clone, PartialEq, prost::Message)]
struct Image {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, repeated, tag = "2")]
    repo_tags: Vec<String>,
    #[prost(string, repeated, tag = "3")]
    repo_digests: Vec<String>,
}

/// An image of the runtime's list, by its names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedImage {
    /// The image ID: on CRI-O, the digest of its config, without the algorithm.
    pub id: String,
    /// `repository:tag` names.
    pub repo_tags: Vec<String>,
    /// `repository@digest` names.
    pub repo_digests: Vec<String>,
}

/// What a runtime reports of itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeVersion {
    /// `runtime_name`: `containerd` or `cri-o`.
    pub name: String,
    /// `runtime_version` as reported, such as `v2.4.2` or `1.37.2`.
    pub version: String,
}

impl RuntimeVersion {
    /// The release in `version`, if it has the form of one.
    #[must_use]
    pub fn release(&self) -> Option<Release> {
        Release::parse(&self.version)
    }
}

/// Why a runtime could not be asked.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The socket could not be connected to.
    #[error("cannot connect to {}: {message}", path.display())]
    Connect {
        /// The socket.
        path: PathBuf,
        /// Why.
        message: String,
    },
    /// The runtime answered an error, or nothing in time.
    #[error("{} did not answer {method}: {message}", path.display())]
    Call {
        /// The socket.
        path: PathBuf,
        /// The method.
        method: &'static str,
        /// Why.
        message: String,
    },
}

impl Error {
    pub(crate) fn connect(path: &Path, message: &dyn std::fmt::Display) -> Self {
        Self::Connect {
            path: path.to_owned(),
            message: message.to_string(),
        }
    }

    pub(crate) fn call(path: &Path, method: &'static str, status: &Status) -> Self {
        Self::Call {
            path: path.to_owned(),
            method,
            message: format!("{}: {}", status.code(), status.message()),
        }
    }
}

/// Runs `future` on a runtime of its own, bounded by [`TIMEOUT`].
pub(crate) fn block_on<T>(
    path: &Path,
    method: &'static str,
    future: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::connect(path, &e))?;
    runtime.block_on(async {
        tokio::time::timeout(TIMEOUT, future)
            .await
            .unwrap_or_else(|_| {
                Err(Error::Call {
                    path: path.to_owned(),
                    method,
                    message: format!("no answer within {} s", TIMEOUT.as_secs()),
                })
            })
    })
}

/// A channel to the socket.
pub(crate) async fn connect(path: &Path) -> Result<Channel, Error> {
    containerd_client::connect(path)
        .await
        .map_err(|e| Error::connect(path, &e))
}

/// `RuntimeService.Version` on the socket of a runtime.
///
/// # Errors
///
/// When the socket cannot be connected to, or the runtime does not answer in 5 s.
pub fn version(socket: &Path) -> Result<RuntimeVersion, Error> {
    block_on(socket, VERSION_METHOD, async {
        let mut client = Grpc::new(connect(socket).await?);
        client
            .ready()
            .await
            .map_err(|e| Error::connect(socket, &e))?;
        let response: VersionResponse = client
            .unary(
                Request::new(VersionRequest {
                    version: "v1".to_owned(),
                }),
                PathAndQuery::from_static(VERSION_METHOD),
                ProstCodec::default(),
            )
            .await
            .map_err(|status| Error::call(socket, VERSION_METHOD, &status))?
            .into_inner();
        Ok(RuntimeVersion {
            name: response.runtime_name,
            version: response.runtime_version,
        })
    })
}

/// `ImageService.ListImages` on the socket of a runtime: every image it holds.
///
/// Unlike [`version`], this is async: the relay asks it while it serves.
///
/// # Errors
///
/// When the socket cannot be connected to, or the runtime does not answer in 5 s.
pub async fn list_images(socket: &Path) -> Result<Vec<ListedImage>, Error> {
    tokio::time::timeout(TIMEOUT, async {
        let mut client = Grpc::new(connect(socket).await?).max_decoding_message_size(MAX_LIST);
        client
            .ready()
            .await
            .map_err(|e| Error::connect(socket, &e))?;
        let response: ListImagesResponse = client
            .unary(
                Request::new(ListImagesRequest {}),
                PathAndQuery::from_static(LIST_IMAGES_METHOD),
                ProstCodec::default(),
            )
            .await
            .map_err(|status| Error::call(socket, LIST_IMAGES_METHOD, &status))?
            .into_inner();
        Ok(response
            .images
            .into_iter()
            .map(|image| ListedImage {
                id: image.id,
                repo_tags: image.repo_tags,
                repo_digests: image.repo_digests,
            })
            .collect())
    })
    .await
    .unwrap_or_else(|_| {
        Err(Error::Call {
            path: socket.to_owned(),
            method: LIST_IMAGES_METHOD,
            message: format!("no answer within {} s", TIMEOUT.as_secs()),
        })
    })
}
