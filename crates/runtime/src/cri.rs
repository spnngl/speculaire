//! The CRI calls the agent makes, which containerd and CRI-O both answer alike (D86): what the runtime says about
//! itself, what it holds and runs, and pulling an image as the kubelet does.
//!
//! [`version`] is blocking: it runs on a runtime of its own, so it may not be called from inside an async task.

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

/// How long a pull may take. containerd cancels a pull whose progress stalls for 5 minutes, CRI-O never does
/// (`pull_progress_timeout`), so this bounds a stalled pull on CRI-O (D188).
const PULL_TIMEOUT: Duration = Duration::from_mins(30);

/// How long `ImageFsInfo` may take: CRI-O walks the whole image store to answer it
/// (`server/image_fs_info.go:15` at v1.37.2), so it is given the kubelet's default `--runtime-request-timeout`.
const FS_INFO_TIMEOUT: Duration = Duration::from_mins(2);

/// The method, in the CRI's `runtime.v1` package (`k8s.io/cri-api` `api.proto`).
const VERSION_METHOD: &str = "/runtime.v1.RuntimeService/Version";
const LIST_IMAGES_METHOD: &str = "/runtime.v1.ImageService/ListImages";
const LIST_CONTAINERS_METHOD: &str = "/runtime.v1.RuntimeService/ListContainers";
const PULL_IMAGE_METHOD: &str = "/runtime.v1.ImageService/PullImage";
const IMAGE_FS_INFO_METHOD: &str = "/runtime.v1.ImageService/ImageFsInfo";

/// `CONTAINER_RUNNING` of the CRI's `ContainerState`.
const CONTAINER_RUNNING: i32 = 1;

/// The largest answer that is read: a node with thousands of images lists them in megabytes.
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
    images: Vec<ListedImage>,
}

/// An image of the runtime's list, by its names: the fields of the CRI's `Image` that the agent reads.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct ListedImage {
    /// The image ID: on CRI-O, the digest of its config, without the algorithm.
    #[prost(string, tag = "1")]
    pub id: String,
    /// `repository:tag` names.
    #[prost(string, repeated, tag = "2")]
    pub repo_tags: Vec<String>,
    /// `repository@digest` names.
    #[prost(string, repeated, tag = "3")]
    pub repo_digests: Vec<String>,
}

/// `ImageSpec`, by reference alone.
#[derive(Clone, PartialEq, prost::Message)]
struct ImageSpec {
    #[prost(string, tag = "1")]
    image: String,
}

/// `PullImageRequest`, without `auth`: the runtime takes credentials from its registry config (D17).
#[derive(Clone, PartialEq, prost::Message)]
struct PullImageRequest {
    #[prost(message, optional, tag = "1")]
    image: Option<ImageSpec>,
}

/// `PullImageResponse`.
#[derive(Clone, PartialEq, prost::Message)]
struct PullImageResponse {
    #[prost(string, tag = "1")]
    image_ref: String,
}

/// `ImageFsInfoRequest`.
#[derive(Clone, PartialEq, prost::Message)]
struct ImageFsInfoRequest {}

/// `ImageFsInfoResponse`, without `container_filesystems`.
#[derive(Clone, PartialEq, prost::Message)]
struct ImageFsInfoResponse {
    #[prost(message, repeated, tag = "1")]
    image_filesystems: Vec<FilesystemUsage>,
}

/// `FilesystemUsage`, by its identifier alone.
#[derive(Clone, PartialEq, prost::Message)]
struct FilesystemUsage {
    #[prost(message, optional, tag = "2")]
    fs_id: Option<FilesystemIdentifier>,
}

/// `FilesystemIdentifier`.
#[derive(Clone, PartialEq, prost::Message)]
struct FilesystemIdentifier {
    #[prost(string, tag = "1")]
    mountpoint: String,
}

/// `ListContainersRequest`.
#[derive(Clone, PartialEq, prost::Message)]
struct ListContainersRequest {
    #[prost(message, optional, tag = "1")]
    filter: Option<ContainerFilter>,
}

/// `ContainerFilter`, by state alone.
#[derive(Clone, PartialEq, prost::Message)]
struct ContainerFilter {
    #[prost(message, optional, tag = "2")]
    state: Option<ContainerStateValue>,
}

/// `ContainerStateValue`.
#[derive(Clone, PartialEq, prost::Message)]
struct ContainerStateValue {
    #[prost(int32, tag = "1")]
    state: i32,
}

/// `ListContainersResponse`.
#[derive(Clone, PartialEq, prost::Message)]
struct ListContainersResponse {
    #[prost(message, repeated, tag = "1")]
    containers: Vec<ListedContainer>,
}

/// The image fields of the CRI's `Container`.
#[derive(Clone, PartialEq, prost::Message)]
struct ListedContainer {
    /// containerd: the image ID; CRI-O: some `repository@digest` of the image, or its ID
    /// (`internal/oci/container.go:181` at v1.37.2).
    #[prost(string, tag = "5")]
    image_ref: String,
    /// The image ID, as `ListImages` gives it; empty from a runtime older than the field.
    #[prost(string, tag = "10")]
    image_id: String,
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
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::connect(path, &e))?
        .block_on(timed(path, method, future))
}

/// `future`, bounded by [`TIMEOUT`]; not `async` itself, so as not to nest one more future in its callers'.
fn timed<'a, T: 'a>(
    path: &'a Path,
    method: &'static str,
    future: impl Future<Output = Result<T, Error>> + 'a,
) -> impl Future<Output = Result<T, Error>> + 'a {
    within(TIMEOUT, path, method, future)
}

/// `future`, bounded by `limit`.
async fn within<T>(
    limit: Duration,
    path: &Path,
    method: &'static str,
    future: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    tokio::time::timeout(limit, future)
        .await
        .unwrap_or_else(|_| {
            Err(Error::Call {
                path: path.to_owned(),
                method,
                message: format!("no answer within {} s", limit.as_secs()),
            })
        })
}

/// The unary CRI `method` on the socket, with `request`.
async fn unary<Q, A>(socket: &Path, method: &'static str, request: Q) -> Result<A, Error>
where
    Q: prost::Message + Send + Sync + 'static,
    A: prost::Message + Default + Send + Sync + 'static,
{
    let mut client = Grpc::new(connect(socket).await?).max_decoding_message_size(MAX_LIST);
    client
        .ready()
        .await
        .map_err(|e| Error::connect(socket, &e))?;
    Ok(client
        .unary(
            Request::new(request),
            PathAndQuery::from_static(method),
            ProstCodec::default(),
        )
        .await
        .map_err(|status| Error::call(socket, method, &status))?
        .into_inner())
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
    let request = VersionRequest {
        version: "v1".to_owned(),
    };
    let response: VersionResponse = block_on(
        socket,
        VERSION_METHOD,
        unary(socket, VERSION_METHOD, request),
    )?;
    Ok(RuntimeVersion {
        name: response.runtime_name,
        version: response.runtime_version,
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
    let response: ListImagesResponse = timed(
        socket,
        LIST_IMAGES_METHOD,
        unary(socket, LIST_IMAGES_METHOD, ListImagesRequest {}),
    )
    .await?;
    Ok(response.images)
}

/// `RuntimeService.ListContainers` on the socket of a runtime: the image ID of each running container, as
/// [`ListedImage::id`] writes it, or its image reference from a runtime without the field.
///
/// # Errors
///
/// When the socket cannot be connected to, or the runtime does not answer in 5 s.
pub async fn running_images(socket: &Path) -> Result<Vec<String>, Error> {
    let request = ListContainersRequest {
        filter: Some(ContainerFilter {
            state: Some(ContainerStateValue {
                state: CONTAINER_RUNNING,
            }),
        }),
    };
    let response: ListContainersResponse = timed(
        socket,
        LIST_CONTAINERS_METHOD,
        unary(socket, LIST_CONTAINERS_METHOD, request),
    )
    .await?;
    Ok(response
        .containers
        .into_iter()
        .map(|container| {
            if container.image_id.is_empty() {
                container.image_ref
            } else {
                container.image_id
            }
        })
        .collect())
}

/// `ImageService.PullImage` of `image` on the socket of a runtime, with no credentials: the image lands where the
/// kubelet looks, pulled through the runtime's registry config like any pull (D188).
///
/// # Errors
///
/// When the socket cannot be connected to, or the pull fails or takes longer than 30 minutes.
pub async fn pull_image(socket: &Path, image: &str) -> Result<(), Error> {
    let request = PullImageRequest {
        image: Some(ImageSpec {
            image: image.to_owned(),
        }),
    };
    let _: PullImageResponse = within(
        PULL_TIMEOUT,
        socket,
        PULL_IMAGE_METHOD,
        unary(socket, PULL_IMAGE_METHOD, request),
    )
    .await?;
    Ok(())
}

/// `ImageService.ImageFsInfo` on the socket of a runtime: the mount point of the filesystem images land on, the
/// first one named, as the kubelet reads it (`internal/cri/server/images/imagefs_info.go:55` in containerd v2.4.2);
/// `None` when it names none.
///
/// # Errors
///
/// When the socket cannot be connected to, or the runtime does not answer in 2 minutes.
pub async fn image_filesystem(socket: &Path) -> Result<Option<PathBuf>, Error> {
    let response: ImageFsInfoResponse = within(
        FS_INFO_TIMEOUT,
        socket,
        IMAGE_FS_INFO_METHOD,
        unary(socket, IMAGE_FS_INFO_METHOD, ImageFsInfoRequest {}),
    )
    .await?;
    Ok(response
        .image_filesystems
        .into_iter()
        .next()
        .and_then(|usage| usage.fs_id)
        .map(|id| id.mountpoint)
        .filter(|mountpoint| !mountpoint.is_empty())
        .map(PathBuf::from))
}
