//! A fake containerd or CRI-O, for tests that run where there is no runtime (the CI runner, macOS): it answers the CRI's
//! `Version`, `ListImages` and `ListContainers`, containerd's introspection `Plugins`, content `List` and `Info`, images
//! `List` and `Get`, snapshots `Stat` and events `Subscribe`, and CRI-O's `GET /config` on a Unix socket, which is all
//! preflight, the registry config, the inventory, the image store, the mirror and the engine ask (D86, D99). On its NRI
//! socket, it registers the plugin that connects (D168).

use std::convert::Infallible;
use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use bytes::Bytes;
use containerd_client::services::v1::snapshots::{self, StatSnapshotRequest, StatSnapshotResponse};
use containerd_client::services::v1::{
    GetImageRequest, GetImageResponse, Info, ListContentRequest, ListContentResponse,
    ListImagesRequest as ListStoredRequest, ListImagesResponse as ListStoredResponse, Plugin,
    PluginsRequest, PluginsResponse, SubscribeRequest,
};
use containerd_client::tonic::codegen::http;
use containerd_client::tonic::server::Grpc;
use containerd_client::tonic::{Request, Response, Status};
use containerd_client::types::{Descriptor, Envelope};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use socket2::SockRef;
use tonic_prost::ProstCodec;

// Linux only: macOS spawns in the kernel, and refuses to shut a listener down.
#[cfg(all(test, target_os = "linux"))]
mod tests;

/// `VersionRequest` of the CRI.
#[derive(Clone, PartialEq, prost::Message)]
struct VersionRequest {
    #[prost(string, tag = "1")]
    version: String,
}

/// `VersionResponse` of the CRI.
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

/// `ListImagesRequest` of the CRI.
#[derive(Clone, PartialEq, prost::Message)]
struct ListImagesRequest {}

/// `ListImagesResponse` of the CRI.
#[derive(Clone, PartialEq, prost::Message)]
struct ListImagesResponse {
    #[prost(message, repeated, tag = "1")]
    images: Vec<Image>,
}

/// `Image` of the CRI.
#[derive(Clone, PartialEq, prost::Message)]
struct Image {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, repeated, tag = "2")]
    repo_tags: Vec<String>,
    #[prost(string, repeated, tag = "3")]
    repo_digests: Vec<String>,
}

/// `ListContainersRequest` of the CRI, its filter by state alone.
#[derive(Clone, PartialEq, prost::Message)]
struct ListContainersRequest {
    #[prost(message, optional, tag = "1")]
    filter: Option<ContainerFilter>,
}

/// `ContainerFilter` of the CRI.
#[derive(Clone, PartialEq, prost::Message)]
struct ContainerFilter {
    #[prost(message, optional, tag = "2")]
    state: Option<ContainerStateValue>,
}

/// `ContainerStateValue` of the CRI.
#[derive(Clone, PartialEq, prost::Message)]
struct ContainerStateValue {
    #[prost(int32, tag = "1")]
    state: i32,
}

/// `ListContainersResponse` of the CRI.
#[derive(Clone, PartialEq, prost::Message)]
struct ListContainersResponse {
    #[prost(message, repeated, tag = "1")]
    containers: Vec<Container>,
}

/// `Container` of the CRI: its state and image.
#[derive(Clone, PartialEq, prost::Message)]
struct Container {
    #[prost(string, tag = "5")]
    image_ref: String,
    #[prost(int32, tag = "6")]
    state: i32,
    #[prost(string, tag = "10")]
    image_id: String,
}

/// `CONTAINER_RUNNING` and `CONTAINER_EXITED` of the CRI's `ContainerState`.
const RUNNING: i32 = 1;
const EXITED: i32 = 2;

/// What the fake answers.
#[derive(Clone, Debug)]
pub struct Answers {
    /// `runtime_name` of `Version`.
    pub runtime_name: String,
    /// `runtime_version` of `Version`.
    pub runtime_version: String,
    /// The exports of the CRI image service in `Plugins`: `DiscardUnpackedLayers` and `RegistryConfigPath`; `None`
    /// lists no such plugin.
    pub image_exports: Option<(bool, String)>,
    /// Whether `Plugins` fails as `Unavailable`.
    pub plugins_unavailable: bool,
    /// The images of `ListImages`: ID, tags and digests.
    pub images: Vec<(String, Vec<String>, Vec<String>)>,
    /// The containers of `ListContainers`: the image ID, and whether it runs; a filter by state is applied.
    pub containers: Vec<(String, bool)>,
    /// The body of CRI-O's `GET /config`, its merged TOML; `None` answers 503.
    pub crio_config: Option<String>,
    /// The digests of containerd's content `List`, whatever the namespace; `Info` finds nothing: the fake holds no
    /// bytes.
    pub content: Vec<String>,
    /// `NRI_version` of NRI's `Configure`, empty for none.
    pub nri_version: String,
    /// The images of containerd's images `List` and `Get`, whatever the namespace: name and target digest. Each target
    /// is an OCI index.
    pub image_store: Vec<(String, String)>,
    /// Whether containerd's images `Get` answers `Unavailable`, as a containerd going away does.
    pub image_get_unavailable: bool,
    /// The snapshots of containerd's snapshots `Stat`, whatever the snapshotter and namespace.
    pub snapshots: Vec<Snapshot>,
}

/// A snapshot of containerd.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Its key.
    pub key: String,
    /// The key of the snapshot it rests on, or empty.
    pub parent: String,
    /// Its labels.
    pub labels: Vec<(String, String)>,
}

impl Answers {
    /// containerd at `version`, whose image service discards no layer and reads `/etc/containerd/certs.d`.
    #[must_use]
    pub fn containerd(version: &str) -> Self {
        Self {
            runtime_name: "containerd".to_owned(),
            runtime_version: version.to_owned(),
            image_exports: Some((false, "/etc/containerd/certs.d".to_owned())),
            plugins_unavailable: false,
            images: Vec::new(),
            containers: Vec::new(),
            content: Vec::new(),
            image_store: Vec::new(),
            image_get_unavailable: false,
            snapshots: Vec::new(),
            crio_config: None,
            nri_version: "v0.12.3".to_owned(),
        }
    }

    /// CRI-O at `version`, with NRI enabled and open, requiring no plugin.
    #[must_use]
    pub fn crio(version: &str) -> Self {
        Self {
            runtime_name: "cri-o".to_owned(),
            runtime_version: version.to_owned(),
            image_exports: None,
            plugins_unavailable: false,
            images: Vec::new(),
            containers: Vec::new(),
            content: Vec::new(),
            image_store: Vec::new(),
            image_get_unavailable: false,
            snapshots: Vec::new(),
            crio_config: Some(
                "[crio.nri]\nenable_nri = true\nnri_disable_connections = false\n".to_owned(),
            ),
            nri_version: "v0.12.2".to_owned(),
        }
    }
}

/// What the fake's connections share with the tests that drive it.
#[derive(Debug)]
struct Shared {
    answers: Mutex<Answers>,
    /// The events every `Subscribe` sends, whatever its filters.
    events: tokio::sync::broadcast::Sender<Envelope>,
    /// Each change of it ends every `Subscribe`.
    cut: tokio::sync::watch::Sender<u64>,
    /// The snapshots `Stat` calls answered so far.
    stats: AtomicUsize,
}

/// A fake runtime listening on a socket until it is dropped.
#[derive(Debug)]
pub struct Fake {
    shared: Arc<Shared>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Fake {
    /// Listens on `socket`, which exists once this returns.
    ///
    /// # Errors
    ///
    /// When the socket cannot be bound.
    pub fn start(socket: &Path, answers: Answers) -> io::Result<Self> {
        Self::serve(UnixListener::bind(socket)?, answers, Protocol::Runtime)
    }

    /// Listens on `socket` as the runtime's NRI, which exists once this returns: it registers each plugin that
    /// connects, with the runtime name and version of `answers` at that moment, and holds it until it disconnects.
    ///
    /// # Errors
    ///
    /// When the socket cannot be bound.
    pub fn start_nri(socket: &Path, answers: Answers) -> io::Result<Self> {
        Self::serve(UnixListener::bind(socket)?, answers, Protocol::Nri)
    }

    /// Answers on `listener` until dropped.
    fn serve(listener: UnixListener, answers: Answers, protocol: Protocol) -> io::Result<Self> {
        listener.set_nonblocking(true)?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let shared = Arc::new(Shared {
            answers: Mutex::new(answers),
            events: tokio::sync::broadcast::channel(64).0,
            cut: tokio::sync::watch::channel(0).0,
            stats: AtomicUsize::new(0),
        });
        let served = Arc::clone(&shared);
        let thread = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
                    return;
                };
                let accept = async {
                    match protocol {
                        Protocol::Runtime => accept(&listener, served).await,
                        Protocol::Nri => accept_nri(&listener, &served).await,
                    }
                };
                tokio::select! {
                    () = accept => {}
                    _ = stopped => {}
                }
                // A process another test spawns holds a copy of the socket until it execs, and the socket listens
                // until its last copy closes. Shut down, it refuses at once on Linux (v6.12 net/unix/af_unix.c:1606).
                // macOS refuses to shut a listener down (ENOTCONN), but it spawns in the kernel: no child holds it.
                let _ = SockRef::from(&listener).shutdown(Shutdown::Both);
            });
        });
        Ok(Self {
            shared,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Fake {
    /// Changes what the fake answers from the next call on.
    pub fn update(&self, change: impl FnOnce(&mut Answers)) {
        change(
            &mut self
                .shared
                .answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Sends `envelope` to every live `Subscribe`, as containerd publishes an event.
    pub fn publish(&self, envelope: Envelope) {
        // No subscriber: nobody hears it, as with containerd.
        let _ = self.shared.events.send(envelope);
    }

    /// The live `Subscribe` streams.
    #[must_use]
    pub fn subscribers(&self) -> usize {
        self.shared.events.receiver_count()
    }

    /// Ends every live `Subscribe` stream, as a containerd restart does.
    pub fn cut(&self) {
        self.shared.cut.send_modify(|cuts| *cuts += 1);
    }

    /// The snapshots `Stat` calls answered so far.
    #[must_use]
    pub fn stats(&self) -> usize {
        self.shared.stats.load(Ordering::Relaxed)
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            // The thread ended already: nothing to stop.
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            // A panic in the fake has no one to tell.
            let _ = thread.join();
        }
    }
}

/// What a fake speaks on its socket.
#[derive(Clone, Copy)]
enum Protocol {
    /// The CRI, containerd's services and CRI-O's inspect API.
    Runtime,
    /// NRI's runtime side.
    Nri,
}

/// Registers each plugin that connects until it disconnects; one that breaks the protocol is dropped.
async fn accept_nri(listener: &tokio::net::UnixListener, shared: &Shared) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let runtime = {
            let answers = shared
                .answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            speculaire_nri::testing::Runtime {
                name: answers.runtime_name.clone(),
                version: answers.runtime_version.clone(),
                nri_version: answers.nri_version.clone(),
                request_timeout: Duration::from_secs(2),
            }
        };
        tokio::spawn(async move {
            let (reader, writer) = stream.into_split();
            // A plugin that breaks the protocol has the test that runs it to tell.
            let _ = runtime.serve(reader, writer).await;
        });
    }
}

/// CRI-O's `GET /config`.
fn config(answers: &Answers) -> http::Response<containerd_client::tonic::body::Body> {
    let (status, body) = match &answers.crio_config {
        Some(body) => (http::StatusCode::OK, body.clone()),
        None => (http::StatusCode::SERVICE_UNAVAILABLE, String::new()),
    };
    let mut response = http::Response::new(containerd_client::tonic::body::Body::new(
        http_body_util::Full::new(Bytes::from(body)),
    ));
    *response.status_mut() = status;
    response
}

async fn accept(listener: &tokio::net::UnixListener, shared: Arc<Shared>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
                let shared = Arc::clone(&shared);
                async move { Ok::<_, Infallible>(route(&shared, request).await) }
            });
            // A client that hangs up ends its own connection. gRPC speaks HTTP/2, CRI-O's inspect API HTTP/1.
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn route(
    shared: &Arc<Shared>,
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<containerd_client::tonic::body::Body> {
    let answers = Arc::new(
        shared
            .answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone(),
    );
    match request.uri().path() {
        "/config" => config(&answers),
        "/runtime.v1.RuntimeService/Version" => {
            let service = tower::service_fn(move |_: Request<VersionRequest>| {
                let answers = Arc::clone(&answers);
                async move {
                    Ok::<_, Status>(Response::new(VersionResponse {
                        version: "0.1.0".to_owned(),
                        runtime_name: answers.runtime_name.clone(),
                        runtime_version: answers.runtime_version.clone(),
                        runtime_api_version: "v1".to_owned(),
                    }))
                }
            });
            Grpc::new(ProstCodec::<VersionResponse, VersionRequest>::default())
                .unary(service, request)
                .await
        }
        "/containerd.services.introspection.v1.Introspection/Plugins" => {
            plugins(answers, request).await
        }
        "/runtime.v1.ImageService/ListImages" => {
            let service = tower::service_fn(move |_: Request<ListImagesRequest>| {
                let answers = Arc::clone(&answers);
                async move {
                    Ok::<_, Status>(Response::new(ListImagesResponse {
                        images: answers
                            .images
                            .iter()
                            .map(|(id, repo_tags, repo_digests)| Image {
                                id: id.clone(),
                                repo_tags: repo_tags.clone(),
                                repo_digests: repo_digests.clone(),
                            })
                            .collect(),
                    }))
                }
            });
            Grpc::new(ProstCodec::<ListImagesResponse, ListImagesRequest>::default())
                .unary(service, request)
                .await
        }
        "/runtime.v1.RuntimeService/ListContainers" => containers(answers, request).await,
        "/containerd.services.content.v1.Content/List" => content(answers, request).await,
        "/containerd.services.content.v1.Content/Info" => {
            Status::not_found("the fake runtime holds no bytes").into_http()
        }
        "/containerd.services.images.v1.Images/List" => stored_images(answers, request).await,
        "/containerd.services.images.v1.Images/Get" => stored_image(answers, request).await,
        "/containerd.services.snapshots.v1.Snapshots/Stat" => {
            shared.stats.fetch_add(1, Ordering::Relaxed);
            stat(answers, request).await
        }
        "/containerd.services.events.v1.Events/Subscribe" => events(shared, request).await,
        other => Status::unimplemented(format!("the fake runtime has no {other}")).into_http(),
    }
}

/// containerd's content `List`: every digest of `Answers::content`, in one message.
async fn content(
    answers: Arc<Answers>,
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<containerd_client::tonic::body::Body> {
    let service = tower::service_fn(move |_: Request<ListContentRequest>| {
        let answers = Arc::clone(&answers);
        async move {
            let info = answers
                .content
                .iter()
                .map(|digest| Info {
                    digest: digest.clone(),
                    ..Info::default()
                })
                .collect();
            let messages = [Ok::<_, Status>(ListContentResponse { info })];
            Ok::<_, Status>(Response::new(futures_util::stream::iter(messages)))
        }
    });
    Grpc::new(ProstCodec::<ListContentResponse, ListContentRequest>::default())
        .server_streaming(service, request)
        .await
}

/// The CRI's `ListContainers`: each container of `Answers::containers` in the state the filter asks, if it asks one.
async fn containers(
    answers: Arc<Answers>,
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<containerd_client::tonic::body::Body> {
    let service = tower::service_fn(move |listed: Request<ListContainersRequest>| {
        let answers = Arc::clone(&answers);
        async move {
            let wanted = listed
                .into_inner()
                .filter
                .and_then(|filter| filter.state)
                .map(|state| state.state);
            Ok::<_, Status>(Response::new(ListContainersResponse {
                containers: answers
                    .containers
                    .iter()
                    .map(|(id, running)| Container {
                        image_ref: id.clone(),
                        state: if *running { RUNNING } else { EXITED },
                        image_id: id.clone(),
                    })
                    .filter(|container| wanted.is_none_or(|state| state == container.state))
                    .collect(),
            }))
        }
    });
    Grpc::new(ProstCodec::<ListContainersResponse, ListContainersRequest>::default())
        .unary(service, request)
        .await
}

/// containerd's image of `Answers::image_store`.
fn stored(name: &str, digest: &str) -> containerd_client::services::v1::Image {
    containerd_client::services::v1::Image {
        name: name.to_owned(),
        target: Some(Descriptor {
            media_type: "application/vnd.oci.image.index.v1+json".to_owned(),
            digest: digest.to_owned(),
            ..Descriptor::default()
        }),
        ..containerd_client::services::v1::Image::default()
    }
}

/// containerd's images `List`: every image of `Answers::image_store`; filters are not applied.
async fn stored_images(
    answers: Arc<Answers>,
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<containerd_client::tonic::body::Body> {
    let service = tower::service_fn(move |_: Request<ListStoredRequest>| {
        let answers = Arc::clone(&answers);
        async move {
            Ok::<_, Status>(Response::new(ListStoredResponse {
                images: answers
                    .image_store
                    .iter()
                    .map(|(name, digest)| stored(name, digest))
                    .collect(),
            }))
        }
    });
    Grpc::new(ProstCodec::<ListStoredResponse, ListStoredRequest>::default())
        .unary(service, request)
        .await
}

/// containerd's images `Get`: the image of `Answers::image_store` with the name asked, or `NotFound`; `Unavailable` if
/// `Answers::image_get_unavailable`.
async fn stored_image(
    answers: Arc<Answers>,
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<containerd_client::tonic::body::Body> {
    let service = tower::service_fn(move |asked: Request<GetImageRequest>| {
        let answers = Arc::clone(&answers);
        async move {
            if answers.image_get_unavailable {
                return Err(Status::unavailable(
                    "the fake containerd's images are unavailable",
                ));
            }
            let name = asked.into_inner().name;
            answers
                .image_store
                .iter()
                .find(|(stored, _)| *stored == name)
                .map(|(name, digest)| {
                    Response::new(GetImageResponse {
                        image: Some(stored(name, digest)),
                    })
                })
                .ok_or_else(|| Status::not_found(format!("image {name:?}: not found")))
        }
    });
    Grpc::new(ProstCodec::<GetImageResponse, GetImageRequest>::default())
        .unary(service, request)
        .await
}

/// containerd's snapshots `Stat`: the snapshot of `Answers::snapshots` with the key asked, or `NotFound`.
async fn stat(
    answers: Arc<Answers>,
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<containerd_client::tonic::body::Body> {
    let service = tower::service_fn(move |asked: Request<StatSnapshotRequest>| {
        let answers = Arc::clone(&answers);
        async move {
            let key = asked.into_inner().key;
            answers
                .snapshots
                .iter()
                .find(|snapshot| snapshot.key == key)
                .map(|snapshot| {
                    Response::new(StatSnapshotResponse {
                        info: Some(snapshots::Info {
                            name: snapshot.key.clone(),
                            parent: snapshot.parent.clone(),
                            labels: snapshot.labels.iter().cloned().collect(),
                            ..snapshots::Info::default()
                        }),
                    })
                })
                .ok_or_else(|| Status::not_found(format!("snapshot {key:?}: not found")))
        }
    });
    Grpc::new(ProstCodec::<StatSnapshotResponse, StatSnapshotRequest>::default())
        .unary(service, request)
        .await
}

/// containerd's events `Subscribe`: each event `Fake::publish` sends from now on, whatever the filters, until
/// `Fake::cut`.
async fn events(
    shared: &Shared,
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<containerd_client::tonic::body::Body> {
    let events = shared.events.subscribe();
    let mut cut = shared.cut.subscribe();
    cut.mark_unchanged();
    let stream = futures_util::stream::unfold((events, cut), |(mut events, mut cut)| async move {
        loop {
            let received = tokio::select! {
                _ = cut.changed() => return None,
                received = events.recv() => received,
            };
            match received {
                Ok(envelope) => return Some((Ok::<_, Status>(envelope), (events, cut))),
                // A test that publishes more than the channel holds loses the oldest, as a slow subscriber of
                // containerd does.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    let stream = Mutex::new(Some(stream));
    let service = tower::service_fn(move |_: Request<SubscribeRequest>| {
        let stream = stream.lock().unwrap_or_else(PoisonError::into_inner).take();
        async move {
            stream
                .map(|stream| Response::new(Box::pin(stream)))
                .ok_or_else(|| Status::internal("one subscription per request"))
        }
    });
    Grpc::new(ProstCodec::<Envelope, SubscribeRequest>::default())
        .server_streaming(service, request)
        .await
}

/// containerd's introspection `Plugins`: the image service's neighbours, and its exports if `Answers::image_exports`.
async fn plugins(
    answers: Arc<Answers>,
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<containerd_client::tonic::body::Body> {
    let service = tower::service_fn(move |_: Request<PluginsRequest>| {
        let answers = Arc::clone(&answers);
        async move {
            if answers.plugins_unavailable {
                return Err(Status::unavailable("Unavailable"));
            }
            // The plugins that share a type or an id with the image service, which come first in containerd's list.
            let mut plugins = vec![
                Plugin {
                    r#type: "io.containerd.nri.v1".to_owned(),
                    id: "nri".to_owned(),
                    ..Plugin::default()
                },
                Plugin {
                    r#type: "io.containerd.cri.v1".to_owned(),
                    id: "runtime".to_owned(),
                    ..Plugin::default()
                },
                Plugin {
                    r#type: "io.containerd.service.v1".to_owned(),
                    id: "images".to_owned(),
                    ..Plugin::default()
                },
            ];
            if let Some((discard, path)) = &answers.image_exports {
                plugins.push(Plugin {
                    r#type: "io.containerd.cri.v1".to_owned(),
                    id: "images".to_owned(),
                    exports: [
                        ("DiscardUnpackedLayers".to_owned(), discard.to_string()),
                        ("RegistryConfigPath".to_owned(), path.clone()),
                    ]
                    .into(),
                    ..Plugin::default()
                });
            }
            Ok::<_, Status>(Response::new(PluginsResponse { plugins }))
        }
    });
    Grpc::new(ProstCodec::<PluginsResponse, PluginsRequest>::default())
        .unary(service, request)
        .await
}
