//! A fake containerd, for tests that run where there is no runtime (the CI runner, macOS): it answers the CRI's
//! `Version` and the introspection service's `Plugins` on a Unix socket, which is all preflight asks (D86).

use std::convert::Infallible;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use containerd_client::services::v1::{Plugin, PluginsRequest, PluginsResponse};
use containerd_client::tonic::codegen::http;
use containerd_client::tonic::server::Grpc;
use containerd_client::tonic::{Request, Response, Status};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tonic_prost::ProstCodec;

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
    /// The images of `ListImages`: ID, tags and digests.
    pub images: Vec<(String, Vec<String>, Vec<String>)>,
}

impl Answers {
    /// containerd at `version`, whose image service discards no layer and reads `/etc/containerd/certs.d`.
    #[must_use]
    pub fn containerd(version: &str) -> Self {
        Self {
            runtime_name: "containerd".to_owned(),
            runtime_version: version.to_owned(),
            image_exports: Some((false, "/etc/containerd/certs.d".to_owned())),
            images: Vec::new(),
        }
    }
}

/// A fake runtime listening on a socket until it is dropped.
#[derive(Debug)]
pub struct Fake {
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
        let listener = std::os::unix::net::UnixListener::bind(socket)?;
        listener.set_nonblocking(true)?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
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
                let answers = Arc::new(answers);
                tokio::select! {
                    () = accept(listener, answers) => {}
                    _ = stopped => {}
                }
            });
        });
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
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

async fn accept(listener: tokio::net::UnixListener, answers: Arc<Answers>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let answers = Arc::clone(&answers);
        tokio::spawn(async move {
            let service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
                let answers = Arc::clone(&answers);
                async move { Ok::<_, Infallible>(route(&answers, request).await) }
            });
            // A client that hangs up ends its own connection.
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn route(
    answers: &Arc<Answers>,
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<containerd_client::tonic::body::Body> {
    let answers = Arc::clone(answers);
    match request.uri().path() {
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
            let service = tower::service_fn(move |_: Request<PluginsRequest>| {
                let answers = Arc::clone(&answers);
                async move {
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
        other => Status::unimplemented(format!("the fake runtime has no {other}")).into_http(),
    }
}
