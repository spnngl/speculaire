//! The inventory of containerd against a fake of its content and events services.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use containerd_client::events::{ContentCreate, ContentDelete};
use containerd_client::services::v1::{
    Info, ListContentRequest, ListContentResponse, SubscribeRequest,
};
use containerd_client::tonic::server::Grpc;
use containerd_client::tonic::{Request, Response, Status};
use containerd_client::types::Envelope;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use speculaire_oci::reference::Digest;
use tokio::sync::{broadcast, mpsc, watch};
use tonic_prost::ProstCodec;

use super::{Containerd, change};
use crate::containerd::NAMESPACE;
use crate::inventory::{Change, Update};
use crate::paths::Paths;

fn digest(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
}

fn envelope(namespace: &str, topic: &str, event: &impl prost::Name) -> Envelope {
    Envelope {
        timestamp: None,
        namespace: namespace.to_owned(),
        topic: topic.to_owned(),
        event: Some(containerd_client::to_any(event)),
    }
}

fn created(namespace: &str, digest: &str) -> Envelope {
    let event = ContentCreate {
        digest: digest.to_owned(),
        ..ContentCreate::default()
    };
    envelope(namespace, "/content/create", &event)
}

fn deleted(namespace: &str, digest: &str) -> Envelope {
    let event = ContentDelete {
        digest: digest.to_owned(),
    };
    envelope(namespace, "/content/delete", &event)
}

/// A fake containerd: content per namespace, and events to whoever subscribed.
struct Fake {
    content: Mutex<HashMap<String, HashSet<String>>>,
    events: broadcast::Sender<Envelope>,
    /// Each change of it ends every subscription.
    cut: watch::Sender<u64>,
    filters: Mutex<Vec<String>>,
}

impl Fake {
    fn start(socket: &Path) -> Arc<Self> {
        let fake = Arc::new(Self {
            content: Mutex::new(HashMap::new()),
            events: broadcast::channel(64).0,
            cut: watch::channel(0).0,
            filters: Mutex::new(Vec::new()),
        });
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        let served = Arc::clone(&fake);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let fake = Arc::clone(&served);
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let fake = Arc::clone(&fake);
                        async move { Ok::<_, Infallible>(fake.serve(request).await) }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        fake
    }

    /// Puts `digest` in `namespace`, and publishes it when `publish`.
    fn put(&self, namespace: &str, digest: &Digest, publish: bool) {
        self.content
            .lock()
            .unwrap()
            .entry(namespace.to_owned())
            .or_default()
            .insert(digest.to_string());
        if publish {
            let _ = self.events.send(created(namespace, &digest.to_string()));
        }
    }

    /// Deletes `digest` from `namespace`, and publishes it when `publish`, as an explicit delete does.
    fn delete(&self, namespace: &str, digest: &Digest, publish: bool) {
        if let Some(held) = self.content.lock().unwrap().get_mut(namespace) {
            held.remove(&digest.to_string());
        }
        if publish {
            let _ = self.events.send(deleted(namespace, &digest.to_string()));
        }
    }

    /// Waits until `count` subscriptions are live.
    async fn subscribed(&self, count: usize) {
        while self.events.receiver_count() != count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn serve(
        self: Arc<Self>,
        request: hyper::Request<hyper::body::Incoming>,
    ) -> hyper::Response<containerd_client::tonic::body::Body> {
        if request.uri().path() == "/containerd.services.content.v1.Content/List" {
            let fake = Arc::clone(&self);
            let svc = tower::service_fn(move |request: Request<ListContentRequest>| {
                let fake = Arc::clone(&fake);
                async move {
                    let namespace = request
                        .metadata()
                        .get("containerd-namespace")
                        .ok_or_else(|| Status::invalid_argument("no namespace"))?
                        .to_str()
                        .unwrap()
                        .to_owned();
                    let held = fake
                        .content
                        .lock()
                        .unwrap()
                        .get(&namespace)
                        .cloned()
                        .unwrap_or_default();
                    // One digest per message, as a service that sends many does; one is not a digest.
                    let messages: Vec<Result<ListContentResponse, Status>> = held
                        .into_iter()
                        .chain(["not a digest".to_owned()])
                        .map(|digest| {
                            Ok(ListContentResponse {
                                info: vec![Info {
                                    digest,
                                    ..Info::default()
                                }],
                            })
                        })
                        .collect();
                    Ok(Response::new(futures_util::stream::iter(messages)))
                }
            });
            let mut grpc =
                Grpc::new(ProstCodec::<ListContentResponse, ListContentRequest>::default());
            grpc.server_streaming(svc, request).await
        } else {
            let fake = Arc::clone(&self);
            let svc = tower::service_fn(move |request: Request<SubscribeRequest>| {
                let fake = Arc::clone(&fake);
                async move {
                    fake.filters
                        .lock()
                        .unwrap()
                        .clone_from(&request.into_inner().filters);
                    let events = fake.events.subscribe();
                    let mut cut = fake.cut.subscribe();
                    cut.mark_unchanged();
                    let stream = futures_util::stream::unfold(
                        (events, cut),
                        |(mut events, mut cut)| async move {
                            tokio::select! {
                                event = events.recv() => {
                                    event.ok().map(|event| (Ok::<_, Status>(event), (events, cut)))
                                }
                                _ = cut.changed() => None,
                            }
                        },
                    );
                    Ok(Response::new(Box::pin(stream)))
                }
            });
            let mut grpc = Grpc::new(ProstCodec::<Envelope, SubscribeRequest>::default());
            grpc.server_streaming(svc, request).await
        }
    }
}

fn containerd(root: &Path, socket: &Path) -> Arc<Containerd> {
    Arc::new(Containerd::new(Paths::under(root), socket, None))
}

async fn next(updates: &mut mpsc::Receiver<Update>) -> Update {
    tokio::time::timeout(Duration::from_secs(5), updates.recv())
        .await
        .unwrap()
        .unwrap()
}

fn listing(digests: &[&Digest]) -> Update {
    Update::Listing(digests.iter().map(|d| (*d).clone()).collect())
}

#[tokio::test]
async fn after_the_event_stream_drops_the_content_is_listed_again_and_nothing_is_missed() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let fake = Fake::start(&socket);
    let (a, b, c, d) = (digest(1), digest(2), digest(3), digest(4));
    fake.put(NAMESPACE, &a, false);
    fake.put("default", &digest(9), false);
    let (sender, mut updates) = mpsc::channel(16);
    let containerd = containerd(dir.path(), &socket);
    let following = tokio::spawn(async move {
        containerd
            .follow_every(&sender, Duration::from_secs(3600))
            .await;
    });
    assert_eq!(next(&mut updates).await, listing(&[&a]));
    fake.subscribed(1).await;
    assert_eq!(
        *fake.filters.lock().unwrap(),
        [
            r#"namespace=="k8s.io",topic=="/content/create""#,
            r#"namespace=="k8s.io",topic=="/content/delete""#
        ]
    );
    // Another namespace is never followed.
    fake.put("default", &digest(8), true);
    fake.put(NAMESPACE, &b, true);
    assert_eq!(
        next(&mut updates).await,
        Update::Change(Change::Added(b.clone()))
    );
    fake.delete(NAMESPACE, &b, true);
    assert_eq!(
        next(&mut updates).await,
        Update::Change(Change::Removed(b.clone()))
    );
    // While the stream is down, content comes and goes unseen: the next listing has it all.
    fake.cut.send_modify(|n| *n += 1);
    fake.put(NAMESPACE, &c, false);
    fake.delete(NAMESPACE, &a, false);
    assert_eq!(next(&mut updates).await, listing(&[&c]));
    fake.subscribed(1).await;
    fake.put(NAMESPACE, &d, true);
    assert_eq!(next(&mut updates).await, Update::Change(Change::Added(d)));
    // Nobody reads the updates any more: following stops.
    drop(updates);
    tokio::time::timeout(Duration::from_secs(5), following)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn content_the_garbage_collector_deleted_leaves_at_the_next_listing_and_a_late_containerd_is_waited_for()
 {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let (sender, mut updates) = mpsc::channel(16);
    let containerd = containerd(dir.path(), &socket);
    let following = tokio::spawn(async move {
        containerd
            .follow_every(&sender, Duration::from_millis(100))
            .await;
    });
    // No containerd yet: it is waited for.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let fake = Fake::start(&socket);
    let a = digest(1);
    fake.put(NAMESPACE, &a, false);
    assert_eq!(next(&mut updates).await, listing(&[&a]));
    fake.delete(NAMESPACE, &a, false);
    assert_eq!(next(&mut updates).await, listing(&[]));
    following.abort();
}

#[test]
fn an_event_is_a_change_only_for_content_of_the_namespace_with_a_digest() {
    let a = digest(1);
    let text = a.to_string();
    assert_eq!(
        change(&created(NAMESPACE, &text)),
        Some(Change::Added(a.clone()))
    );
    assert_eq!(change(&deleted(NAMESPACE, &text)), Some(Change::Removed(a)));
    assert_eq!(change(&created("default", &text)), None);
    assert_eq!(change(&created(NAMESPACE, "sha256:short")), None);
    let mut other = created(NAMESPACE, &text);
    other.topic = "/images/create".to_owned();
    assert_eq!(change(&other), None);
    let mut garbled = created(NAMESPACE, &text);
    if let Some(event) = garbled.event.as_mut() {
        event.value = vec![0xff];
    }
    assert_eq!(change(&garbled), None);
    garbled.event = None;
    assert_eq!(change(&garbled), None);
}
