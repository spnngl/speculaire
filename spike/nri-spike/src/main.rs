//! Spike 01: external NRI plugin over our own multiplexer, ttrpc-rust over in-memory duplex streams.
//! Usage: nri-spike [socket] [plugin-name] [plugin-idx]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use ttrpc::asynchronous::{Client, Server, TtrpcContext};
use ttrpc::asynchronous::transport::{Listener, Socket};

mod snapshot;

mod api {
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}
use api::nri::pkg::api::v1alpha1 as nri;

const PLUGIN_CONN: u32 = 1;
const RUNTIME_CONN: u32 = 2;
/// Go's ttrpc reads through a 4096-byte bufio.Reader; a larger frame makes `conn.Read` return ENOMEM.
const MAX_FRAME: usize = 4096;
/// Event bit: 1 << (CREATE_CONTAINER - 1), api.proto:377.
const CREATE_CONTAINER_BIT: i32 = 1 << 3;

macro_rules! log {
    ($($t:tt)*) => { println!("nri-spike: {}", format!($($t)*)) };
}

/// Opens ConnID 1 and 2 on the trunk. The returned streams are what ttrpc reads and writes.
fn mux(trunk: UnixStream) -> (DuplexStream, DuplexStream) {
    let (mut trunk_r, mut trunk_w) = trunk.into_split();
    let (plugin_ttrpc, plugin_mux) = duplex(64 * 1024);
    let (runtime_ttrpc, runtime_mux) = duplex(64 * 1024);
    let (plugin_r, mut plugin_w) = split(plugin_mux);
    let (runtime_r, mut runtime_w) = split(runtime_mux);

    let (tx, mut rx) = mpsc::channel::<(u32, Vec<u8>)>(64);

    // Trunk writer: one frame = 4-byte BE ConnID + 4-byte BE length + payload.
    tokio::spawn(async move {
        while let Some((id, payload)) = rx.recv().await {
            let mut frame = Vec::with_capacity(8 + payload.len());
            frame.extend_from_slice(&id.to_be_bytes());
            frame.extend_from_slice(&u32::try_from(payload.len()).expect("frame at most 4096 bytes").to_be_bytes());
            frame.extend_from_slice(&payload);
            if trunk_w.write_all(&frame).await.is_err() {
                break;
            }
        }
    });

    for (id, mut r) in [(PLUGIN_CONN, plugin_r), (RUNTIME_CONN, runtime_r)] {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_FRAME];
            loop {
                match r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send((id, buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    // Trunk reader: demux by ConnID.
    tokio::spawn(async move {
        loop {
            let mut header = [0u8; 8];
            if trunk_r.read_exact(&mut header).await.is_err() {
                log!("trunk closed");
                std::process::exit(0);
            }
            let id = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
            let len = usize::try_from(u32::from_be_bytes([header[4], header[5], header[6], header[7]])).expect("u32 fits usize");
            let mut payload = vec![0u8; len];
            if trunk_r.read_exact(&mut payload).await.is_err() {
                std::process::exit(0);
            }
            let out = match id {
                PLUGIN_CONN => &mut plugin_w,
                RUNTIME_CONN => &mut runtime_w,
                other => {
                    log!("frame for unknown ConnID {other}, dropped");
                    continue;
                }
            };
            if out.write_all(&payload).await.is_err() {
                break;
            }
        }
    });

    (plugin_ttrpc, runtime_ttrpc)
}

struct Plugin {
    snap: Option<snapshot::Containerd>,
}

#[async_trait::async_trait]
impl nri::Plugin for Plugin {
    async fn configure(&self, _: &TtrpcContext, req: nri::ConfigureRequest) -> ttrpc::Result<nri::ConfigureResponse> {
        log!(
            "Configure runtime_name={} runtime_version={} NRI_version={} registration_timeout={}ms request_timeout={}ms config={:?}",
            req.runtime_name, req.runtime_version, req.nri_version, req.registration_timeout, req.request_timeout, req.config
        );
        Ok(nri::ConfigureResponse { events: CREATE_CONTAINER_BIT })
    }

    async fn synchronize(&self, _: &TtrpcContext, req: nri::SynchronizeRequest) -> ttrpc::Result<nri::SynchronizeResponse> {
        log!("Synchronize pods={} containers={} more={}", req.pods.len(), req.containers.len(), req.more);
        Ok(nri::SynchronizeResponse { update: vec![], more: false })
    }

    async fn create_container(&self, _: &TtrpcContext, req: nri::CreateContainerRequest) -> ttrpc::Result<nri::CreateContainerResponse> {
        let (pod, ctr) = (req.pod.unwrap_or_default(), req.container.unwrap_or_default());
        let image = ctr.image.as_ref().map(|i| format!("{} {}", i.name, i.digest)).unwrap_or_default();
        log!("CreateContainer pod={}/{} container={} image={:?} labels={:?} annotations={:?} container_labels={:?}", pod.namespace, pod.name, ctr.name, image, pod.labels, ctr.annotations, ctr.labels);
        if let Some(snap) = &self.snap {
            let name = ctr.annotations.get("io.kubernetes.cri.image-name").cloned().unwrap_or_default();
            match snap.check(&name, &ctr.id).await {
                Ok(o) => log!(
                    "SNAPSHOT pod={} id={} image={} target={} nri_image_digest={} chain={} parent={} grandparent={:?} match={} stat_us={} total_us={}",
                    pod.name, ctr.id, name, o.target, ctr.image.as_ref().map(|i| i.digest.as_str()).unwrap_or(""), o.chain_id, o.parent, o.grandparent,
                    o.parent == o.chain_id, o.stat.as_micros(), o.total.as_micros()
                ),
                Err(e) => log!("SNAPSHOT pod={} id={} error={e:#}", pod.name, ctr.id),
            }
        }
        if pod.labels.get("spike/reject").map(String::as_str) == Some("true") {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::FAILED_PRECONDITION,
                "speculaire spike: rejected",
            )));
        }
        Ok(nri::CreateContainerResponse::default())
    }

    async fn shutdown(&self, _: &TtrpcContext, _: nri::Empty) -> ttrpc::Result<nri::Empty> {
        log!("Shutdown");
        Ok(nri::Empty::default())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let sock = args.next().unwrap_or_else(|| "/var/run/nri/nri.sock".into());
    let name = args.next().unwrap_or_else(|| "speculaire".into());
    let idx = args.next().unwrap_or_else(|| "50".into());

    let snap = if std::env::var_os("SNAPSHOT").is_some() {
        Some(snapshot::Containerd::connect(std::path::Path::new("/run/containerd/containerd.sock")).await?)
    } else {
        None
    };

    let trunk = UnixStream::connect(&sock).await.with_context(|| format!("connect {sock}"))?;
    let (plugin_conn, runtime_conn) = mux(trunk);

    // Serve Plugin on ConnID 1: a one-shot listener, kept open by a pending stream.
    let listener = Listener::new(stream::once(async move { Ok::<_, std::io::Error>(plugin_conn) }).chain(stream::pending()));
    let mut server = Server::new().add_listener(listener).register_service(nri::create_plugin(Arc::new(Plugin { snap })));
    server.start().await.context("server start")?;

    // Call Runtime on ConnID 2.
    let client = nri::RuntimeClient::new(Client::new(Socket::new(runtime_conn)));
    let ctx = ttrpc::context::with_duration(Duration::from_secs(5));
    let start = std::time::Instant::now();
    client
        .register_plugin(ctx, &nri::RegisterPluginRequest { plugin_name: name.clone(), plugin_idx: idx.clone(), ..Default::default() })
        .await
        .context("RegisterPlugin")?;
    log!("registered as {name}-{idx} in {:?}", start.elapsed());

    tokio::signal::ctrl_c().await?;
    server.shutdown().await.ok();
    Ok(())
}
