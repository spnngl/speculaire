//! A blob pulled from a peer, again and again: the run `just profile peer` and `just valgrind` profile (D116).
//!
//! [`pull`] starts a reflector and two agents, each a process of its own on a fake containerd: the holder, which holds a
//! random blob and announces it, and the puller, which holds nothing. It asks the puller's mirror for the blob as
//! containerd does, a `GET` without `Range`, whose head the mirror sends once the holder answers, and whose body once it
//! has fetched the whole blob and checked it (D102, D205). The puller keeps nothing it fetched, so every pull goes to the
//! holder again. Each is timed to the answer's first byte, of its head, and to its last, on a connection of its own.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use aws_lc_rs::digest::{SHA256, digest};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use speculaire_pki::mirror::Part;
use speculaire_pki::testing::Cluster;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::node::{Agent, Node};

/// The node that holds the blob.
const HOLDER: &str = "peer-holder";
/// The node that pulls it.
const PULLER: &str = "peer-puller";
/// How long the reflector may take to hear from both agents.
const SETTLE: Duration = Duration::from_mins(2);
/// The seed of the blob's bytes.
const SEED: u64 = 108;

/// What [`pull`] does.
#[derive(Clone, Debug)]
pub struct Pulls {
    /// The blob's size, in bytes.
    pub size: usize,
    /// How many times it is pulled.
    pub count: usize,
    /// Each agent's command, before `agent --config <file>`: the `speculaire` binary, or a wrapper followed by it.
    pub agent: Vec<OsString>,
}

/// How long the pulls took.
#[derive(Clone, Debug)]
pub struct Timings {
    size: usize,
    /// To each answer's first byte.
    first_byte: Vec<Duration>,
    /// To each answer's last byte.
    last_byte: Vec<Duration>,
}

impl Timings {
    /// The timings as a Markdown table: their median, 90th percentile and maximum.
    #[must_use]
    pub fn markdown(&self) -> String {
        let mut markdown = format!(
            "{} pulls of a {} MiB blob, from a peer, through the mirror.\n\n\
             | Time to | p50 | p90 | max |\n|---|---|---|---|\n",
            self.first_byte.len(),
            self.size >> 20,
        );
        for (measure, times) in [
            ("first byte", &self.first_byte),
            ("last byte", &self.last_byte),
        ] {
            let mut sorted = times.clone();
            sorted.sort_unstable();
            let at = |percentile: usize| {
                let time = sorted
                    .get(sorted.len().saturating_sub(1) * percentile / 100)
                    .copied()
                    .unwrap_or_default();
                format!("{:.1} ms", time.as_secs_f64() * 1e3)
            };
            let _ = writeln!(
                markdown,
                "| {measure} | {} | {} | {} |",
                at(50),
                at(90),
                at(100)
            );
        }
        markdown
    }
}

/// Pulls a random blob of `settings.size` bytes `settings.count` times from the holder through the puller's mirror,
/// and times each pull.
///
/// # Errors
///
/// When an agent does not start, does not exit with success, or the mirror answers anything but the blob.
pub async fn pull(settings: &Pulls) -> anyhow::Result<Timings> {
    let cluster = Cluster::new("speculaire-peer");
    let mut blob = vec![0; settings.size];
    fastrand::Rng::with_seed(SEED).fill(&mut blob);
    let hex = sha256(&blob);
    let digest = format!("sha256:{hex}");
    let reflector = Node::new(&cluster)?;
    let holder = Node::agent(&cluster, HOLDER, vec![digest.clone()], &reflector)?;
    let puller = Node::agent(&cluster, PULLER, Vec::new(), &reflector)?;
    let blobs = holder.content().join("blobs/sha256");
    std::fs::create_dir_all(&blobs)?;
    std::fs::write(blobs.join(&hex), &blob)?;
    drop(blob);

    let agents = [
        Agent::start(&settings.agent, &reflector).await?,
        Agent::start(&settings.agent, &holder).await?,
        Agent::start(&settings.agent, &puller).await?,
    ];
    agents[0]
        .settled(2, 1, SETTLE)
        .await?
        .context("the reflector never heard from both agents")?;
    tracing::info!(count = settings.count, size = settings.size, "pulling");
    let mirror = Mirror::new(&puller, agents[2].mirror)?;
    let mut timings = Timings {
        size: settings.size,
        first_byte: Vec::with_capacity(settings.count),
        last_byte: Vec::with_capacity(settings.count),
    };
    for _ in 0..settings.count {
        let (first, last) = mirror.pull(&digest, settings.size).await?;
        timings.first_byte.push(first);
        timings.last_byte.push(last);
    }
    // The puller first, so that no fetch is in flight when the holder goes.
    for agent in agents.into_iter().rev() {
        agent.stop().await?;
    }
    Ok(timings)
}

/// The SHA-256 of `bytes`, in hexadecimal.
fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// The puller's mirror, as containerd reaches it: TLS with the client certificate of the mirror's directory (D14).
struct Mirror {
    connector: TlsConnector,
    address: SocketAddr,
}

impl Mirror {
    /// The mirror at `address` of `node`'s agent.
    fn new(node: &Node, address: SocketAddr) -> anyhow::Result<Self> {
        let read = |part: Part| std::fs::read(node.path().join("mirror").join(part.file_name()));
        let mut roots = RootCertStore::empty();
        for der in CertificateDer::pem_slice_iter(&read(Part::Ca)?) {
            roots.add(der?)?;
        }
        let client = read(Part::Client)?;
        let chain = CertificateDer::pem_slice_iter(&client).collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_slice(&client)?;
        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            address,
        })
    }

    /// Pulls the blob `digest` of `size` bytes, and checks it: how long to the answer's first byte, and to its last.
    async fn pull(&self, digest: &str, size: usize) -> anyhow::Result<(Duration, Duration)> {
        let start = Instant::now();
        let tcp = TcpStream::connect(self.address).await?;
        let mut tls = self
            .connector
            .connect(ServerName::IpAddress(self.address.ip().into()), tcp)
            .await?;
        tls.write_all(
            format!(
                "GET /v2/library/peer/blobs/{digest}?ns=docker.io HTTP/1.1\r\nHost: {}\r\n\r\n",
                self.address
            )
            .as_bytes(),
        )
        .await?;
        let mut raw = Vec::with_capacity(size + 1024);
        let mut first_byte = None;
        let head = loop {
            if tls.read_buf(&mut raw).await? == 0 {
                bail!("the mirror closed the connection within the head");
            }
            first_byte.get_or_insert_with(|| start.elapsed());
            if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let status = std::str::from_utf8(&raw[..head])?;
        ensure!(
            status.starts_with("HTTP/1.1 200 "),
            "the mirror answered {}",
            status.lines().next().unwrap_or_default()
        );
        while raw.len() < head + size {
            if tls.read_buf(&mut raw).await? == 0 {
                bail!("the mirror closed the connection within the body");
            }
        }
        let last_byte = start.elapsed();
        ensure!(
            raw.len() == head + size
                && Some(sha256(&raw[head..]).as_str()) == digest.strip_prefix("sha256:"),
            "the mirror sent something other than the blob"
        );
        Ok((first_byte.unwrap_or_default(), last_byte))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_timings_are_a_table_of_percentiles() {
        let ms = Duration::from_millis;
        let timings = Timings {
            size: 64 << 20,
            first_byte: (1..=10).rev().map(ms).collect(),
            last_byte: (11..=20).map(ms).collect(),
        };
        let markdown = timings.markdown();
        assert!(
            markdown.starts_with("10 pulls of a 64 MiB blob"),
            "{markdown}"
        );
        assert!(
            markdown.contains("| first byte | 5.0 ms | 9.0 ms | 10.0 ms |"),
            "{markdown}"
        );
        assert!(
            markdown.contains("| last byte | 15.0 ms | 19.0 ms | 20.0 ms |"),
            "{markdown}"
        );
    }

    #[test]
    fn a_digest_is_the_lowercase_hex_of_sha256() {
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
