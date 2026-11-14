//! Fetching a digest the node lacks from the peers that announced it (D7, D24, D52, D73, D102).
//!
//! A lookup names the holders. The fetcher asks the first, and one more at each hedge delay, up to [`WIDTH`] at once;
//! a peer that fails, answers 503 or 404 gives its turn to the next at once. The first good head wins and the others
//! are dropped. A body that breaks off, or is silent for `peer.stall_timeout`, resumes from the next peer with `Range`.
//! Each connection requires the certificate of the node the lookup named (D16). Content whose digest does not match
//! denies, for `peer.deny_ttl`, every peer that sent part of it (D52).
//!
//! The hedge after a lookup's answer follows Spegel v0.8.0 (`pkg/registry/registry.go:132`): delays at the 80th, 85th
//! and 90th percentiles of the time peers took to answer, with 50 ms as the floor.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, HOST, RANGE};
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use speculaire_oci::reference::Digest;
use speculaire_pki::node::Credentials;
use speculaire_runtime::content::Blob;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::hash::Hash;
use crate::metrics::{self, Fetched};
use crate::request::Kind;

/// The target of audit events, which the agent's logs send to the audit log alone (D37).
pub const AUDIT_TARGET: &str = "speculaire::audit";

/// The most peers asked at once for one head.
pub const WIDTH: usize = 4;
/// The shortest hedge delay.
pub const HEDGE_FLOOR: Duration = Duration::from_millis(50);
/// The percentiles of the peers' answer times that the hedges wait for, one hedge each.
const HEDGE_PERCENTILES: [usize; WIDTH - 1] = [80, 85, 90];
/// How many answer times the hedge delays are drawn from.
const SAMPLES: usize = 256;
/// How many times a fetch starts over after a digest mismatch, each time without the peers it denied.
const ROUNDS: usize = 3;

/// An agent that announced a digest: its node name, which its certificate must carry, and its peer address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    /// The node name.
    pub node: String,
    /// The peer API's address.
    pub address: SocketAddr,
}

/// Who holds a digest.
pub trait Lookup: Send + Sync + 'static {
    /// The holders of `digest`, best first; none when the reflectors do not answer.
    fn holders<'a>(
        &'a self,
        digest: &'a Digest,
    ) -> Pin<Box<dyn Future<Output = Vec<Holder>> + Send + 'a>>;
}

/// The live keys the fetcher follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// `peer.stall_timeout`: the longest silence of a peer, head or body (D73).
    pub stall_timeout: Duration,
    /// `peer.deny_ttl`: how long a peer that sent a wrong digest is skipped (D52).
    pub deny_ttl: Duration,
}

/// Fetches from peers; a handle, cheap to clone.
#[derive(Clone)]
pub struct Fetcher(Arc<Shared>);

struct Shared {
    /// Where a blob is written while it is checked, as an unnamed file.
    staging: PathBuf,
    settings: Mutex<Settings>,
    /// The lookup and the node identity, once P2P starts; until then nothing is fetched.
    link: OnceLock<Link>,
    /// Each denied node, until when.
    denied: Mutex<HashMap<String, Instant>>,
    /// The last answer times.
    times: Mutex<VecDeque<Duration>>,
}

struct Link {
    lookup: Arc<dyn Lookup>,
    credentials: Arc<Credentials>,
}

impl Fetcher {
    /// A fetcher that stages blobs in `staging` and fetches nothing until [`Fetcher::link`].
    #[must_use]
    pub fn new(staging: PathBuf, settings: Settings) -> Self {
        Self(Arc::new(Shared {
            staging,
            settings: Mutex::new(settings),
            link: OnceLock::new(),
            denied: Mutex::default(),
            times: Mutex::default(),
        }))
    }

    /// Takes up the live keys of a reloaded config for the next fetch.
    pub fn set(&self, settings: Settings) {
        *lock(&self.0.settings) = settings;
    }

    /// The live keys the next fetch follows.
    #[must_use]
    pub fn settings(&self) -> Settings {
        *lock(&self.0.settings)
    }

    /// Starts fetching: holders come from `lookup`, and connections present the identity of `credentials`. A second
    /// link is ignored.
    pub fn link(&self, lookup: Arc<dyn Lookup>, credentials: Arc<Credentials>) {
        // Only the first link counts: P2P starts once.
        let _ = self.0.link.set(Link {
            lookup,
            credentials,
        });
    }

    /// `digest` whole, from peers, staged in an unnamed file and checked against its digest before anything is served.
    /// `None` when no peer has it, or none sent it right.
    pub async fn whole(&self, kind: Kind, digest: &Digest) -> Option<Blob> {
        for _ in 0..ROUNDS {
            let mut download = self.download(kind, digest).await?;
            let mut hash = Hash::new(digest)?;
            let staged = self.stage(&mut download, &mut hash).await?;
            if hash.matches() {
                download.finish(true);
                return Some(staged);
            }
            download.finish(false);
        }
        None
    }

    /// The body of a blob from peers, as it arrives, or `None` when no peer answers. The caller hashes it and ends it
    /// with [`Download::finish`].
    pub async fn download(&self, kind: Kind, digest: &Digest) -> Option<Download> {
        let link = self.0.link.get()?;
        let mut waiting: VecDeque<Holder> = link
            .lookup
            .holders(digest)
            .await
            .into_iter()
            .filter(|holder| self.0.allowed(&holder.node))
            .collect();
        if waiting.is_empty() {
            return None;
        }
        let credentials = Arc::clone(&link.credentials);
        let (holder, body, size) =
            race(&self.0, &credentials, &mut waiting, kind, digest, 0, None).await?;
        Some(Download {
            shared: Arc::clone(&self.0),
            credentials,
            kind,
            digest: digest.clone(),
            waiting,
            current: Some(Current {
                holder,
                body,
                contributed: false,
            }),
            size,
            received: 0,
            contributors: Vec::new(),
        })
    }

    /// The whole of `download`, a blob or a manifest, in an unnamed file of the staging directory, hashed into `hash`.
    async fn stage(&self, download: &mut Download, hash: &mut Hash) -> Option<Blob> {
        let staging = self.0.staging.clone();
        let file = tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&staging)?;
            tempfile::tempfile_in(&staging)
        })
        .await
        .map_err(std::io::Error::other)
        .and_then(|opened| opened)
        .map_err(|err| warn!(error = %err, directory = %self.0.staging.display(), "cannot stage a blob from peers: it is pulled from upstream"))
        .ok()?;
        let mut file = tokio::fs::File::from_std(file);
        while let Some(chunk) = download.next().await? {
            hash.update(&chunk);
            if let Err(err) = file.write_all(&chunk).await {
                warn!(error = %err, "cannot stage a blob from peers: it is pulled from upstream");
                return None;
            }
        }
        if let Err(err) = file.flush().await {
            warn!(error = %err, "cannot stage a blob from peers: it is pulled from upstream");
            return None;
        }
        Some(Blob::from_open(file.into_std().await, download.size))
    }
}

impl Shared {
    fn stall(&self) -> Duration {
        lock(&self.settings).stall_timeout
    }

    /// Whether `node` is not denied now.
    fn allowed(&self, node: &str) -> bool {
        let mut denied = lock(&self.denied);
        let now = Instant::now();
        denied.retain(|_, until| *until > now);
        !denied.contains_key(node)
    }

    /// Denies each of `holders` for `peer.deny_ttl`, logging each, and auditing each when the audit is on (D37, D52).
    fn deny(&self, holders: &[Holder], digest: &Digest) {
        let ttl = lock(&self.settings).deny_ttl;
        let until = end_of_denial(ttl);
        let mut denied = lock(&self.denied);
        for holder in holders {
            denied.insert(holder.node.clone(), Instant::now() + ttl);
            warn!(node = %holder.node, peer = %holder.address, %digest, %until, "a peer sent content that is not its digest: it is skipped until then (D52)");
            info!(target: AUDIT_TARGET, event = "peer", node = %holder.node, peer = %holder.address, %digest, %until);
        }
    }

    /// Notes how long a peer took to answer.
    fn answered(&self, took: Duration) {
        let mut times = lock(&self.times);
        if times.len() == SAMPLES {
            times.pop_front();
        }
        times.push_back(took);
    }

    /// When to start each hedge, from the first request.
    fn hedge_delays(&self) -> [Duration; WIDTH - 1] {
        let mut times: Vec<Duration> = lock(&self.times).iter().copied().collect();
        times.sort_unstable();
        HEDGE_PERCENTILES.map(|percentile| {
            let at = times.len().saturating_sub(1) * percentile / 100;
            times.get(at).copied().unwrap_or_default().max(HEDGE_FLOOR)
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A body coming from peers, resumed from the next peer when one fails.
pub struct Download {
    shared: Arc<Shared>,
    credentials: Arc<Credentials>,
    kind: Kind,
    digest: Digest,
    /// Holders not asked yet.
    waiting: VecDeque<Holder>,
    /// The peer the body is coming from, until it fails.
    current: Option<Current>,
    size: u64,
    received: u64,
    /// Every peer that sent part of the body.
    contributors: Vec<Holder>,
}

struct Current {
    holder: Holder,
    body: Incoming,
    contributed: bool,
}

impl Download {
    /// The size the first peer gave.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The next part of the body, or `None` at its end. `None` inside the `Option`'s place is never returned early:
    /// a body that ends short resumes from the next peer.
    ///
    /// # Errors
    ///
    /// When no peer is left to resume from, which the `None` of the outer `Option` says.
    pub async fn next(&mut self) -> Option<Option<Bytes>> {
        loop {
            if self.received == self.size {
                return Some(None);
            }
            let Some(current) = &mut self.current else {
                let (holder, body, _) = race(
                    &self.shared,
                    &self.credentials,
                    &mut self.waiting,
                    self.kind,
                    &self.digest,
                    self.received,
                    Some(self.size),
                )
                .await?;
                self.current = Some(Current {
                    holder,
                    body,
                    contributed: false,
                });
                continue;
            };
            let failed = match timeout(self.shared.stall(), current.body.frame()).await {
                Err(_) => Fetched::Timeout,
                Ok(Some(Ok(frame))) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if data.is_empty() {
                        continue;
                    }
                    let length = data.len() as u64;
                    if self
                        .received
                        .checked_add(length)
                        .is_some_and(|end| end <= self.size)
                    {
                        if !current.contributed {
                            current.contributed = true;
                            self.contributors.push(current.holder.clone());
                        }
                        self.received += length;
                        return Some(Some(data));
                    }
                    // Longer than its head said: the peer is broken.
                    Fetched::Error
                }
                Ok(Some(Err(_)) | None) => Fetched::Error,
            };
            debug!(node = %current.holder.node, received = self.received, result = failed.label(), "a peer's body failed: resuming from the next");
            metrics::fetched(failed);
            self.current = None;
        }
    }

    /// Ends the download once its whole body was hashed: a body that `matched` its digest counts `ok`; one that did not
    /// counts `digest_mismatch` and denies every peer that sent part of it (D52).
    pub fn finish(self, matched: bool) {
        if matched {
            metrics::fetched(Fetched::Ok);
        } else {
            metrics::fetched(Fetched::DigestMismatch);
            self.shared.deny(&self.contributors, &self.digest);
        }
    }
}

/// A request in flight: the holder asked, and its answer.
type Asking = Pin<Box<dyn Future<Output = (Holder, Result<(Incoming, u64), Fetched>)> + Send>>;

/// The first good head of `digest` from `offset` among `waiting`, hedged; `size`, when known, is what it must say.
/// Holders that failed leave `waiting`; those still asked when another won go back to its end.
async fn race(
    shared: &Shared,
    credentials: &Arc<Credentials>,
    waiting: &mut VecDeque<Holder>,
    kind: Kind,
    digest: &Digest,
    offset: u64,
    size: Option<u64>,
) -> Option<(Holder, Incoming, u64)> {
    let stall = shared.stall();
    let start = Instant::now();
    let mut hedges = shared.hedge_delays().into_iter().map(|delay| start + delay);
    let mut next_hedge = hedges.next();
    let mut asking = FuturesUnordered::<Asking>::new();
    let mut asked: Vec<Holder> = Vec::new();
    let mut ask_next = |asking: &mut FuturesUnordered<Asking>, asked: &mut Vec<Holder>| {
        let Some(holder) = waiting.pop_front() else {
            return false;
        };
        asked.push(holder.clone());
        let config = credentials.client(&holder.node);
        let path = path(kind, digest);
        asking.push(Box::pin(async move {
            let answer = match timeout(stall, ask(&holder, config, &path, offset)).await {
                Ok(answer) => answer,
                Err(_) => Err(Fetched::Timeout),
            };
            (holder, answer)
        }));
        true
    };
    ask_next(&mut asking, &mut asked);
    let won = loop {
        // Holders that fail are replaced one for one, so the start and the hedges keep at most `WIDTH` asked.
        tokio::select! {
            answered = asking.next() => {
                let Some((holder, answer)) = answered else {
                    break None;
                };
                asked.retain(|other| *other != holder);
                match answer {
                    Ok((body, said)) if size.is_none_or(|size| size == said) => {
                        shared.answered(start.elapsed());
                        break Some((holder, body, said));
                    }
                    Ok(_) => {
                        debug!(node = %holder.node, "a peer gave another size than the first");
                        metrics::fetched(Fetched::Error);
                    }
                    Err(failed) => {
                        debug!(node = %holder.node, result = failed.label(), "a peer did not give the content");
                        metrics::fetched(failed);
                    }
                }
                if !ask_next(&mut asking, &mut asked) && asking.is_empty() {
                    break None;
                }
            }
            () = sleep_until(next_hedge) => {
                next_hedge = hedges.next();
                if ask_next(&mut asking, &mut asked) {
                    metrics::hedged();
                }
            }
        }
    };
    waiting.extend(asked);
    won
}

/// When a denial for `ttl` from now ends, as the warning and the audit event print it.
fn end_of_denial(ttl: Duration) -> humantime::Rfc3339Timestamp {
    humantime::format_rfc3339_seconds(SystemTime::now() + ttl)
}

/// Waits until `deadline`, or forever without one.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// The path of `digest` on the peer API, which does not read the name (D100).
fn path(kind: Kind, digest: &Digest) -> String {
    let route = match kind {
        Kind::Manifest => "manifests",
        _ => "blobs",
    };
    format!("/v2/speculaire/{route}/{digest}")
}

/// The body of `path` from `offset`, from `holder` alone, and the content's size.
async fn ask(
    holder: &Holder,
    mut config: rustls::ClientConfig,
    path: &str,
    offset: u64,
) -> Result<(Incoming, u64), Fetched> {
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = TcpStream::connect(holder.address)
        .await
        .map_err(|err| failed(holder, &err))?;
    tcp.set_nodelay(true).map_err(|err| failed(holder, &err))?;
    // The server name is not checked: the node name is (D16).
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::IpAddress(holder.address.ip().into()), tcp)
        .await
        .map_err(|err| failed(holder, &err))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|err| failed(holder, &err))?;
    tokio::spawn(connection);
    let mut request = Request::get(path).header(HOST, holder.address.to_string());
    if offset > 0 {
        request = request.header(RANGE, format!("bytes={offset}-"));
    }
    let request = request
        .body(Empty::<Bytes>::new())
        .map_err(|err| failed(holder, &err))?;
    // A refused certificate arrives as an alert on the first read, here (TLS 1.3).
    let response = sender
        .send_request(request)
        .await
        .map_err(|err| failed(holder, &err))?;
    let size = read_head(response.status(), response.headers(), offset)?;
    Ok((response.into_body(), size))
}

fn failed(holder: &Holder, err: &dyn std::fmt::Display) -> Fetched {
    debug!(node = %holder.node, peer = %holder.address, error = %err, "a peer cannot be asked");
    Fetched::Error
}

/// The size of the content a peer's head announces for a body from `offset`: a `200` with its `Content-Length` from
/// the start, else a `206` whose `Content-Range` runs from `offset` to the end. A `503` is `busy` (D24); anything else,
/// a `404` included, is an `error`.
///
/// # Errors
///
/// When the head is not one that gives the content asked for.
pub fn read_head(status: StatusCode, headers: &HeaderMap, offset: u64) -> Result<u64, Fetched> {
    let number = |text: &str| {
        // `u64::from_str` takes a leading `+`, which HTTP does not.
        (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse::<u64>().ok())
            .flatten()
    };
    let header = |name| headers.get(name).and_then(|value| value.to_str().ok());
    let length = header(CONTENT_LENGTH)
        .and_then(number)
        .ok_or(Fetched::Error);
    match status {
        StatusCode::SERVICE_UNAVAILABLE => Err(Fetched::Busy),
        StatusCode::OK if offset == 0 => length,
        StatusCode::PARTIAL_CONTENT if offset > 0 => {
            let (span, size) = header(CONTENT_RANGE)
                .and_then(|range| range.strip_prefix("bytes "))
                .and_then(|range| range.split_once('/'))
                .ok_or(Fetched::Error)?;
            let (first, last) = span.split_once('-').ok_or(Fetched::Error)?;
            let (first, last, size) = (number(first), number(last), number(size));
            match (first, last, size, length?) {
                (Some(first), Some(last), Some(size), length)
                    if first == offset
                        && last.checked_add(1) == Some(size)
                        && size - first == length =>
                {
                    Ok(size)
                }
                _ => Err(Fetched::Error),
            }
        }
        _ => Err(Fetched::Error),
    }
}

#[cfg(test)]
pub(crate) mod tests;
