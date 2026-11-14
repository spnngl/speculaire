//! The agent process: loads the config, then serves until SIGTERM, reloading on SIGHUP and on file changes (D30).

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context as _;
use speculaire_mirror::Local;
use speculaire_mirror::cache::Cache;
use speculaire_mirror::fetch::{self, Fetcher, Holder};
use speculaire_mirror::peer::Uploads;
use speculaire_mirror::relay::{CriImages, Relay};
use speculaire_mirror::tls::Tls;
use speculaire_oci::reference::Digest;
use speculaire_pki::node::Credentials;
use speculaire_reflect::client::{self, Client, Holdings, LookupError, Lookups};
use speculaire_reflect::{Member, Reflector, Settings};
use speculaire_runtime::content::Content;
use speculaire_runtime::inventory::{Change, Inventory, Update};
use speculaire_runtime::registries::Registries;
use speculaire_runtime::watch::Watch;
use speculaire_runtime::{Fallback, Node as RuntimeNode};
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, Interval, MissedTickBehavior, interval};
use tracing::{debug, error, info, warn};

use crate::config::{self, Config, PeerAddress, Role};
use crate::identity::Identity;
use crate::log::{self, Logs};
use crate::node::Node;
use crate::status::{self, Status};
use crate::{systemd, telemetry};

/// Runs the agent with the config at `path`.
///
/// # Errors
///
/// When the config is invalid, which stops startup before any listener opens (D30), or a listener cannot open.
pub fn run(path: &Path) -> anyhow::Result<()> {
    // Stamped before the first read, so that a write during it is a change the first poll finds (D93).
    let watch = Watch::new(vec![path.to_owned()]);
    let config = config::load(path)?;
    let logs = log::install(&config.log, &config.audit)?;
    let node = Node::new(&config);
    let node = preflight(&node)?;
    tokio::runtime::Runtime::new()
        .context("starting the runtime")?
        .block_on(serve(path, watch, config, logs, node))
}

/// Refuses to start on a node where the agent would mirror or gate wrongly (D86), naming each file and key; returns the
/// node as the runtime it has runs on it.
fn preflight(node: &Node) -> anyhow::Result<RuntimeNode> {
    let runtime = node.runtime()?;
    let on = node.on(runtime);
    let problems = speculaire_configure::preflight(on.settings(), &node.target, SystemTime::now());
    if problems.is_empty() {
        info!(%runtime, "preflight passed");
        return Ok(on);
    }
    let lines: Vec<String> = problems
        .iter()
        .map(|problem| format!("  {problem}"))
        .collect();
    anyhow::bail!(
        "{} problem{} on this node keep{} the agent from starting ({runtime}):\n{}",
        problems.len(),
        if problems.len() == 1 { "" } else { "s" },
        if problems.len() == 1 { "s" } else { "" },
        lines.join("\n")
    )
}

async fn serve(
    path: &Path,
    mut watch: Watch,
    mut config: Config,
    logs: Logs,
    node: RuntimeNode,
) -> anyhow::Result<()> {
    // Before any listener opens and before READY=1: a signal's default action would end the agent, and a signal that
    // arrives during startup is handled once it is done.
    let mut hangup = signal(SignalKind::hangup()).context("handling SIGHUP")?;
    let mut terminate = signal(SignalKind::terminate()).context("handling SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("handling SIGINT")?;
    let metrics = telemetry::install()?;
    let role = *config.role.get();
    if role == Role::Reflector {
        speculaire_reflect::metrics::describe();
    }
    let status = Arc::new(Status::new(metrics.clone(), role == Role::Reflector));
    let configured = *config.metrics.address.get();
    let listener = tokio::net::TcpListener::bind(configured)
        .await
        .with_context(|| format!("listening on metrics.address {configured}"))?;
    // The bound address: port 0 in the config is the one the kernel picked.
    let address = listener
        .local_addr()
        .context("reading the status listener's address")?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(
        axum::serve(listener, status::router(Arc::clone(&status)))
            .with_graceful_shutdown(async {
                // An error means the sender is gone, which also means stop.
                let _ = stopped.await;
            })
            .into_future(),
    );
    tokio::spawn(async move {
        let mut upkeep = tokio::time::interval(telemetry::UPKEEP_PERIOD);
        loop {
            upkeep.tick().await;
            metrics.run_upkeep();
        }
    });
    info!(%address, "status listener open");
    // P2P waits for the identity; readiness does not (D16, D45).
    let mut identity = Identity::load(&config.identity);
    // `/readyz` answers 503 until the mirror listens (D45); an agent that cannot open it stops (D55).
    let registries = node.registries();
    reload_registries(&*registries);
    let mirror = start_mirror(&config, &node, Arc::clone(&registries)).await?;
    status.mirror_listening();
    let mut reflector = None;
    open_reflector(&config, &identity, &mut reflector, &status).await;
    let mut sharing = None;
    open_sharing(&config, &identity, &mirror, &node, &mut sharing);
    systemd::watchdog();
    systemd::ready();

    let mut period = config.config.poll_interval.get();
    let mut poll = polls(period);
    // D93: a poll reads a file again when it differs from its stamp, taken before the last read; SIGHUP always does.
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = hangup.recv() => {
                watch = watch.again();
                reload(path, &mut config, &logs);
                mirror.apply(&config);
                reload_registries(&*registries);
                identity.reload();
                open_reflector(&config, &identity, &mut reflector, &status).await;
                open_sharing(&config, &identity, &mirror, &node, &mut sharing);
            }
            _ = poll.tick() => {
                if watch.changed() {
                    watch = watch.again();
                    reload(path, &mut config, &logs);
                    mirror.apply(&config);
                }
                if registries.changed() {
                    reload_registries(&*registries);
                }
                identity.poll();
                open_reflector(&config, &identity, &mut reflector, &status).await;
                open_sharing(&config, &identity, &mirror, &node, &mut sharing);
            }
        }
        if config.config.poll_interval.get() != period {
            period = config.config.poll_interval.get();
            poll = polls(period);
        }
    }

    // D39, step 1.
    systemd::stopping();
    status.stop();
    info!("stopping");
    shut_down(&config, mirror, sharing, reflector).await;
    // An error means the server already ended; its result says why.
    let _ = stop.send(());
    server
        .await
        .context("the status listener panicked")?
        .context("serving the status listener")
}

/// D39, steps 2 to 4 for peers, and a stopping reflector closes the streams of its agents. The mirror's part of steps 2
/// and 4, and steps 5 and 6, arrive with the cache and the gate.
async fn shut_down(
    config: &Config,
    mirror: Mirror,
    sharing: Option<Sharing>,
    reflector: Option<Reflector>,
) {
    mirror.uploads.stop();
    let (client, peers) = sharing
        .map(|sharing| (sharing.client, sharing.peers))
        .unzip();
    if let Some(client) = client {
        client.stop().await;
    }
    if let Some(reflector) = reflector {
        reflector.stop().await;
    }
    let drain = config.shutdown.drain_timeout.get();
    if tokio::time::timeout(drain, mirror.uploads.drained())
        .await
        .is_err()
    {
        warn!(
            ?drain,
            "uploads to peers still in flight at shutdown.drain_timeout are cut"
        );
    }
    if let Some(peers) = peers {
        peers.stop().await;
    }
    mirror.stop().await;
}

/// Swaps in the config at `path`, or keeps `running` and counts the failure (D30).
fn reload(path: &Path, running: &mut Config, logs: &Logs) {
    match config::load(path) {
        Err(err) => {
            metrics::counter!(telemetry::CONFIG_RELOAD_FAILURES).increment(1);
            let err = anyhow::Error::from(err);
            error!(
                error = format_args!("{err:#}"),
                "config reload failed; the previous config stays in use"
            );
        }
        Ok(mut new) => {
            for key in new.keep_restart_keys(running) {
                warn!(
                    key,
                    "config reload: this key changes only on restart; the running value stays"
                );
            }
            logs.apply(&new.log, &new.audit);
            *running = new;
            debug!(path = %path.display(), "config reloaded");
        }
    }
}

/// Reads the registry config again (D91). A config that is not valid stays unread: the one held serves, and the failure
/// is logged and counted. A credential, certificate or key file that cannot be used does not fail the read: each is
/// logged, and the reload counts as one failure however many there are (D92).
fn reload_registries(registries: &dyn Registries) {
    match registries.reload() {
        Ok(reloaded) => {
            debug!("registry config reloaded");
            if !reloaded.problems.is_empty() {
                metrics::counter!(telemetry::CONFIG_RELOAD_FAILURES).increment(1);
            }
            for problem in &reloaded.problems {
                error!(
                    error = %problem,
                    "registry config reloaded with a file left out"
                );
            }
        }
        Err(err) => {
            metrics::counter!(telemetry::CONFIG_RELOAD_FAILURES).increment(1);
            error!(
                error = %err,
                "registry config reload failed; the previous registry config stays in use"
            );
        }
    }
}

/// The mirror, listening, and what stops it.
struct Mirror {
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
    /// The relay, where the node has one.
    relay: Option<Arc<Relay<CriImages>>>,
    /// The cap on the peer API's bodies, which it holds from startup so that a reload reaches it before it opens.
    uploads: Arc<Uploads>,
    /// What fetches from peers, linked to the reflectors once the agent shares.
    fetcher: Fetcher,
}

impl Mirror {
    /// Gives the mirror the live keys of `config`: a lowered `blob_cache.max_size` evicts at the next blob kept (D91),
    /// `peer.max_uploads` caps the next upload (D24), and `peer.stall_timeout` and `peer.deny_ttl` reach the next fetch.
    fn apply(&self, config: &Config) {
        if let Some(relay) = &self.relay {
            relay.cache().set_max_size(config.blob_cache.max_size.get());
        }
        self.uploads.set_limit(config.peer.max_uploads.get());
        self.fetcher.set(fetch_settings(config));
    }

    /// Opens the peer API on the address `fixed` gives, serving what [`Self::inventory`] announces.
    fn open_peers(
        &self,
        node: &RuntimeNode,
        fixed: impl Future<Output = Option<SocketAddr>> + Send + 'static,
        credentials: Arc<Credentials>,
    ) -> Peers {
        let uploads = Arc::clone(&self.uploads);
        match &self.relay {
            Some(relay) => Peers::open(Arc::clone(relay.cache()), fixed, credentials, uploads),
            None => Peers::open(Arc::new(node.content()), fixed, credentials, uploads),
        }
    }

    /// What the node serves to peers: the blob cache where the node relays (D67), else the runtime's content.
    fn inventory(&self, node: &RuntimeNode) -> Arc<dyn Inventory> {
        match &self.relay {
            Some(relay) => Arc::<Cache>::clone(relay.cache()),
            None => node.inventory(),
        }
    }

    async fn stop(self) {
        // An error means the mirror already ended.
        let _ = self.stop.send(());
        if let Err(err) = self.task.await {
            error!(error = %err, "the mirror panicked");
        }
    }
}

/// Opens the mirror on `mirror.address` with the certificates of `configure` (D14, D55). On containerd it serves what
/// the node holds; on CRI-O it relays pulls through the blob cache (D66, D67).
async fn start_mirror(
    config: &Config,
    node: &RuntimeNode,
    registries: Arc<dyn Registries>,
) -> anyhow::Result<Mirror> {
    let directory = config.mirror.directory.get().get();
    let tls = Tls::load(directory).with_context(|| {
        format!(
            "loading the mirror's certificates from {}: run `speculaire configure`",
            directory.display()
        )
    })?;
    let configured = config.mirror.address.get().get();
    let listener = tokio::net::TcpListener::bind(configured)
        .await
        .with_context(|| format!("listening on mirror.address {configured}"))?;
    let address = listener
        .local_addr()
        .context("reading the mirror's address")?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let stopped = async {
        // An error means the sender is gone, which also means stop.
        let _ = stopped.await;
    };
    let tls = Arc::new(tls);
    let uploads = Arc::new(Uploads::new(config.peer.max_uploads.get()));
    let blobs = config.blob_cache.directory.get().get();
    // On containerd, a blob from peers waits there until it is whole and checked (D102).
    let fetcher = Fetcher::new(blobs.join("staging"), fetch_settings(config));
    speculaire_mirror::metrics::describe_fetch();
    let (task, relay) = match node.fallback() {
        Fallback::PerBlob => (
            tokio::spawn(speculaire_mirror::serve(
                listener,
                tls,
                Arc::new(Local::new(node.content(), fetcher.clone())),
                stopped,
            )),
            None,
        ),
        Fallback::Relay => {
            let cache = Cache::open(blobs, config.blob_cache.max_size.get())
                .with_context(|| format!("opening the blob cache {}", blobs.display()))?;
            let relay = Arc::new(Relay::new(
                cache,
                fetcher.clone(),
                registries,
                CriImages::new(node.socket(), node.name()),
            ));
            speculaire_mirror::metrics::describe_relay();
            tokio::spawn({
                let relay = Arc::clone(&relay);
                async move { relay.evict_when_over().await }
            });
            let task = tokio::spawn(speculaire_mirror::serve(
                listener,
                tls,
                Arc::clone(&relay),
                stopped,
            ));
            (task, Some(relay))
        }
    };
    info!(%address, "mirror open");
    Ok(Mirror {
        stop,
        task,
        relay,
        uploads,
        fetcher,
    })
}

/// The fetcher's live keys in `config`.
fn fetch_settings(config: &Config) -> fetch::Settings {
    fetch::Settings {
        stall_timeout: config.peer.stall_timeout.get(),
        deny_ttl: config.peer.deny_ttl.get(),
    }
}

/// The holders of a digest, from the reflectors (D98).
struct Holders(Lookups);

impl fetch::Lookup for Holders {
    fn holders<'a>(
        &'a self,
        digest: &'a Digest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Vec<Holder>> + Send + 'a>> {
        Box::pin(async move {
            match self.0.lookup(digest).await {
                Ok(peers) => peers
                    .into_iter()
                    .map(|peer| Holder {
                        node: peer.node,
                        address: peer.address,
                    })
                    .collect(),
                // No reflector yet, or one that fails: the pull falls through (D66).
                Err(LookupError::NoMember) => Vec::new(),
                Err(LookupError::Call(status)) => {
                    debug!(%digest, error = %status, "a lookup failed: the pull falls through");
                    Vec::new()
                }
            }
        })
    }
}

/// The peer API, and what stops it.
struct Peers {
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Peers {
    /// Serves `content` to other nodes on the peer address once `fixed` gives it, with the node identity of
    /// `credentials` (D14, D16, D36); `fixed` gives `None` when the client stops first. An address that cannot be
    /// listened on is logged: peers fall through to other nodes.
    fn open<C: Content>(
        content: Arc<C>,
        fixed: impl Future<Output = Option<SocketAddr>> + Send + 'static,
        credentials: Arc<Credentials>,
        uploads: Arc<Uploads>,
    ) -> Self {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let mut stopped = std::pin::pin!(async {
                // An error means the sender is gone, which also means stop.
                let _ = stopped.await;
            });
            let address = tokio::select! {
                address = fixed => address,
                () = &mut stopped => None,
            };
            let Some(address) = address else {
                return;
            };
            let listener = match tokio::net::TcpListener::bind(address).await {
                Ok(listener) => listener,
                Err(err) => {
                    error!(%address, error = %err, "cannot listen on the peer address; this node serves no peers");
                    return;
                }
            };
            // The bound address: port 0 takes a port the kernel picks, as the tests do.
            let address = listener.local_addr().unwrap_or(address);
            info!(%address, "peer API open");
            speculaire_mirror::peer::serve(
                listener,
                credentials.server(),
                content,
                uploads,
                stopped,
            )
            .await;
        });
        Self { stop, task }
    }

    async fn stop(self) {
        // An error means the peer API already ended.
        let _ = self.stop.send(());
        if let Err(err) = self.task.await {
            error!(error = %err, "the peer API panicked");
        }
    }
}

/// Opens the reflector on `reflector.listen`, on a node whose role is reflector, once its identity allows peer links
/// (D2, D16); `/readyz` waits for it. A listener that cannot open is logged, and tried again at the next poll.
async fn open_reflector(
    config: &Config,
    identity: &Identity,
    reflector: &mut Option<Reflector>,
    status: &Status,
) {
    if *config.role.get() != Role::Reflector
        || reflector.is_some()
        || !identity.enabled(SystemTime::now())
    {
        return;
    }
    let address = *config.reflector.listen.get();
    let members = config
        .reflector
        .members
        .get()
        .iter()
        .map(|member| Member {
            node: member.node.as_str().to_owned(),
            address: member.address,
        })
        .collect();
    let opened = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => Reflector::spawn(listener, identity.credentials(), Settings::new(members)),
        Err(err) => Err(err),
    };
    match opened {
        Ok(opened) => {
            *reflector = Some(opened);
            status.reflector_listening();
        }
        Err(err) => error!(
            %address,
            error = %err,
            "cannot listen on reflector.listen; trying again at the next poll"
        ),
    }
}

/// Follows `inventory` into the holdings the agent announces (D99).
fn follow(inventory: Arc<dyn Inventory>) -> Arc<Holdings> {
    let holdings = Arc::new(Holdings::default());
    let (updates, mut received) = tokio::sync::mpsc::channel(64);
    tokio::spawn(inventory.follow(updates));
    tokio::spawn({
        let holdings = Arc::clone(&holdings);
        async move {
            while let Some(update) = received.recv().await {
                match update {
                    Update::Listing(digests) => holdings.replace(digests),
                    Update::Change(Change::Added(digest)) => holdings.add(digest),
                    Update::Change(Change::Removed(digest)) => holdings.remove(&digest),
                }
            }
        }
    });
    holdings
}

/// The agent's part in P2P: announcing what the node holds, and serving it.
struct Sharing {
    client: Client,
    peers: Peers,
}

/// Starts following `inventory` and announcing it to the reflectors of `reflector.url`, when one is set, once the
/// identity allows peer links, then serves it on the peer address the client fixes (D2, D16, D36, D99).
fn open_sharing(
    config: &Config,
    identity: &Identity,
    mirror: &Mirror,
    node: &RuntimeNode,
    sharing: &mut Option<Sharing>,
) {
    if sharing.is_some() || !identity.enabled(SystemTime::now()) {
        return;
    }
    if let Some(settings) = client_config(config) {
        let credentials = Arc::clone(identity.credentials());
        let client = Client::spawn(
            settings,
            Arc::clone(&credentials),
            follow(mirror.inventory(node)),
        );
        mirror.fetcher.link(
            Arc::new(Holders(client.lookups())),
            Arc::clone(&credentials),
        );
        let peers = mirror.open_peers(node, client.fixed_peer_address(), credentials);
        *sharing = Some(Sharing { client, peers });
    }
}

/// The client's settings: the host and port of `reflector.url`, and `peer.address` (D2, D56).
fn client_config(config: &Config) -> Option<client::Config> {
    let url = config.reflector.url.get().get()?;
    // `ReflectorUrl` holds an `https://` URL with a host; an IPv6 host comes in brackets.
    let host = url.host()?.trim_start_matches('[').trim_end_matches(']');
    Some(client::Config {
        host: host.to_owned(),
        port: url.port_u16().unwrap_or(443),
        peer: match config.peer.address.get() {
            PeerAddress::Auto => None,
            PeerAddress::Fixed(address) => Some(*address),
        },
    })
}

/// The config polls (D30): the first one period from now.
fn polls(period: Duration) -> Interval {
    // `interval` caps a period past the clock's range, and `reset` moves its immediate first tick a period away.
    let mut poll = interval(period);
    poll.reset();
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    poll
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use speculaire_runtime::registries::ContainerdRegistries;

    use super::*;

    #[test]
    fn a_poll_interval_past_the_clocks_range_starts_the_polls() {
        // humantime reads up to `u64::MAX` seconds; `Instant` holds fewer.
        let config = config::parse("[config]\npoll_interval = \"500000000000y\"\n").unwrap();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            polls(config.config.poll_interval.get());
        });
    }

    #[test]
    fn the_client_reads_the_host_and_port_of_the_url_and_the_peer_address() {
        let client = |text: &str| client_config(&config::parse(text).unwrap());
        assert!(client("").is_none());
        let found = client("[reflector]\nurl = \"https://reflector.example\"\n").unwrap();
        assert_eq!(
            (found.host.as_str(), found.port, found.peer),
            ("reflector.example", 443, None)
        );
        let found = client(
            "[reflector]\nurl = \"https://[fd00::1]:7483\"\n[peer]\naddress = \"10.0.0.1:9000\"\n",
        )
        .unwrap();
        assert_eq!(
            (found.host.as_str(), found.port, found.peer),
            ("fd00::1", 7483, Some("10.0.0.1:9000".parse().unwrap()))
        );
    }

    #[test]
    fn the_live_keys_of_a_config_reach_the_relays_cache_and_the_fetcher() {
        let dir = tempfile::tempdir().unwrap();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let fetcher = Fetcher::new(
                dir.path().join("staging"),
                fetch::Settings {
                    stall_timeout: Duration::from_secs(1),
                    deny_ttl: Duration::from_secs(1),
                },
            );
            let relay = Arc::new(Relay::new(
                Cache::open(dir.path(), 1 << 30).unwrap(),
                fetcher.clone(),
                Arc::new(ContainerdRegistries::new(dir.path().join("config.toml"))),
                CriImages::new(dir.path().join("crio.sock"), "cri-o"),
            ));
            let (stop, _stopped) = tokio::sync::oneshot::channel();
            let mirror = Mirror {
                stop,
                task: tokio::spawn(async {}),
                relay: Some(Arc::clone(&relay)),
                uploads: Arc::new(Uploads::new(NonZeroUsize::MIN)),
                fetcher,
            };
            let config = Config::default();
            assert_ne!(config.blob_cache.max_size.get(), 1 << 30);
            mirror.apply(&config);
            assert_eq!(relay.cache().max_size(), config.blob_cache.max_size.get());
            assert_eq!(mirror.uploads.limit(), config.peer.max_uploads.get().get());
            assert_eq!(mirror.fetcher.settings(), fetch_settings(&config));
        });
    }
}
