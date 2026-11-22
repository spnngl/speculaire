//! The agent process: loads the config, then serves until SIGTERM, reloading on SIGHUP and on file changes (D30).

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context as _;
use speculaire_artifacts::follow::Fetching;
use speculaire_artifacts::{Discovery, Limits, Store};
use speculaire_mirror::cache::Cache;
use speculaire_mirror::fetch::{self, Fetcher, Holder};
use speculaire_mirror::listed::Listed;
use speculaire_mirror::peer::Uploads;
use speculaire_mirror::relay::Relay;
use speculaire_mirror::tls::Tls;
use speculaire_mirror::{Fetched, Local};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_pki::node::Credentials;
use speculaire_reflect::client::{self, Client, Holdings, LookupError, Lookups, Source};
use speculaire_reflect::prewarm::{Plan, Resolve};
use speculaire_reflect::{Member, Reflector, Settings};
use speculaire_runtime::content::Content;
use speculaire_runtime::inventory::{Change, Inventory, Update};
use speculaire_runtime::registries::{self, Registries, Reloaded};
use speculaire_runtime::watch::Watch;
use speculaire_runtime::{Fallback, Node as RuntimeNode, images};
use speculaire_verify::{Engine, Policies, Running, Signatures};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{Duration, Interval, MissedTickBehavior, interval};
use tracing::{debug, error, info, warn};

use crate::cache::{Caches, Saver};
use crate::config::{self, Config, PeerAddress, Role};
use crate::followed::Followed;
use crate::gate::Gate;
use crate::gate::decision::Verifier;
use crate::gate::decision::running::SYNCHRONIZE_WAIT;
use crate::identity::Identity;
use crate::log::{self, Logs};
use crate::node::Node;
use crate::prewarm::Resolver;
use crate::status::{self, Status};
use crate::{listen, systemd, telemetry, trust};

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
    let policy = Followed::read("the policy file", config.verify.policy.get(), read_policy)?;
    let trust = trust::Source::read(&config.verify)?;
    let node = Node::new(&config);
    let node = preflight(&node, config.gate.wait.get())?;
    tokio::runtime::Runtime::new()
        .context("starting the runtime")?
        .block_on(serve(path, watch, config, logs, node, policy, trust))
}

/// Reads the policy file, refusing to start on one that does not parse (D30); a missing file is no policy (D142).
fn read_policy(path: &Path) -> anyhow::Result<Arc<Policies>> {
    let policies = Policies::load(path)?;
    info!(path = %path.display(), count = policies.iter().count(), "policy read");
    Ok(Arc::new(policies))
}

/// Refuses to start on a node where the agent would mirror or gate wrongly (D86), naming each file and key; returns the
/// node as the runtime it has runs on it. `wait` is `gate.wait`, checked against the runtime's NRI request timeout
/// (D41, D64).
fn preflight(node: &Node, wait: Duration) -> anyhow::Result<RuntimeNode> {
    let runtime = node.runtime()?;
    let on = node.on(runtime);
    let problems =
        speculaire_configure::preflight(on.settings(), &node.target, wait, SystemTime::now());
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

#[expect(
    clippy::too_many_lines,
    reason = "the startup, step by step in order, then the loop"
)]
async fn serve(
    path: &Path,
    mut watch: Watch,
    mut config: Config,
    logs: Logs,
    node: RuntimeNode,
    mut policy: Followed<Arc<Policies>>,
    trust: trust::Source,
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
    let listener = listen::listen(configured)
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
    // Held while the agent serves; TUF refreshes it (D143), and a pinned file is read again as it changes (D30).
    let mut trust = trust.hold();
    // P2P waits for the identity; readiness does not (D16, D45).
    let mut identity = Identity::load(&config.identity);
    // `/readyz` answers 503 until the mirror listens and the artifact store is open (D45, D121); an agent that cannot
    // open either stops (D55).
    let registries = node.registries();
    report_registries(registries.reload());
    let (mirror, fetched) = start_mirror(&config, &node, Arc::clone(&registries)).await?;
    // Discovery waits for a reflector stream, so that it asks peers before upstream, and asks a root again soon when it
    // failed just after one came up (D126, D134). Without `reflector.url` the sender drops: discovery waits for none.
    let (up, last_up) = tokio::sync::watch::channel(None);
    let up = client_config(&config).map(|_| up);
    let (store, verifier, saver) = start_discovery(
        &config,
        &node,
        (&mirror, fetched),
        Arc::clone(&registries),
        last_up,
        (policy.subscribe(), trust.subscribe()),
    )?;
    status.mirror_listening();
    // The gate registers once the verdicts are loaded; `/readyz` waits for it (D41, D45).
    let gate = Gate::start(
        config.nri.socket.get().get().to_owned(),
        node.runtime(),
        (node.identity(), mirror.listed.clone()),
        verifier.clone(),
        &config.gate,
        Arc::clone(&status),
    );
    // The reflector resolves `prewarm.images` as the node pulls, its own mirror left out (D17, D185).
    let resolver: Arc<dyn Resolve> = Arc::new(Resolver::new(
        Arc::clone(&registries),
        config.mirror.address.get().get().to_string(),
    ));
    let (plan, plans) = tokio::sync::watch::channel(config.prewarm.plan());
    let mut reflector = None;
    open_reflector(
        &config,
        &identity,
        (&resolver, &plans),
        &mut reflector,
        &status,
    )
    .await;
    let mut sharing = None;
    open_sharing(
        &config,
        &identity,
        &mirror,
        &node,
        &store,
        up.as_ref(),
        &mut sharing,
    );
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
                report_registries(registries.reload());
                identity.reload();
                policy.reload(config.verify.policy.get());
                trust.reload();
                open_reflector(&config, &identity, (&resolver, &plans), &mut reflector, &status).await;
                open_sharing(&config, &identity, &mirror, &node, &store, up.as_ref(), &mut sharing);
            }
            _ = poll.tick() => {
                if let Some(now) = watch.changed() {
                    watch = now;
                    reload(path, &mut config, &logs);
                    mirror.apply(&config);
                }
                if let Some(reloaded) = registries.poll() {
                    report_registries(reloaded);
                }
                identity.poll();
                policy.poll(config.verify.policy.get());
                trust.poll();
                open_reflector(&config, &identity, (&resolver, &plans), &mut reflector, &status).await;
                open_sharing(&config, &identity, &mirror, &node, &store, up.as_ref(), &mut sharing);
            }
        }
        verifier
            .verdicts
            .set_stale_max(config.verify.stale_max.get());
        gate.set(&config.gate);
        // The waves take an unchanged plan as a no-op.
        plan.send_replace(config.prewarm.plan());
        if config.config.poll_interval.get() != period {
            period = config.config.poll_interval.get();
            poll = polls(period);
        }
    }

    // D39, step 1.
    systemd::stopping();
    status.stop();
    info!("stopping");
    // The runtime's followers end as the teardown cuts them, without a warning.
    node.stop();
    // D39, step 6 after steps 2 to 5.
    gate.stop_after(async {
        shut_down(&config, mirror, sharing, reflector).await;
        // D39, step 5.
        saver.stop().await;
    })
    .await;
    // An error means the server already ended; its result says why.
    let _ = stop.send(());
    server
        .await
        .context("the status listener panicked")?
        .context("serving the status listener")
}

/// D39, steps 2 to 4: the peer API answers 503 and the mirror 404 from now on, and both drain; a stopping reflector
/// closes the streams of its agents.
async fn shut_down(
    config: &Config,
    mirror: Mirror,
    sharing: Option<Sharing>,
    reflector: Option<Reflector>,
) {
    mirror.uploads.stop();
    let mirror = mirror.stop();
    let (client, peers) = sharing
        .map(|sharing| (sharing.client, sharing.peers))
        .unzip();
    if let Some(client) = client {
        client.stop().await;
    }
    if let Some(reflector) = reflector {
        reflector.stop().await;
    }
    // The connections open on both send what is in flight, then close (D39 step 4, D103); a listener closes once its
    // connections have, or with the process when they are cut (D177).
    let peers = async {
        if let Some(peers) = peers {
            peers.stop().await;
        }
    };
    let drain = config.shutdown.drain_timeout.get();
    let transfers = async { tokio::join!(peers, mirror) };
    if tokio::time::timeout(drain, transfers).await.is_err() {
        warn!(
            ?drain,
            "transfers still in flight at shutdown.drain_timeout are cut"
        );
    }
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

/// Reports a read of the registry config (D91). A config that is not valid stays unread: the one held serves, and the
/// failure is logged and counted. A credential, certificate or key file that cannot be used does not fail the read: each
/// is logged, and the reload counts as one failure however many there are (D92).
fn report_registries(reloaded: Result<Reloaded, registries::Error>) {
    match reloaded {
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
    relay: Option<Arc<Relay>>,
    /// The cap on the peer API's bodies, which it holds from startup so that a reload reaches it before it opens.
    uploads: Arc<Uploads>,
    /// What fetches from peers, linked to the reflectors once the agent shares.
    fetcher: Fetcher,
    /// The images the runtime lists, whose tags the agent announces and the peer API resolves (D123).
    listed: Listed,
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

    /// Opens the peer API on the address `fixed` gives, serving what [`Self::inventory`] and `store` announce.
    fn open_peers(
        &self,
        node: &RuntimeNode,
        store: Arc<Store>,
        fixed: impl Future<Output = Option<SocketAddr>> + Send + 'static,
        credentials: Arc<Credentials>,
    ) -> Peers {
        let uploads = Arc::clone(&self.uploads);
        let listed = self.listed.clone();
        match &self.relay {
            Some(relay) => Peers::open(
                Arc::clone(relay.cache()),
                listed,
                store,
                fixed,
                credentials,
                uploads,
            ),
            None => Peers::open(
                Arc::new(node.content()),
                listed,
                store,
                fixed,
                credentials,
                uploads,
            ),
        }
    }

    /// What the node serves to peers: the blob cache where the node relays (D67), else the runtime's content.
    fn inventory(&self, node: &RuntimeNode) -> Arc<dyn Inventory> {
        match &self.relay {
            Some(relay) => Arc::<Cache>::clone(relay.cache()),
            None => node.inventory(),
        }
    }

    /// The manifests the node holds, for discovery: the blob cache where the node relays, else the runtime's content.
    fn manifests(&self, node: &RuntimeNode) -> Arc<dyn speculaire_artifacts::Local> {
        match &self.relay {
            Some(relay) => Arc::<Cache>::clone(relay.cache()),
            None => Arc::new(node.content()),
        }
    }

    /// Answers every request 404 from now on (D39 step 2); the future returned ends once the connections open have
    /// closed (step 4).
    fn stop(self) -> impl Future<Output = ()> {
        // An error means the mirror already ended.
        let _ = self.stop.send(());
        let task = self.task;
        async move {
            if let Err(err) = task.await {
                error!(error = %err, "the mirror panicked");
            }
        }
    }
}

/// Opens the mirror on `mirror.address` with the certificates of `configure` (D14, D55). On containerd it serves what
/// the node holds; on CRI-O it relays pulls through the blob cache (D66, D67). The receiver hears of each manifest it
/// is asked for (D152).
async fn start_mirror(
    config: &Config,
    node: &RuntimeNode,
    registries: Arc<dyn Registries>,
) -> anyhow::Result<(Mirror, UnboundedReceiver<Fetched>)> {
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
    let (tell, asked) = tokio::sync::mpsc::unbounded_channel();
    let (task, relay, listed) = match node.fallback() {
        Fallback::PerBlob => (
            tokio::spawn(speculaire_mirror::serve(
                listener,
                tls,
                Arc::new(Local::new(node.content(), fetcher.clone())),
                tell,
                stopped,
            )),
            None,
            Listed::follow(node.images()),
        ),
        Fallback::Relay => {
            let cache = Cache::open(blobs, config.blob_cache.max_size.get())
                .with_context(|| format!("opening the blob cache {}", blobs.display()))?;
            let relay = Arc::new(Relay::new(
                cache,
                fetcher.clone(),
                registries,
                node.images(),
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
                tell,
                stopped,
            ));
            let listed = relay.listed().clone();
            (task, Some(relay), listed)
        }
    };
    info!(%address, "mirror open");
    Ok((
        Mirror {
            stop,
            task,
            relay,
            uploads,
            fetcher,
            listed,
        },
        asked,
    ))
}

/// How long discovery waits at startup for `last_up` to say a reflector stream is up, before it starts without peers.
const LINK_WAIT: Duration = Duration::from_secs(10);

/// Opens the artifact store and discovers the artifacts of each image the runtime lists, from the store, then peers
/// through the mirror's fetcher, then upstream (D121, D126); the store is what the node serves of them (D124).
///
/// Discovery starts once `last_up` holds the time a reflector stream came up, or its sender drops, or after
/// [`LINK_WAIT`]: a root it found unreachable waits [`speculaire_artifacts::discover::RETRY`], so its first pass asks
/// peers when the node has any. A manifest `fetched` through the mirror starts a discovery too, and the store keeps
/// what it names for `artifacts.grace` unless it is listed (D152, D153). The store is collected from the first listing
/// on (D131).
///
/// The verdict engine verifies each root against the policies and the trust root `held` holds as its discovery ends,
/// and paces the discoveries of the roots it waits on (D151); it verifies again as they change (D21). The gate reads its
/// verdicts, and asks for the roots no list named yet, through the [`Verifier`] returned (D22).
fn start_discovery(
    config: &Config,
    node: &RuntimeNode,
    (mirror, fetched): (&Mirror, UnboundedReceiver<Fetched>),
    registries: Arc<dyn Registries>,
    last_up: tokio::sync::watch::Receiver<Option<tokio::time::Instant>>,
    (policies, trust): (
        tokio::sync::watch::Receiver<Arc<Policies>>,
        tokio::sync::watch::Receiver<trust::Held>,
    ),
) -> anyhow::Result<(Arc<Store>, Verifier, Saver)> {
    let directory = config.artifacts.directory.get().get();
    let store = Store::open(directory)
        .with_context(|| format!("opening the artifact store {}", directory.display()))?;
    speculaire_artifacts::metrics::describe();
    let store = Arc::new(store);
    let discovery = Arc::new(Discovery::new(
        Arc::clone(&store),
        mirror.manifests(node),
        mirror.fetcher.clone(),
        registries,
        config.mirror.address.get().get().to_string(),
        Host::current(),
        Limits::new(config.sbom.max_size.get()),
    ));
    speculaire_verify::metrics::describe();
    let signatures = Signatures::new(config.sbom.max_size.get());
    let engine = Engine::new(
        Arc::clone(&discovery),
        policies.clone(),
        signatures,
        trust.clone(),
        running(node.socket().to_owned()),
    );
    let verifier = Verifier {
        verdicts: Arc::clone(engine.verdicts()),
        policies,
        trust,
        asker: engine.asker(),
        synchronized: Arc::default(),
    };
    verifier
        .verdicts
        .set_stale_max(config.verify.stale_max.get());
    // Before the engine runs, as a load replaces the verdicts it keeps, and before the gate registers (D31).
    let caches = Caches {
        path: config.verify.cache.get().get().to_owned(),
        verdicts: Arc::clone(engine.verdicts()),
        signatures: Arc::clone(engine.signatures()),
        policies: verifier.policies.clone(),
        trust: verifier.trust.clone(),
    };
    caches.load();
    let saver = caches.save();
    let (found, told) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(engine.run(told));
    let follow = speculaire_artifacts::follow(
        discovery,
        node.images(),
        Fetching {
            fetched,
            grace: config.artifacts.grace.get().get(),
        },
        linked_or_after(last_up.clone(), LINK_WAIT),
        last_up,
        found,
    );
    // The running containers' roots are verified first, under `synchronize`: the list waits for the gate to ask for
    // them (D175).
    let synchronized = Arc::clone(&verifier.synchronized);
    tokio::spawn(async move {
        drop(tokio::time::timeout(SYNCHRONIZE_WAIT, synchronized.notified()).await);
        follow.await;
    });
    Ok((store, verifier, saver))
}

/// The roots the runtime's running containers run, asked over the CRI at `socket` (D21): none when it does not answer.
fn running(socket: PathBuf) -> Running {
    Box::new(move || {
        let socket = socket.clone();
        Box::pin(async move {
            images::running_roots(&socket).await.unwrap_or_else(|e| {
                warn!(error = %e, "the running containers are unknown: verifying again in no set order");
                HashSet::new()
            })
        })
    })
}

/// Resolves once `last_up` holds a time, or its sender drops, or after `wait`.
async fn linked_or_after(
    mut last_up: tokio::sync::watch::Receiver<Option<tokio::time::Instant>>,
    wait: Duration,
) {
    if tokio::time::timeout(wait, last_up.wait_for(Option::is_some))
        .await
        .is_err()
    {
        info!("no reflector stream after {wait:?}: discovery starts without peers");
    }
}

/// The fetcher's live keys in `config`.
pub(crate) fn fetch_settings(config: &Config) -> fetch::Settings {
    fetch::Settings {
        stall_timeout: config.peer.stall_timeout.get(),
        deny_ttl: config.peer.deny_ttl.get(),
        resolve_tags: config.mirror.resolve_tags,
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
    /// Serves `content`, the tags `listed` and the artifacts of `store` to other nodes on the peer address once `fixed`
    /// gives it, with the node identity of `credentials` (D14, D16, D36, D124); `fixed` gives `None` when the client
    /// stops first. An address that cannot be listened on is logged: peers fall through to other nodes.
    fn open<C: Content>(
        content: Arc<C>,
        listed: Listed,
        store: Arc<Store>,
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
                listed,
                store,
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
    (resolver, plans): (&Arc<dyn Resolve>, &tokio::sync::watch::Receiver<Plan>),
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
    let opened = match listen::listen(address).await {
        Ok(listener) => Reflector::spawn(listener, identity.credentials(), Settings::new(members)),
        Err(err) => Err(err),
    };
    match opened {
        Ok(mut opened) => {
            opened.prewarm(Arc::clone(resolver), plans.clone());
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

/// Follows `inventory`, the artifact `store` and the tags `listed` into the holdings the agent announces (D99, D123,
/// D124).
fn follow(inventory: Arc<dyn Inventory>, store: Arc<Store>, listed: Listed) -> Arc<Holdings> {
    let holdings = Arc::new(Holdings::default());
    follow_inventory(&holdings, Source::Content, inventory);
    follow_inventory(&holdings, Source::Artifacts, store);
    tokio::spawn({
        let holdings = Arc::clone(&holdings);
        listed.tag_keys(move |keys| holdings.replace(Source::Tags, &keys))
    });
    holdings
}

/// Follows `inventory` into the keys of `source` in `holdings`.
fn follow_inventory(holdings: &Arc<Holdings>, source: Source, inventory: Arc<dyn Inventory>) {
    let (updates, mut received) = tokio::sync::mpsc::channel(64);
    tokio::spawn(inventory.follow(updates));
    tokio::spawn({
        let holdings = Arc::clone(holdings);
        async move {
            while let Some(update) = received.recv().await {
                match update {
                    Update::Listing(digests) => holdings.replace(source, &digests),
                    Update::Change(Change::Added(digest)) => holdings.add(source, &digest),
                    Update::Change(Change::Removed(digest)) => holdings.remove(source, &digest),
                }
            }
        }
    });
}

/// The agent's part in P2P: announcing what the node holds, and serving it.
struct Sharing {
    client: Client,
    peers: Peers,
}

/// Starts following what the node holds and announcing it to the reflectors of `reflector.url`, when one is set, once
/// the identity allows peer links, then serves it on the peer address the client fixes (D2, D16, D36, D99, D124).
fn open_sharing(
    config: &Config,
    identity: &Identity,
    mirror: &Mirror,
    node: &RuntimeNode,
    store: &Arc<Store>,
    up: Option<&tokio::sync::watch::Sender<Option<tokio::time::Instant>>>,
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
            follow(
                mirror.inventory(node),
                Arc::clone(store),
                mirror.listed.clone(),
            ),
            // The agent takes no pushes yet: a closed channel drops them.
            tokio::sync::mpsc::channel(1).0,
        );
        mirror.fetcher.link(
            Arc::new(Holders(client.lookups())),
            Arc::clone(&credentials),
        );
        if let Some(up) = up {
            let mut last_up = client.last_up();
            // A stream may already be up.
            last_up.mark_changed();
            let up = up.clone();
            tokio::spawn(async move {
                // An error means the client is gone: no stream comes up again.
                while last_up.changed().await.is_ok() {
                    up.send_replace(*last_up.borrow_and_update());
                }
            });
        }
        let peers = mirror.open_peers(
            node,
            Arc::clone(store),
            client.fixed_peer_address(),
            credentials,
        );
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

    #[tokio::test]
    async fn discovery_starts_once_a_stream_is_up_or_after_the_wait() {
        let (up, receiver) = tokio::sync::watch::channel(None);
        let start = std::time::Instant::now();
        linked_or_after(receiver.clone(), Duration::from_millis(50)).await;
        assert!(start.elapsed() >= Duration::from_millis(50));
        up.send_replace(Some(tokio::time::Instant::now()));
        let start = std::time::Instant::now();
        linked_or_after(receiver, Duration::from_secs(60)).await;
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_poll_interval_past_the_clocks_range_starts_the_polls() {
        // A duration reads up to `i64::MAX` seconds (D138); `Instant` holds fewer.
        let config = config::parse("[config]\npoll_interval = 9223372036854775807\n").unwrap();
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
                    resolve_tags: false,
                },
            );
            let relay = Arc::new(Relay::new(
                Cache::open(dir.path(), 1 << 30).unwrap(),
                fetcher.clone(),
                Arc::new(ContainerdRegistries::new(dir.path().join("config.toml"))),
                Arc::new(speculaire_runtime::crio::CriO::new(
                    speculaire_runtime::paths::Paths::under(dir.path()),
                    dir.path().join("crio.sock"),
                    "systemctl",
                )),
            ));
            let (stop, _stopped) = tokio::sync::oneshot::channel();
            let mirror = Mirror {
                stop,
                task: tokio::spawn(async {}),
                relay: Some(Arc::clone(&relay)),
                uploads: Arc::new(Uploads::new(NonZeroUsize::MIN)),
                fetcher,
                listed: relay.listed().clone(),
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
