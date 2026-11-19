//! The verdict engine: one verdict per key for each root listed, from the artifacts discovery keeps (D20, D151).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use speculaire_artifacts::discover::{Error, Reason};
use speculaire_artifacts::follow::{Found, Roots};
use speculaire_artifacts::{Artifact, Discovery, Store};
use speculaire_oci::reference::{Digest, Reference};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};
use tracing::{info, warn};

use crate::policy::Sbom;
use crate::signature::Signatures;
use crate::trust::{Absent, Held, RootHash, TrustRoot};
use crate::{MatchHash, Policies, Policy, metrics};

/// The target of the audit events (D37).
const AUDIT_TARGET: &str = "speculaire::audit";
/// The first wait before an unverifiable key is verified again; each next wait doubles it (D151).
pub const RETRY_FIRST: Duration = Duration::from_secs(10);
/// The longest wait before an unverifiable key is verified again (D20).
pub const RETRY_MAX: Duration = Duration::from_mins(5);

/// What verification concluded for a key (D20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every policy matched passes.
    Allow,
    /// A policy fails on the artifacts found, with upstream asked once more (D126): final for the key.
    Rejected {
        /// Why the first policy failing fails, as its first authority or its SBOM check says.
        reason: Arc<str>,
    },
    /// Verification could not conclude, and runs again at `retry_at`.
    Unverifiable {
        /// Why.
        reason: Arc<str>,
        /// When verification runs again.
        retry_at: Instant,
    },
    /// Not verified yet.
    Pending,
}

impl Verdict {
    /// The verdict's state, as the metrics label it.
    #[must_use]
    pub fn state(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Rejected { .. } => "rejected",
            Self::Unverifiable { .. } => "unverifiable",
            Self::Pending => "pending",
        }
    }

    /// Whether `self` and `other` tell the same result, whenever they retry.
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Rejected { reason: a }, Self::Rejected { reason: b })
            | (Self::Unverifiable { reason: a, .. }, Self::Unverifiable { reason: b, .. }) => {
                a == b
            }
            _ => self.state() == other.state(),
        }
    }

    fn reason(&self) -> &str {
        match self {
            Self::Rejected { reason } | Self::Unverifiable { reason, .. } => reason,
            Self::Allow | Self::Pending => "",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow | Self::Pending => f.write_str(self.state()),
            Self::Rejected { reason } | Self::Unverifiable { reason, .. } => {
                write!(f, "{}: {reason}", self.state())
            }
        }
    }
}

/// What a verdict is kept under (D20), borrowed so that the gate looks one up without allocating (D107).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key<'a> {
    /// The image identity: the manifest digest the image was listed with.
    pub image: &'a Digest,
    /// The hash of the policies the image's names match.
    pub policies: MatchHash,
    /// The trust root's hash, none when no trust root is held (D143).
    pub root: Option<RootHash>,
}

/// A verdict looked up: the one kept for the key, or, while the key is re-verified after a policy or trust-root change,
/// the one kept before it, marked stale (D21). A pending verdict is never stale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    /// The verdict.
    pub verdict: Verdict,
    /// Whether it is the verdict of the key before the change.
    pub stale: bool,
}

impl Lookup {
    const PENDING: Self = Self {
        verdict: Verdict::Pending,
        stale: false,
    };
}

/// A verdict kept, under the rest of its key.
#[derive(Clone, Debug)]
struct Kept {
    policies: MatchHash,
    root: Option<RootHash>,
    verdict: Verdict,
    /// When the change came that left `verdict` stale (D21).
    stale_since: Option<Instant>,
}

/// The verdicts kept, in memory (D151), by image identity.
#[derive(Debug, Default)]
pub struct Verdicts {
    kept: RwLock<HashMap<Digest, Vec<Kept>>>,
    /// `verify.stale_max`, in nanoseconds: none until [`Self::set_stale_max`].
    stale_max: AtomicU64,
}

impl Verdicts {
    /// Sets how long a stale verdict answers after the change that left it stale, `verify.stale_max` (D21).
    pub fn set_stale_max(&self, stale_max: Duration) {
        let nanos = u64::try_from(stale_max.as_nanos()).unwrap_or(u64::MAX);
        self.stale_max.store(nanos, Ordering::Relaxed);
    }

    /// The verdict kept for `key`, stale while it is re-verified; [`Verdict::Pending`] when none is, or when it has
    /// been stale longer than `verify.stale_max` (D21).
    #[must_use]
    pub fn get(&self, key: Key<'_>) -> Lookup {
        let kept = self.kept.read().unwrap_or_else(PoisonError::into_inner);
        let Some(kept) = kept.get(key.image).and_then(|kept| {
            kept.iter()
                .find(|kept| kept.policies == key.policies && kept.root == key.root)
        }) else {
            return Lookup::PENDING;
        };
        match kept.stale_since {
            None => Lookup {
                verdict: kept.verdict.clone(),
                stale: false,
            },
            Some(since) => {
                let stale_max = Duration::from_nanos(self.stale_max.load(Ordering::Relaxed));
                if since.elapsed() < stale_max {
                    Lookup {
                        verdict: kept.verdict.clone(),
                        stale: true,
                    }
                } else {
                    Lookup::PENDING
                }
            }
        }
    }

    /// Keeps `verdict` for `key`, in place of one kept under an earlier trust root or a stale one, and returns the
    /// verdict kept before, unless a rejection is kept already: it is final (D20).
    pub fn keep(&self, key: Key<'_>, verdict: Verdict) -> Option<Verdict> {
        let mut kept = self.kept.write().unwrap_or_else(PoisonError::into_inner);
        let image = kept.entry(key.image.clone()).or_default();
        match image.iter_mut().find(|kept| kept.policies == key.policies) {
            Some(Kept {
                verdict: Verdict::Rejected { .. },
                root,
                stale_since: None,
                ..
            }) if *root == key.root => None,
            Some(kept) => {
                kept.root = key.root;
                kept.stale_since = None;
                Some(std::mem::replace(&mut kept.verdict, verdict))
            }
            None => {
                image.push(Kept {
                    policies: key.policies,
                    root: key.root,
                    verdict,
                    stale_since: None,
                });
                Some(Verdict::Pending)
            }
        }
    }

    /// Keeps for `image` a verdict under `root` and each hash of `keys`, and drops the others: one kept under both
    /// stays; any other is the one kept under the hash paired with it, stale since `since` unless it was already, or
    /// pending (D21).
    fn rekey(
        &self,
        image: &Digest,
        root: Option<RootHash>,
        keys: &[(MatchHash, Option<MatchHash>)],
        since: Instant,
    ) {
        let mut kept = self.kept.write().unwrap_or_else(PoisonError::into_inner);
        let before = kept.remove(image).unwrap_or_default();
        let after: Vec<Kept> = keys
            .iter()
            .map(|&(policies, previous)| {
                if let Some(same) = before
                    .iter()
                    .find(|kept| kept.policies == policies && kept.root == root)
                {
                    return same.clone();
                }
                let previous = previous
                    .and_then(|previous| before.iter().find(|kept| kept.policies == previous))
                    .filter(|kept| kept.verdict != Verdict::Pending);
                Kept {
                    policies,
                    root,
                    verdict: previous.map_or(Verdict::Pending, |kept| kept.verdict.clone()),
                    stale_since: previous.map(|kept| kept.stale_since.unwrap_or(since)),
                }
            })
            .collect();
        if !after.is_empty() {
            kept.insert(image.clone(), after);
        }
    }

    /// Drops the verdicts of `image` but those under `policies`.
    fn retain(&self, image: &Digest, policies: &[MatchHash]) {
        let mut kept = self.kept.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(verdicts) = kept.get_mut(image) {
            verdicts.retain(|kept| policies.contains(&kept.policies));
            if verdicts.is_empty() {
                kept.remove(image);
            }
        }
    }

    /// How many verdicts are kept in each state.
    fn counts(&self) -> HashMap<&'static str, usize> {
        let kept = self.kept.read().unwrap_or_else(PoisonError::into_inner);
        let mut counts =
            HashMap::from(["allow", "rejected", "unverifiable", "pending"].map(|state| (state, 0)));
        for kept in kept.values().flatten() {
            *counts.entry(kept.verdict.state()).or_default() += 1;
        }
        counts
    }
}

/// What the engine asks of discovery (D126): the artifacts of a root, and upstream's once more before a rejection.
pub trait Discover: Send + Sync + 'static {
    /// The store discovery records into.
    fn store(&self) -> &Store;

    /// Discovers the artifacts of `root`, pulled as `names`.
    fn discover(
        &self,
        root: &Digest,
        names: &[String],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Asks upstream for the artifacts of `root` once more, recorded beside those found before.
    fn again(
        &self,
        root: &Digest,
        names: &[String],
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

impl Discover for Discovery {
    fn store(&self) -> &Store {
        Discovery::store(self)
    }

    async fn discover(&self, root: &Digest, names: &[String]) -> Result<(), Error> {
        Discovery::discover(self, root, names).await.map(drop)
    }

    async fn again(&self, root: &Digest, names: &[String]) -> Result<(), Error> {
        Discovery::again(self, root, names).await.map(drop)
    }
}

/// What the engine knows of a root listed or fetched.
#[derive(Debug)]
struct Root {
    /// The names it is listed under, else fetched under.
    names: Vec<String>,
    /// What its next verification counts under.
    trigger: Trigger,
    /// The hashes of the policies its names match: a verdict each.
    keys: Vec<MatchHash>,
    /// Whether its artifacts are recorded.
    discovered: bool,
    /// The unverifiable verifications in a row.
    failures: u32,
    /// When it is verified again.
    retry_at: Option<Instant>,
    /// Whether discovery runs for the engine.
    asking: bool,
    /// Whether upstream was asked once more (D126).
    asked_again: bool,
}

/// What a verification counts under: what started it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trigger {
    /// The first of a root a manifest fetch made, even when listed since (D152).
    Manifest,
    /// The first after a policy or trust-root change changed a key of the root (D21).
    Reverify,
    /// Any other: a listing, a discovery or a retry (D151).
    Event,
}

impl Trigger {
    /// The `trigger` label.
    fn label(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Reverify => "reverify",
            Self::Event => "event",
        }
    }
}

impl Root {
    /// The `trigger` label of the verification under way; the next ones are events.
    fn trigger(&mut self) -> &'static str {
        std::mem::replace(&mut self.trigger, Trigger::Event).label()
    }
}

/// What the engine asked of discovery.
#[derive(Clone, Copy, Debug)]
enum Ask {
    Discover,
    Again,
}

/// What a policy, or the policies of a key, came to.
#[derive(Debug)]
enum Outcome {
    /// Passed, with the identities that satisfied each authority.
    Pass(Vec<String>),
    Fail(String),
    Unverifiable(String),
}

/// The policies an image's names match, one group per hash.
struct Group<'a> {
    hash: MatchHash,
    policies: Vec<&'a Policy>,
}

/// The roots of the images the runtime's containers run now, which a change verifies again first (D21). It logs its
/// own errors: an empty set keeps the engine's order.
pub type Running =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = HashSet<Digest>> + Send>> + Send + Sync>;

/// Keeps a verdict for each key of each root discovery is told of.
pub struct Engine<D> {
    discovery: Arc<D>,
    /// The policies verified against, swapped as a whole when `policy_feed` changes (D21).
    policies: Arc<Policies>,
    policy_feed: watch::Receiver<Arc<Policies>>,
    signatures: Signatures,
    /// The trust root verified against, swapped as a whole when `trust` changes (D21).
    held: Held,
    trust: watch::Receiver<Held>,
    verdicts: Arc<Verdicts>,
    roots: HashMap<Digest, Root>,
    asks: JoinSet<(Digest, Ask, Result<(), Error>)>,
    /// The roots to verify again after a change, in order.
    reverify: VecDeque<Digest>,
    running: Running,
}

impl<D: Discover> Engine<D> {
    /// An engine verifying against the policies `policies` holds and the trust root `trust` holds, and again against
    /// each change of them, the roots `running` gives first (D21).
    #[must_use]
    pub fn new(
        discovery: Arc<D>,
        mut policies: watch::Receiver<Arc<Policies>>,
        signatures: Signatures,
        mut trust: watch::Receiver<Held>,
        running: Running,
    ) -> Self {
        let held = trust.borrow_and_update().clone();
        let current = Arc::clone(&policies.borrow_and_update());
        Self {
            discovery,
            policies: current,
            policy_feed: policies,
            signatures,
            held,
            trust,
            verdicts: Arc::default(),
            roots: HashMap::new(),
            asks: JoinSet::new(),
            reverify: VecDeque::new(),
            running,
        }
    }

    /// The verdicts the engine keeps.
    #[must_use]
    pub fn verdicts(&self) -> &Arc<Verdicts> {
        &self.verdicts
    }

    /// Verifies each root `found` tells of until it closes (D151).
    ///
    /// A root whose names match a policy has a verdict per hash of the policies its names match, pending until its
    /// discovery ends. An unverifiable key is verified again [`RETRY_FIRST`] later, then after twice the wait each
    /// time up to [`RETRY_MAX`], and discovery runs again first while the root's artifacts are not recorded. Before
    /// a rejection, upstream is asked once more (D126).
    ///
    /// A change of the policies or of the trust root's hash swaps them in, and verifies again, one root per turn of
    /// the loop, each root a key of which it changed; until then the key answers the verdict kept under the key it
    /// had, stale (D21).
    pub async fn run(mut self, mut found: mpsc::UnboundedReceiver<Found>) {
        loop {
            let next = self.roots.values().filter_map(|root| root.retry_at).min();
            tokio::select! {
                event = found.recv() => match event {
                    Some(Found::Roots { listed, fetched }) => self.roots(listed, fetched).await,
                    Some(Found::Ended { root, discovered }) => self.ended(&root, discovered).await,
                    None => break,
                },
                Some(answer) = self.asks.join_next() => match answer {
                    Ok((root, ask, answer)) => self.answered(&root, ask, answer).await,
                    Err(e) => warn!(error = %e, "a discovery for verification failed"),
                },
                () = sleep_until(next.unwrap_or_else(Instant::now)), if next.is_some() => self.due().await,
                // An error means the sender is gone: what it held stays.
                Ok(()) = self.policy_feed.changed() => self.changed().await,
                Ok(()) = self.trust.changed() => self.changed().await,
                () = std::future::ready(()), if !self.reverify.is_empty() => self.reverify_next().await,
            }
            self.count();
        }
        self.asks.abort_all();
    }

    /// Swaps in the policies and the trust root held now, and queues each root a key of which changed, its verdicts
    /// stale under their new keys, those the runtime's containers run first (D21).
    async fn changed(&mut self) {
        let policies = Arc::clone(&self.policy_feed.borrow_and_update());
        let previous = std::mem::replace(&mut self.policies, policies);
        let previous_root = self.trust_hash();
        self.held.clone_from(&self.trust.borrow_and_update());
        let trust = self.trust_hash();
        let since = Instant::now();
        let queued = self.reverify.len();
        for (digest, root) in &mut self.roots {
            let mut keys: Vec<(MatchHash, Option<MatchHash>)> = Vec::new();
            for name in &root.names {
                let Some(hash) = match_hash(&self.policies, name) else {
                    continue;
                };
                if keys.iter().all(|(kept, _)| *kept != hash) {
                    keys.push((hash, match_hash(&previous, name)));
                }
            }
            if trust == previous_root && keys.iter().map(|(hash, _)| hash).eq(&root.keys) {
                continue;
            }
            self.verdicts.rekey(digest, trust, &keys, since);
            root.keys = keys.into_iter().map(|(hash, _)| hash).collect();
            // A root asking verifies as discovery answers, and one not discovered as its discovery ends.
            if root.discovered
                && !root.asking
                && !root.keys.is_empty()
                && root.trigger != Trigger::Reverify
            {
                root.trigger = Trigger::Reverify;
                root.asked_again = false;
                self.reverify.push_back(digest.clone());
            }
        }
        if self.reverify.len() > queued {
            let running = (self.running)().await;
            // The sort is stable: the other roots keep their order.
            self.reverify
                .make_contiguous()
                .sort_by_key(|digest| !running.contains(digest));
            info!(
                roots = self.reverify.len() - queued,
                running = running.len(),
                "the policies or the trust root changed: verifying again"
            );
        }
    }

    /// Verifies again the next root queued, unless it was verified since.
    async fn reverify_next(&mut self) {
        let Some(digest) = self.reverify.pop_front() else {
            return;
        };
        if self
            .roots
            .get(&digest)
            .is_some_and(|root| root.trigger == Trigger::Reverify)
        {
            self.verify(&digest).await;
        }
    }

    /// Follows the roots listed and fetched: forgets those that left, and keeps a pending verdict for each key of the
    /// others.
    async fn roots(&mut self, listed: Roots, fetched: Roots) {
        let verdicts = &self.verdicts;
        self.roots.retain(|root, _| {
            let kept = listed.contains_key(root) || fetched.contains_key(root);
            if !kept {
                verdicts.retain(root, &[]);
            }
            kept
        });
        let trust = self.trust_hash();
        let mut changed = Vec::new();
        let listed = listed
            .into_iter()
            .map(|(digest, names)| (digest, names, Trigger::Event));
        let fetched = fetched
            .into_iter()
            .map(|(digest, names)| (digest, names, Trigger::Manifest));
        for (digest, names, trigger) in listed.chain(fetched) {
            let keys: Vec<MatchHash> = groups(&self.policies, &names)
                .iter()
                .map(|group| group.hash)
                .collect();
            for policies in &keys {
                let key = Key {
                    image: &digest,
                    policies: *policies,
                    root: trust,
                };
                if self.verdicts.get(key).verdict == Verdict::Pending {
                    self.verdicts.keep(key, Verdict::Pending);
                }
            }
            match self.roots.get_mut(&digest) {
                Some(root) if root.names == names => {}
                Some(root) => {
                    self.verdicts.retain(&digest, &keys);
                    root.names = names;
                    root.keys = keys;
                    if root.discovered {
                        changed.push(digest);
                    }
                }
                None => {
                    self.roots.insert(
                        digest,
                        Root {
                            names,
                            trigger,
                            keys,
                            discovered: false,
                            failures: 0,
                            retry_at: None,
                            asking: false,
                            asked_again: false,
                        },
                    );
                }
            }
        }
        for digest in changed {
            self.verify(&digest).await;
        }
    }

    /// Takes in the end of the discovery that follows the image list.
    async fn ended(&mut self, digest: &Digest, discovered: Result<(), Error>) {
        let Some(root) = self.roots.get_mut(digest) else {
            return;
        };
        match discovered {
            Ok(()) => {
                root.discovered = true;
                if !root.asking {
                    self.verify(digest).await;
                }
            }
            // The engine's own retries pace those of a root it waits on.
            Err(e) if !root.discovered && !root.asking && root.retry_at.is_none() => {
                self.unverified(digest, &e);
            }
            Err(_) => {}
        }
    }

    /// Takes in the answer to a discovery the engine asked for.
    async fn answered(&mut self, digest: &Digest, ask: Ask, answer: Result<(), Error>) {
        let Some(root) = self.roots.get_mut(digest) else {
            return;
        };
        root.asking = false;
        match (ask, answer) {
            (Ask::Discover, Ok(())) => {
                root.discovered = true;
                self.verify(digest).await;
            }
            (Ask::Discover, Err(e)) => self.unverified(digest, &e),
            // Upstream adding nothing leaves the rejection as the store's artifacts give it.
            (Ask::Again, answer) => {
                if let Err(e) = answer {
                    info!("discovery of {digest} upstream once more: {e}");
                }
                self.verify(digest).await;
            }
        }
    }

    /// Verifies again each root whose retry time came: discovers it first while its artifacts are not recorded.
    async fn due(&mut self) {
        let now = Instant::now();
        let mut due = Vec::new();
        for (digest, root) in &mut self.roots {
            if root.retry_at.is_some_and(|at| at <= now) {
                root.retry_at = None;
                if root.discovered {
                    due.push(digest.clone());
                } else {
                    root.asking = true;
                    self.asks.spawn(ask(
                        Arc::clone(&self.discovery),
                        digest.clone(),
                        root.names.clone(),
                        Ask::Discover,
                    ));
                }
            }
        }
        for digest in due {
            self.verify(&digest).await;
        }
    }

    /// Keeps each key of `digest` unverifiable as its discovery failed, and schedules the next try.
    fn unverified(&mut self, digest: &Digest, error: &Error) {
        let (reason, at) = match error {
            Error::Unverifiable { reason, retry_at } => (
                reason.to_string(),
                // A rate limit is upstream's to set (D38).
                matches!(reason, Reason::RateLimited { .. }).then_some(*retry_at),
            ),
            Error::Store(e) => (format!("artifact store: {e}"), None),
        };
        let started = Instant::now();
        let Some(retry_at) = self.roots.get_mut(digest).and_then(|root| retry(root, at)) else {
            return;
        };
        let Some(root) = self.roots.get_mut(digest) else {
            return;
        };
        let trigger = root.trigger();
        let groups = groups(&self.policies, &root.names);
        let trust = self.trust_hash();
        for group in &groups {
            let verdict = Verdict::Unverifiable {
                reason: Arc::from(reason.as_str()),
                retry_at,
            };
            decide(
                &self.verdicts,
                Key {
                    image: digest,
                    policies: group.hash,
                    root: trust,
                },
                &group.policies,
                &verdict,
                &[],
                (trigger, started),
            );
        }
    }

    /// Verifies each key of `digest` over its recorded artifacts, and keeps what it came to.
    async fn verify(&mut self, digest: &Digest) {
        let Some(root) = self.roots.get(digest).filter(|root| !root.keys.is_empty()) else {
            return;
        };
        let started = Instant::now();
        let held = self.held.clone();
        let trust = self.trust_hash();
        let artifacts = match self.discovery.store().recorded(digest).await {
            Ok(Some(artifacts)) => Ok(artifacts),
            Ok(None) => Err("artifacts not recorded".to_owned()),
            Err(e) => Err(format!("artifact store: {e}")),
        };
        let groups = groups(&self.policies, &root.names);
        let mut outcomes = Vec::with_capacity(groups.len());
        for group in &groups {
            let outcome = match &artifacts {
                Ok(artifacts) => {
                    let store = self.discovery.store();
                    combine(
                        &self.signatures,
                        store,
                        digest,
                        artifacts,
                        &group.policies,
                        held.as_deref(),
                    )
                    .await
                }
                Err(reason) => Outcome::Unverifiable(reason.clone()),
            };
            outcomes.push(outcome);
        }
        let failed = outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Fail(_)));
        let unverifiable = outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Unverifiable(_)));
        let Some(root) = self.roots.get_mut(digest) else {
            return;
        };
        let asking_again = failed && !root.asked_again;
        // The verification after upstream answers counts under the same trigger.
        let trigger = if asking_again {
            root.trigger.label()
        } else {
            root.trigger()
        };
        if asking_again {
            root.asked_again = true;
            root.asking = true;
            self.asks.spawn(ask(
                Arc::clone(&self.discovery),
                digest.clone(),
                root.names.clone(),
                Ask::Again,
            ));
        }
        let retry_at = if unverifiable {
            retry(root, None)
        } else {
            root.failures = 0;
            root.retry_at = None;
            None
        };
        for (group, outcome) in groups.iter().zip(outcomes) {
            let key = Key {
                image: digest,
                policies: group.hash,
                root: trust,
            };
            let (verdict, signers) = match outcome {
                Outcome::Pass(signers) => (Verdict::Allow, signers),
                Outcome::Fail(_) if asking_again => continue,
                Outcome::Fail(reason) => (
                    Verdict::Rejected {
                        reason: reason.into(),
                    },
                    Vec::new(),
                ),
                Outcome::Unverifiable(reason) => match retry_at {
                    Some(retry_at) => (
                        Verdict::Unverifiable {
                            reason: reason.into(),
                            retry_at,
                        },
                        Vec::new(),
                    ),
                    None => continue,
                },
            };
            decide(
                &self.verdicts,
                key,
                &group.policies,
                &verdict,
                &signers,
                (trigger, started),
            );
        }
    }

    /// The hash of the trust root verified against, if one is held.
    fn trust_hash(&self) -> Option<RootHash> {
        self.held.as_ref().ok().map(|root| root.hash())
    }

    /// Sets the verdicts gauge.
    fn count(&self) {
        for (state, count) in self.verdicts.counts() {
            metrics::verdicts(state, count);
        }
    }
}

/// Schedules the next try of `root`, no sooner than `at`, and returns its time; none for a root without key.
fn retry(root: &mut Root, at: Option<Instant>) -> Option<Instant> {
    if root.keys.is_empty() {
        return None;
    }
    let wait = RETRY_FIRST
        .saturating_mul(1 << root.failures.min(16))
        .min(RETRY_MAX);
    root.failures = root.failures.saturating_add(1);
    let retry_at = at.map_or(Instant::now() + wait, |at| at.max(Instant::now() + wait));
    root.retry_at = Some(retry_at);
    Some(retry_at)
}

/// Asks `discovery` for `root`'s artifacts as `ask` says.
async fn ask<D: Discover>(
    discovery: Arc<D>,
    root: Digest,
    names: Vec<String>,
    ask: Ask,
) -> (Digest, Ask, Result<(), Error>) {
    let answer = match ask {
        Ask::Discover => discovery.discover(&root, &names).await,
        Ask::Again => discovery.again(&root, &names).await,
    };
    (root, ask, answer)
}

/// The policies `name` matches; none for a name that does not parse.
fn matching<'a>(policies: &'a Policies, name: &str) -> Vec<&'a Policy> {
    let Ok(reference) = Reference::parse_normalized_named(name) else {
        warn!(%name, "an image name the runtime lists does not parse: no policy matches it");
        return Vec::new();
    };
    policies.matching(&reference).collect()
}

/// The hash of the policies `name` matches; none when it matches none.
fn match_hash(policies: &Policies, name: &str) -> Option<MatchHash> {
    let matched = matching(policies, name);
    (!matched.is_empty()).then(|| MatchHash::of(matched))
}

/// The groups of the policies `names` match, once per hash; a name no policy matches has none.
fn groups<'a>(policies: &'a Policies, names: &[String]) -> Vec<Group<'a>> {
    let mut groups: Vec<Group<'a>> = Vec::new();
    for name in names {
        let matched = matching(policies, name);
        if matched.is_empty() {
            continue;
        }
        let hash = MatchHash::of(matched.iter().copied());
        if groups.iter().all(|group| group.hash != hash) {
            groups.push(Group {
                hash,
                policies: matched,
            });
        }
    }
    groups
}

/// What `policies` come to over `artifacts`: each must pass (D11); a failure counts before an unverifiable check.
async fn combine(
    signatures: &Signatures,
    store: &Store,
    target: &Digest,
    artifacts: &[Artifact],
    policies: &[&Policy],
    root: Result<&TrustRoot, &Absent>,
) -> Outcome {
    let mut signers = Vec::new();
    let mut unverifiable = None;
    for policy in policies {
        match check(signatures, store, target, artifacts, policy, root).await {
            Outcome::Pass(passed) => signers.extend(passed),
            fail @ Outcome::Fail(_) => return fail,
            Outcome::Unverifiable(reason) => {
                unverifiable.get_or_insert(reason);
            }
        }
    }
    unverifiable.map_or(Outcome::Pass(signers), Outcome::Unverifiable)
}

/// What `policy` comes to over `artifacts`: one authority passes, and the SBOM it requires is there (D145, D150).
async fn check(
    signatures: &Signatures,
    store: &Store,
    target: &Digest,
    artifacts: &[Artifact],
    policy: &Policy,
    root: Result<&TrustRoot, &Absent>,
) -> Outcome {
    let name = policy.name();
    let results = match signatures
        .check(store, target, artifacts, policy, root)
        .await
    {
        Ok(results) => results,
        Err(e) => return Outcome::Unverifiable(e.to_string()),
    };
    let signers: Vec<String> = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .map(|signed| format!("{name}: {signed}"))
        .collect();
    if signers.is_empty() {
        // A policy has an authority at least, so it has an unmet one here.
        let unmet = results.iter().find_map(|result| result.as_ref().err());
        return Outcome::Fail(unmet.map_or_else(|| format!("policy {name}"), ToString::to_string));
    }
    // Without a trust root, the signature check is unverifiable already (D145).
    if let (Sbom::Required, Ok(root)) = (policy.sbom(), root) {
        match signatures
            .sbom(store, target, artifacts, policy, root)
            .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(failure)) => return Outcome::Fail(failure.to_string()),
            Err(e) => return Outcome::Unverifiable(e.to_string()),
        }
    }
    Outcome::Pass(signers)
}

/// Keeps `verdict` for `key`, counts the verification under the trigger that started it at the time given, and logs and
/// audits it when it differs from the one kept (D37).
fn decide(
    verdicts: &Verdicts,
    key: Key<'_>,
    policies: &[&Policy],
    verdict: &Verdict,
    signers: &[String],
    (trigger, started): (&'static str, Instant),
) {
    metrics::verified(verdict.state(), trigger, started.elapsed());
    let Some(before) = verdicts.keep(key, verdict.clone()) else {
        return;
    };
    if before.same(verdict) {
        return;
    }
    let names = policies
        .iter()
        .map(|policy| policy.name())
        .collect::<Vec<_>>()
        .join(", ");
    info!("verdict of {} under {names}: {verdict}", key.image);
    let trust_root = key
        .root
        .map_or_else(|| "none".to_owned(), |root| root.to_string());
    info!(
        target: AUDIT_TARGET,
        event = "verdict",
        image = %key.image,
        policies = %names,
        trust_root,
        result = verdict.state(),
        reason = verdict.reason(),
        signers = %signers.join("; "),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verdict_changes_with_its_state_or_reason_and_not_with_its_retry_time() {
        let now = Instant::now();
        let unverifiable = |reason: &str, retry_at| Verdict::Unverifiable {
            reason: reason.into(),
            retry_at,
        };
        let rejected = |reason: &str| Verdict::Rejected {
            reason: reason.into(),
        };
        assert!(unverifiable("a", now).same(&unverifiable("a", now + RETRY_FIRST)));
        assert!(!unverifiable("a", now).same(&unverifiable("b", now)));
        assert!(rejected("a").same(&rejected("a")));
        assert!(!rejected("a").same(&rejected("b")));
        assert!(!rejected("a").same(&unverifiable("a", now)));
        assert!(Verdict::Allow.same(&Verdict::Allow));
        assert!(!Verdict::Allow.same(&Verdict::Pending));
        assert_eq!((rejected("a").reason(), Verdict::Allow.reason()), ("a", ""));
    }

    #[test]
    fn verdicts_are_counted_by_state_and_dropped_unless_under_a_hash_kept() {
        let policy = "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: a\nspec:\n  \
                      images:\n  - glob: \"**\"\n  authorities:\n  - keyless:\n      identities:\n      - issuer: \
                      https://issuer.test\n        subject: https://subject.test\n";
        let policies = crate::Policies::parse(policy).expect("the test policy parses");
        let (none, one) = (MatchHash::of([]), MatchHash::of(policies.iter()));
        let image = speculaire_oci::hash::of("sha256", b"image").expect("sha256 is an algorithm");
        let key = |policies| Key {
            image: &image,
            policies,
            root: None,
        };
        let verdicts = Verdicts::default();
        verdicts.keep(key(none), Verdict::Allow);
        verdicts.keep(key(one), Verdict::Rejected { reason: "r".into() });
        let counts = verdicts.counts();
        assert_eq!(
            (
                counts.len(),
                counts["allow"],
                counts["rejected"],
                counts["pending"]
            ),
            (4, 1, 1, 0)
        );

        verdicts.retain(&image, &[one]);
        assert!(matches!(verdicts.get(key(none)).verdict, Verdict::Pending));
        assert!(matches!(
            verdicts.get(key(one)).verdict,
            Verdict::Rejected { .. }
        ));
        assert_eq!(verdicts.counts()["allow"], 0);

        verdicts.retain(&image, &[]);
        assert!(verdicts.kept.read().expect("not poisoned").is_empty());
    }

    #[test]
    fn a_rekey_marks_a_verdict_stale_under_its_new_key_and_keeps_one_whose_key_stays() {
        let path =
            std::path::Path::new(speculaire_artifacts::testing::FIXTURES).join("trusted_root.json");
        let root = Some(TrustRoot::load(&path).expect("the recorded root").hash());
        let image = speculaire_oci::hash::of("sha256", b"image").expect("sha256 is an algorithm");
        let policy = "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: a\nspec:\n  \
                      images:\n  - glob: \"**\"\n  authorities:\n  - keyless:\n      identities:\n      - issuer: \
                      https://issuer.test\n        subject: https://subject.test\n";
        let policies = crate::Policies::parse(policy).expect("the test policy parses");
        let (p, q) = (MatchHash::of([]), MatchHash::of(policies.iter()));
        let key = |policies, root| Key {
            image: &image,
            policies,
            root,
        };
        let verdicts = Verdicts::default();
        verdicts.set_stale_max(Duration::from_secs(3600));
        verdicts.keep(key(p, None), Verdict::Allow);
        let stale = Lookup {
            verdict: Verdict::Allow,
            stale: true,
        };

        verdicts.rekey(&image, root, &[(p, Some(p))], Instant::now());
        assert_eq!(verdicts.get(key(p, root)), stale);
        assert_eq!(verdicts.get(key(p, None)), Lookup::PENDING);

        verdicts.keep(key(q, root), Verdict::Allow);
        verdicts.rekey(&image, root, &[(p, Some(p)), (q, Some(q))], Instant::now());
        assert_eq!(verdicts.get(key(p, root)), stale);
        assert_eq!(verdicts.get(key(q, root)).verdict, Verdict::Allow);
        assert!(!verdicts.get(key(q, root)).stale, "an unchanged key stays");
    }
}
