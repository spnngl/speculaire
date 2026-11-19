//! The verdict engine: one verdict per key for each root listed, from the artifacts discovery keeps (D20, D151).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
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

/// A verdict kept, under the rest of its key.
#[derive(Debug)]
struct Kept {
    policies: MatchHash,
    root: Option<RootHash>,
    verdict: Verdict,
}

/// The verdicts kept, in memory (D151), by image identity.
#[derive(Debug, Default)]
pub struct Verdicts {
    kept: RwLock<HashMap<Digest, Vec<Kept>>>,
}

impl Verdicts {
    /// The verdict kept for `key`, [`Verdict::Pending`] when none is.
    #[must_use]
    pub fn get(&self, key: Key<'_>) -> Verdict {
        let kept = self.kept.read().unwrap_or_else(PoisonError::into_inner);
        kept.get(key.image)
            .and_then(|kept| {
                kept.iter()
                    .find(|kept| kept.policies == key.policies && kept.root == key.root)
            })
            .map_or(Verdict::Pending, |kept| kept.verdict.clone())
    }

    /// Keeps `verdict` for `key`, in place of one kept under an earlier trust root, and returns the verdict kept
    /// before, unless a rejection is kept already: it is final (D20).
    pub fn keep(&self, key: Key<'_>, verdict: Verdict) -> Option<Verdict> {
        let mut kept = self.kept.write().unwrap_or_else(PoisonError::into_inner);
        let image = kept.entry(key.image.clone()).or_default();
        match image.iter_mut().find(|kept| kept.policies == key.policies) {
            Some(Kept {
                verdict: Verdict::Rejected { .. },
                root,
                ..
            }) if *root == key.root => None,
            Some(kept) => {
                kept.root = key.root;
                Some(std::mem::replace(&mut kept.verdict, verdict))
            }
            None => {
                image.push(Kept {
                    policies: key.policies,
                    root: key.root,
                    verdict,
                });
                Some(Verdict::Pending)
            }
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

/// What the engine knows of a root listed.
#[derive(Debug)]
struct Root {
    /// The names it is listed under.
    names: Vec<String>,
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

/// Keeps a verdict for each key of each root discovery is told of.
pub struct Engine<D> {
    discovery: Arc<D>,
    policies: Policies,
    signatures: Signatures,
    trust: watch::Receiver<Held>,
    verdicts: Arc<Verdicts>,
    roots: HashMap<Digest, Root>,
    asks: JoinSet<(Digest, Ask, Result<(), Error>)>,
}

impl<D: Discover> Engine<D> {
    /// An engine verifying against `policies` and the trust root `trust` holds.
    #[must_use]
    pub fn new(
        discovery: Arc<D>,
        policies: Policies,
        signatures: Signatures,
        trust: watch::Receiver<Held>,
    ) -> Self {
        Self {
            discovery,
            policies,
            signatures,
            trust,
            verdicts: Arc::default(),
            roots: HashMap::new(),
            asks: JoinSet::new(),
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
    pub async fn run(mut self, mut found: mpsc::UnboundedReceiver<Found>) {
        loop {
            let next = self.roots.values().filter_map(|root| root.retry_at).min();
            tokio::select! {
                event = found.recv() => match event {
                    Some(Found::Listed(roots)) => self.listed(roots).await,
                    Some(Found::Ended { root, discovered }) => self.ended(&root, discovered).await,
                    None => break,
                },
                Some(answer) = self.asks.join_next() => match answer {
                    Ok((root, ask, answer)) => self.answered(&root, ask, answer).await,
                    Err(e) => warn!(error = %e, "a discovery for verification failed"),
                },
                () = sleep_until(next.unwrap_or_else(Instant::now)), if next.is_some() => self.due().await,
            }
            self.count();
        }
        self.asks.abort_all();
    }

    /// Follows the roots listed: forgets those that left, and keeps a pending verdict for each key of the others.
    async fn listed(&mut self, listed: Roots) {
        let verdicts = &self.verdicts;
        self.roots.retain(|root, _| {
            let kept = listed.contains_key(root);
            if !kept {
                verdicts.retain(root, &[]);
            }
            kept
        });
        let trust = self.trust_hash();
        let mut changed = Vec::new();
        for (digest, names) in listed {
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
                if self.verdicts.get(key) == Verdict::Pending {
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
        let groups = self
            .roots
            .get(digest)
            .map(|root| groups(&self.policies, &root.names))
            .unwrap_or_default();
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
                started,
            );
        }
    }

    /// Verifies each key of `digest` over its recorded artifacts, and keeps what it came to.
    async fn verify(&mut self, digest: &Digest) {
        let Some(root) = self.roots.get(digest).filter(|root| !root.keys.is_empty()) else {
            return;
        };
        let started = Instant::now();
        let held = self.trust.borrow().clone();
        let trust = held.as_ref().ok().map(|root| root.hash());
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
                started,
            );
        }
    }

    /// The hash of the trust root held, if one is.
    fn trust_hash(&self) -> Option<RootHash> {
        self.trust.borrow().as_ref().ok().map(|root| root.hash())
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

/// The groups of the policies `names` match, once per hash; a name no policy matches has none.
fn groups<'a>(policies: &'a Policies, names: &[String]) -> Vec<Group<'a>> {
    let mut groups: Vec<Group<'a>> = Vec::new();
    for name in names {
        let Ok(reference) = Reference::parse_normalized_named(name) else {
            warn!(%name, "an image name the runtime lists does not parse: no policy matches it");
            continue;
        };
        let matched: Vec<&Policy> = policies.matching(&reference).collect();
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

/// Keeps `verdict` for `key`, counts the verification, and logs and audits it when it differs from the one kept (D37).
fn decide(
    verdicts: &Verdicts,
    key: Key<'_>,
    policies: &[&Policy],
    verdict: &Verdict,
    signers: &[String],
    started: Instant,
) {
    metrics::verified(verdict.state(), "event", started.elapsed());
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
        assert!(matches!(verdicts.get(key(none)), Verdict::Pending));
        assert!(matches!(verdicts.get(key(one)), Verdict::Rejected { .. }));
        assert_eq!(verdicts.counts()["allow"], 0);

        verdicts.retain(&image, &[]);
        assert!(verdicts.kept.read().expect("not poisoned").is_empty());
    }
}
