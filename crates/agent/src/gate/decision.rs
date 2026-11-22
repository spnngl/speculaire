//! The decision on each `CreateContainer`, from the cached verdict of its image (D18, D22, D23, D41, D54, D172).
//!
//! An exempt namespace allows first, before the image identity is read; then an exempt image, then an image no policy
//! matches, which `gate.unmatched` decides; else the verdict of the image identity. A verdict missing or `Pending`, or
//! a CRI-O image ID the list does not name yet, asks the engine to verify the image and waits up to `gate.wait` for it.
//! `audit` allows every container; `enforce` rejects with the reason texts of `docs/operations.md`. Each decision is a
//! `gate` audit event (D37, D173).

pub mod running;

use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use speculaire_nri::Answer;
use speculaire_nri::create::{Container, Request};
use speculaire_oci::reference::{Reference, Repository};
use speculaire_runtime::identity::{Identified, Identity, MISSING, NodeIdentity};
use speculaire_runtime::images::List;
use speculaire_verify::engine::{Asked, Asking};
use speculaire_verify::{Glob, Held, Lookup, Policies, Verdict, Verdicts};
use tokio::sync::{Notify, mpsc, watch};
use tokio::time::Instant;
use tracing::{Level, info};

use crate::config::{self, Mode, Unmatched};
use crate::log::AUDIT_TARGET;

/// The reason of a container whose verdict did not land within `gate.wait` (D22).
pub const PENDING: &str = "verification pending";
/// The reason of a container whose image no policy matches, under `gate.unmatched = "deny"` (D23).
pub const UNMATCHED: &str = "unmatched";

/// The `[gate]` settings a decision reads, swapped whole at a reload.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `gate.mode`.
    pub mode: Mode,
    /// `gate.wait`.
    pub wait: Duration,
    /// `gate.unmatched`.
    pub unmatched: Unmatched,
    namespaces: Vec<String>,
    images: Vec<Glob>,
}

impl Settings {
    /// The settings of `gate`.
    #[must_use]
    pub fn new(gate: &config::Gate) -> Self {
        Self {
            mode: gate.mode,
            wait: gate.wait.get(),
            unmatched: gate.unmatched,
            namespaces: gate.exempt.namespaces.clone(),
            images: gate.exempt.images.clone(),
        }
    }

    /// Whether `gate.exempt.images` names each of the names policies match, and there is one (D18, D172, D179).
    fn exempts(&self, identified: &Identified<'_>) -> bool {
        let mut names = identified.names().peekable();
        !self.images.is_empty()
            && names.peek().is_some()
            && names.all(|name| {
                Repository::parse(name)
                    .is_ok_and(|name| self.images.iter().any(|glob| glob.is_match(name.as_str())))
            })
    }
}

/// What exempts a container (D18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exemption {
    /// `gate.exempt.namespaces` names its namespace.
    Namespace,
    /// `gate.exempt.images` names its image.
    Image,
}

impl Exemption {
    /// The `exemption` field of the `gate` audit event (D173).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Image => "image",
        }
    }
}

/// What the gate makes of a `CreateContainer`, before `gate.mode` applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Its namespace or image is exempt (D18).
    Exempt(Exemption),
    /// No policy matches its image (D23).
    Unmatched,
    /// The verdict of its image identity.
    Verdict(Lookup),
    /// The NRI plugin had too many requests in flight to decide it.
    Overloaded,
}

impl Decision {
    /// The `result` label of `speculaire_gate_total`.
    #[must_use]
    pub fn result(&self) -> &'static str {
        match self {
            Self::Exempt(_) => "exempt",
            Self::Unmatched => "unmatched",
            Self::Verdict(lookup) => lookup.verdict.state(),
            Self::Overloaded => "overloaded",
        }
    }

    /// Whether the verdict is stale (D21).
    #[must_use]
    pub fn stale(&self) -> bool {
        matches!(self, Self::Verdict(Lookup { stale: true, .. }))
    }

    /// Whether the gate waits for a verdict to land.
    fn pending(&self) -> bool {
        matches!(
            self,
            Self::Verdict(Lookup {
                verdict: Verdict::Pending,
                ..
            })
        )
    }

    /// The answer to the runtime under `settings`: `audit` allows all (D54).
    #[must_use]
    pub fn answer(&self, settings: &Settings) -> Answer {
        match self.reason(settings.unmatched) {
            Some(reason) if settings.mode == Mode::Enforce => Answer::Reject(reason),
            _ => Answer::Allow,
        }
    }

    /// The reason `enforce` rejects with under `unmatched`; none when it allows.
    fn reason(&self, unmatched: Unmatched) -> Option<String> {
        match self {
            Self::Exempt(_) => None,
            Self::Unmatched => match unmatched {
                Unmatched::Allow => None,
                Unmatched::Deny => Some(UNMATCHED.to_owned()),
            },
            Self::Verdict(lookup) => match &lookup.verdict {
                Verdict::Allow => None,
                verdict @ (Verdict::Rejected { .. } | Verdict::Unverifiable { .. }) => {
                    Some(verdict.to_string())
                }
                Verdict::Pending => Some(PENDING.to_owned()),
            },
            Self::Overloaded => Some(PENDING.to_owned()),
        }
    }

    /// The exemption that applied, if any.
    fn exemption(&self) -> Option<Exemption> {
        match self {
            Self::Exempt(exemption) => Some(*exemption),
            Self::Unmatched | Self::Verdict(_) | Self::Overloaded => None,
        }
    }
}

/// The verifier's side the gate reads: the verdicts, what keys them, and where to ask for a missing one.
#[derive(Debug, Clone)]
pub struct Verifier {
    /// The engine's verdicts.
    pub verdicts: Arc<Verdicts>,
    /// The policies in use.
    pub policies: watch::Receiver<Arc<Policies>>,
    /// The trust root in use.
    pub trust: watch::Receiver<Held>,
    /// The engine's [`speculaire_verify::Engine::asker`].
    pub asker: mpsc::UnboundedSender<Asked>,
    /// Told once the gate asked for the images of the containers `Synchronize` listed, which the image list waits for
    /// (D175).
    pub synchronized: Arc<Notify>,
}

impl Verifier {
    /// The decision on `identified` as the verdicts stand.
    fn decide(&self, settings: &Settings, identified: &Identified<'_>) -> Decision {
        if settings.exempts(identified) {
            return Decision::Exempt(Exemption::Image);
        }
        let root = self.trust.borrow().as_ref().ok().map(|root| root.hash());
        let policies = self.policies.borrow();
        match self.verdicts.identified(identified, &policies, root) {
            Some(lookup) => Decision::Verdict(lookup),
            None => Decision::Unmatched,
        }
    }

    /// The names of the policies the names of `identified` match, each once.
    fn matched(&self, identified: &Identified<'_>) -> Vec<String> {
        let policies = self.policies.borrow();
        let mut matched: Vec<String> = Vec::new();
        let names = identified
            .names()
            .filter_map(|name| Reference::parse_normalized_named(name).ok());
        for name in names {
            for policy in policies.matching(&name) {
                if !matched.iter().any(|seen| seen == policy.name()) {
                    matched.push(policy.name().to_owned());
                }
            }
        }
        matched
    }

    /// Asks the engine, as `by`, to verify each manifest of `identified` that no list named yet (D22, D175).
    fn ask(&self, identified: &Identified<'_>, by: Asking) {
        let names: Vec<String> = identified
            .names()
            .filter_map(|name| Reference::parse_normalized_named(name).ok())
            .map(|name| name.name().to_owned())
            .collect();
        for root in identified.digests() {
            let asked = Asked {
                root: root.clone(),
                names: names.clone(),
                by,
            };
            // A closed engine has stopped verifying: the wait ends as `Pending`.
            drop(self.asker.send(asked));
        }
    }
}

/// A decision, and the image identity it read: none when the namespace is exempt.
type Read<'a> = (Decision, Option<Identified<'a>>);

/// Decides each `CreateContainer` of the node's runtime.
#[derive(Debug)]
pub struct Decider {
    identity: Arc<NodeIdentity>,
    verifier: Verifier,
    settings: watch::Receiver<Arc<Settings>>,
    /// Wakes the waits at each image list the identity keeps.
    listed: Notify,
}

impl Decider {
    /// Decides through `identity` and `verifier`, under the latest `settings`.
    #[must_use]
    pub fn new(
        identity: Arc<NodeIdentity>,
        verifier: Verifier,
        settings: watch::Receiver<Arc<Settings>>,
    ) -> Self {
        Self {
            identity,
            verifier,
            settings,
            listed: Notify::new(),
        }
    }

    /// The identity the decisions read.
    #[must_use]
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// The settings in use.
    #[must_use]
    pub fn settings(&self) -> Arc<Settings> {
        Arc::clone(&self.settings.borrow())
    }

    /// Keeps the runtime's image `list` for the identity, and wakes the waits for an image ID it lacked (D172).
    pub fn keep(&self, list: &List) {
        self.identity.keep(list);
        self.listed.notify_waiters();
    }

    /// The decision on `request` under `settings`, waiting for a pending verdict until `gate.wait` has passed or
    /// `deadline` comes; audited.
    pub async fn decide(
        &self,
        request: &Request<'_>,
        settings: &Settings,
        deadline: Instant,
    ) -> Decision {
        let (decision, identified) = self.read(request, settings, deadline).await;
        self.audit(request, &decision, identified.as_ref(), settings);
        decision
    }

    /// The decision on `request` when it needs no wait, audited: of an exempt namespace, or of an identity read from
    /// memory whose verdict is not pending. None leaves `request` to [`Self::decide`], untouched. On a stored verdict, it
    /// allocates nothing (D189).
    pub fn decide_now(&self, request: &Request<'_>, settings: &Settings) -> Option<Decision> {
        let (decision, identified) = match self.container(request, settings) {
            Err(read) => read,
            Ok(container) => {
                let identified = self.identity.identify_now(&container)?;
                let decision = self.verifier.decide(settings, &identified);
                if decision.pending() {
                    return None;
                }
                (decision, Some(identified))
            }
        };
        self.audit(request, &decision, identified.as_ref(), settings);
        Some(decision)
    }

    /// [`Decision::Overloaded`] on `request`, audited.
    pub fn overloaded(&self, request: &Request<'_>, settings: &Settings) -> Decision {
        let decision = Decision::Overloaded;
        self.audit(request, &decision, None, settings);
        decision
    }

    /// The decision on `request`, and the image identity it read: none when the namespace is exempt.
    async fn read<'a>(
        &'a self,
        request: &Request<'a>,
        settings: &Settings,
        deadline: Instant,
    ) -> Read<'a> {
        let container = match self.container(request, settings) {
            Ok(container) => container,
            Err(read) => return read,
        };
        // NRI always sends the pod; a missing one is on the default runtime handler, as an empty one.
        let pod = request.pod.unwrap_or_default();
        let until = (Instant::now() + settings.wait).min(deadline);
        let mut identified = None;
        let mut asked = false;
        loop {
            // Enabled before the lookup, so that no verdict or list kept after it is missed.
            let mut landed = pin!(self.verifier.verdicts.changed());
            landed.as_mut().enable();
            let mut listed = pin!(self.listed.notified());
            listed.as_mut().enable();
            let current = match identified.take() {
                None | Some(Identified::Unlisted) => self.identity.identify(&pod, &container).await,
                Some(known) => known,
            };
            let decision = self.verifier.decide(settings, &current);
            if !decision.pending() || Instant::now() >= until {
                return (decision, Some(current));
            }
            if !asked {
                self.verifier.ask(&current, Asking::GateMiss);
                asked = true;
            }
            tokio::select! {
                () = landed => {}
                () = listed => {}
                () = tokio::time::sleep_until(until) => return (decision, Some(current)),
            }
            identified = Some(current);
        }
    }

    /// The container of `request` to identify; or the decision on a request that needs no identity, of an exempt
    /// namespace or without a container.
    #[expect(
        clippy::result_large_err,
        reason = "read once by its caller: boxing would allocate on the gate's path (D107)"
    )]
    fn container<'a>(
        &self,
        request: &Request<'a>,
        settings: &Settings,
    ) -> Result<Container<'a>, Read<'a>> {
        if let Some(pod) = request.pod
            && settings
                .namespaces
                .iter()
                .any(|namespace| namespace == pod.namespace)
        {
            return Err((Decision::Exempt(Exemption::Namespace), None));
        }
        request.container.ok_or_else(|| {
            let identified = Identified::Unknown(MISSING);
            (
                self.verifier.decide(settings, &identified),
                Some(identified),
            )
        })
    }

    /// Writes the `gate` audit event of `decision` on `request`, whose image identity reads as `identified`; its fields
    /// are those of `docs/operations.md` § Audit events (D37, D173).
    fn audit(
        &self,
        request: &Request<'_>,
        decision: &Decision,
        identified: Option<&Identified<'_>>,
        settings: &Settings,
    ) {
        // Audit is off by default: the fields cost nothing then (D107).
        if !tracing::enabled!(target: AUDIT_TARGET, Level::INFO) {
            return;
        }
        let Request { pod, container } = request;
        let identity = identified.and_then(Identified::identity);
        let policies = identified.map(|identified| self.verifier.matched(identified));
        info!(
            target: AUDIT_TARGET,
            event = "gate",
            namespace = pod.map_or("", |pod| pod.namespace),
            pod = pod.map_or("", |pod| pod.name),
            container = container.map_or("", |container| container.name),
            image_name = container.map(|container| self.identity.image_name(&container, identified)).unwrap_or_default(),
            image_identity = identity.map(ToString::to_string).unwrap_or_default(),
            identity_path = self.identity.path(),
            matched_policies = policies.unwrap_or_default().join(", "),
            mode = settings.mode.name(),
            result = decision.result(),
            reason = decision.reason(settings.unmatched).unwrap_or_default(),
            stale = decision.stale(),
            exemption = decision.exemption().map_or("", Exemption::name),
        );
    }
}

#[cfg(test)]
mod tests;
