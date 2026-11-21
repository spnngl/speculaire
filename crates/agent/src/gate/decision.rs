//! The decision on each `CreateContainer`, from the cached verdict of its image (D18, D22, D23, D41, D54, D172).
//!
//! An exempt namespace allows first, before the image identity is read; then an exempt image, then an image no policy
//! matches, which `gate.unmatched` decides; else the verdict of the image identity. A verdict missing or `Pending`, or
//! a CRI-O image ID the list does not name yet, asks the engine to verify the image and waits up to `gate.wait` for it.
//! `audit` allows every container; `enforce` rejects with the reason texts of `docs/operations.md`.

use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use speculaire_nri::Answer;
use speculaire_nri::api::{CreateContainerRequest, PodSandbox};
use speculaire_oci::reference::Reference;
use speculaire_runtime::identity::{Identified, Identity, MISSING, NodeIdentity};
use speculaire_runtime::images::List;
use speculaire_verify::engine::{Asked, Asking};
use speculaire_verify::{Glob, Held, Lookup, Policies, Verdict, Verdicts};
use tokio::sync::{Notify, mpsc, watch};
use tokio::time::Instant;

use crate::config::{self, Mode, Unmatched};

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

    /// Whether `gate.exempt.images` names one of the names policies match (D18, D172).
    fn exempts(&self, identified: &Identified<'_>) -> bool {
        !self.images.is_empty()
            && identified.names().any(|name| {
                Reference::parse_normalized_named(name)
                    .is_ok_and(|name| self.images.iter().any(|glob| glob.matches(&name)))
            })
    }
}

/// What the gate makes of a `CreateContainer`, before `gate.mode` applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Its namespace or image is exempt (D18).
    Exempt,
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
            Self::Exempt => "exempt",
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
        if settings.mode == Mode::Audit {
            return Answer::Allow;
        }
        match self {
            Self::Exempt => Answer::Allow,
            Self::Unmatched => match settings.unmatched {
                Unmatched::Allow => Answer::Allow,
                Unmatched::Deny => Answer::Reject(UNMATCHED.to_owned()),
            },
            Self::Verdict(lookup) => match &lookup.verdict {
                Verdict::Allow => Answer::Allow,
                verdict @ (Verdict::Rejected { .. } | Verdict::Unverifiable { .. }) => {
                    Answer::Reject(verdict.to_string())
                }
                Verdict::Pending => Answer::Reject(PENDING.to_owned()),
            },
            Self::Overloaded => Answer::Reject(PENDING.to_owned()),
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
}

impl Verifier {
    /// The decision on `identified` as the verdicts stand.
    fn decide(&self, settings: &Settings, identified: &Identified<'_>) -> Decision {
        if settings.exempts(identified) {
            return Decision::Exempt;
        }
        let root = self.trust.borrow().as_ref().ok().map(|root| root.hash());
        let policies = self.policies.borrow();
        match self.verdicts.identified(identified, &policies, root) {
            Some(lookup) => Decision::Verdict(lookup),
            None => Decision::Unmatched,
        }
    }

    /// Asks the engine to verify each manifest of `identified` that no list named yet (D22).
    fn ask(&self, identified: &Identified<'_>) {
        let names: Vec<String> = identified
            .names()
            .filter_map(|name| Reference::parse_normalized_named(name).ok())
            .map(|name| name.name().to_owned())
            .collect();
        for root in identified.digests() {
            let asked = Asked {
                root: root.clone(),
                names: names.clone(),
                by: Asking::GateMiss,
            };
            // A closed engine has stopped verifying: the wait ends as `Pending`.
            drop(self.asker.send(asked));
        }
    }
}

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
    /// `deadline` comes.
    pub async fn decide(
        &self,
        request: &CreateContainerRequest,
        settings: &Settings,
        deadline: Instant,
    ) -> Decision {
        if let Some(pod) = &request.pod
            && settings.namespaces.contains(&pod.namespace)
        {
            return Decision::Exempt;
        }
        let Some(container) = &request.container else {
            return self
                .verifier
                .decide(settings, &Identified::Unknown(MISSING));
        };
        // NRI always sends the pod; a missing one is on the default runtime handler, as an empty one.
        let unnamed = PodSandbox::default();
        let pod = request.pod.as_ref().unwrap_or(&unnamed);
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
                None | Some(Identified::Unlisted) => self.identity.identify(pod, container).await,
                Some(known) => known,
            };
            let decision = self.verifier.decide(settings, &current);
            if !decision.pending() || Instant::now() >= until {
                return decision;
            }
            if !asked {
                self.verifier.ask(&current);
                asked = true;
            }
            identified = Some(current);
            tokio::select! {
                () = landed => {}
                () = listed => {}
                () = tokio::time::sleep_until(until) => return decision,
            }
        }
    }
}

#[cfg(test)]
mod tests;
