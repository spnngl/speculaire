//! Discovery from peers (D126): what the node holds of a root, then what peers list about each target, before upstream.
//!
//! Each manifest and blob comes from the store when held, else from peers by digest with the fetcher, which checks it
//! in flight and denies a peer that sends wrong bytes (D52, D102). A peer's list is a hint: a listed manifest is kept
//! only when it is a Sigstore bundle whose subject is the target, or a legacy `.sig` manifest, which has no subject and
//! is kept for the target it was listed under.

use std::future::Future;
use std::pin::Pin;

use speculaire_mirror::request::Kind as Wanted;
use speculaire_oci::manifest::{self, Children};
use speculaire_oci::reference::Digest;
use speculaire_oci::referrers::{Referrer, SIMPLE_SIGNING};
use speculaire_runtime::content::Content;
use tracing::{debug, warn};

use super::{Discovery, Error, Origin};
use crate::metrics::{self, Outcome};
use crate::store::{Artifact, Discovering, Kind};

/// What the node holds of a manifest: the runtime's content, or the blob cache where the node relays (D67).
pub trait Local: Send + Sync {
    /// The manifest `digest`, when the node holds it and it is at most `max` bytes.
    fn manifest<'a>(
        &'a self,
        digest: &'a Digest,
        max: u64,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>>;
}

impl<C: Content> Local for C {
    fn manifest<'a>(
        &'a self,
        digest: &'a Digest,
        max: u64,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let blob = self.open(digest).await.ok().flatten()?;
            blob.read_all(max).await.ok().map(|bytes| bytes.to_vec())
        })
    }
}

impl Discovery {
    /// The manifest of `root` from the node's content, else the store or peers.
    pub(super) async fn held(&self, root: &Digest) -> Result<Option<Vec<u8>>, Error> {
        if let Some(bytes) = self.local.manifest(root, self.limits.manifest).await {
            return Ok(Some(bytes));
        }
        self.nearby_bytes(Wanted::Manifest, root, self.limits.manifest)
            .await
    }

    /// The artifacts of `root` that the store and peers give, `index` being its manifest when held.
    pub(super) async fn nearby(
        &self,
        discovering: &Discovering<'_>,
        root: &Digest,
        index: Option<&[u8]>,
    ) -> Result<Vec<Artifact>, Error> {
        let mut targets = vec![root.clone()];
        let mut artifacts = Vec::new();
        if let Some((platform, attestations)) = self.platform(index) {
            targets.push(platform.clone());
            for attestation in attestations {
                if let Some(artifact) = self
                    .near_attestation(discovering, &platform, &attestation)
                    .await?
                {
                    artifacts.push(artifact);
                    targets.push(attestation);
                }
            }
        }
        for target in &targets {
            self.listed(discovering, target, &mut artifacts).await?;
        }
        Ok(artifacts)
    }

    /// The attestation manifest `digest` of `target`, kept with its blobs.
    async fn near_attestation(
        &self,
        discovering: &Discovering<'_>,
        target: &Digest,
        digest: &Digest,
    ) -> Result<Option<Artifact>, Error> {
        let Some(bytes) = self
            .nearby_bytes(Wanted::Manifest, digest, self.limits.manifest)
            .await?
        else {
            return Ok(None);
        };
        let Ok(Children::Image { config, layers }) = manifest::children(&bytes) else {
            debug!(%digest, "an attestation manifest from peers that is no image manifest is dropped");
            return Ok(None);
        };
        let artifact = Artifact {
            target: target.clone(),
            manifest: digest.clone(),
            kind: Kind::Attestation,
            blobs: std::iter::once(config).chain(layers).collect(),
        };
        self.keep(discovering, Origin::Peers, &bytes, artifact)
            .await
    }

    /// The bundles and `.sig` manifests that peers list about `target`, kept with their blobs.
    async fn listed(
        &self,
        discovering: &Discovering<'_>,
        target: &Digest,
        artifacts: &mut Vec<Artifact>,
    ) -> Result<(), Error> {
        let mut listed = self.peers.referrers(target).await;
        listed.retain(|d| {
            (d.may_be_bundle() || d.artifact_type.as_deref() == Some(SIMPLE_SIGNING))
                && d.size <= self.limits.manifest
        });
        if listed.len() > self.limits.referrers {
            warn!(%target, referrers = listed.len(), kept = self.limits.referrers, "peers list too many referrers of a target");
            listed.truncate(self.limits.referrers);
        }
        for descriptor in listed {
            let digest = &descriptor.digest;
            let Some(bytes) = self
                .nearby_bytes(Wanted::Manifest, digest, self.limits.manifest)
                .await?
            else {
                continue;
            };
            let (kind, referrer) = match Referrer::parse(&bytes) {
                Ok(referrer)
                    if referrer.subject.as_ref() == Some(target) && referrer.is_bundle() =>
                {
                    (Kind::Bundle, referrer)
                }
                Ok(referrer)
                    if referrer.subject.is_none() && referrer.listed_type() == SIMPLE_SIGNING =>
                {
                    (Kind::Signature, referrer)
                }
                _ => {
                    debug!(%target, referrer = %digest, "a referrer from peers that is no bundle or signature of the target is dropped");
                    continue;
                }
            };
            let artifact = Artifact {
                target: target.clone(),
                manifest: digest.clone(),
                kind,
                blobs: referrer.blobs().map(|blob| blob.digest.clone()).collect(),
            };
            if let Some(artifact) = self
                .keep(discovering, Origin::Peers, &bytes, artifact)
                .await?
            {
                artifacts.push(artifact);
            }
        }
        Ok(())
    }

    /// `digest` from the store, else from peers, up to `max` bytes.
    pub(super) async fn nearby_bytes(
        &self,
        wanted: Wanted,
        digest: &Digest,
        max: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        if let Some(bytes) = self.store.read(digest).await? {
            return Ok(Some(bytes));
        }
        let Some(blob) = self.peers.whole_up_to(wanted, digest, max).await else {
            metrics::fetched_from_peers(Outcome::NotFound);
            return Ok(None);
        };
        match blob.read_all(max).await {
            Ok(bytes) => {
                metrics::fetched_from_peers(Outcome::Ok);
                Ok(Some(bytes.to_vec()))
            }
            Err(e) => {
                warn!(%digest, error = %e, "content from peers cannot be read");
                metrics::fetched_from_peers(Outcome::Error);
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests;
