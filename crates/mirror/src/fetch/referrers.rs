//! The referrers peers list for a manifest (D124, D126): the first holders of the manifest are asked for the index of
//! its referrers, and their lists are unioned.
//!
//! A list is a hint: the caller fetches each manifest it names by digest, which checks it (D7), and keeps it only when
//! the manifest itself says what it is about.

use futures_util::future::join_all;
use http_body_util::{BodyExt as _, Limited};
use speculaire_oci::reference::Digest;
use speculaire_oci::referrers::{self, Descriptor};
use tokio::time::timeout;
use tracing::debug;

use super::{Fetcher, Holder, WIDTH, ask};
use crate::serve::MAX_MANIFEST;

impl Fetcher {
    /// The referrers that the first [`WIDTH`] holders of `target`, in lookup order, list, each once; empty when the
    /// fetcher is not linked or no holder lists any.
    pub async fn referrers(&self, target: &Digest) -> Vec<Descriptor> {
        let Some(link) = self.0.link.get() else {
            return Vec::new();
        };
        let stall = self.settings().stall_timeout;
        let path = format!("/v2/speculaire/referrers/{target}");
        let asked = link
            .lookup
            .holders(target)
            .await
            .into_iter()
            .filter(|holder| self.0.allowed(&holder.node))
            .take(WIDTH)
            .map(|holder| {
                let config = link.credentials.client(&holder.node);
                let path = &path;
                async move {
                    timeout(stall, list(&holder, config, path))
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or_default()
                }
            });
        let mut union: Vec<Descriptor> = Vec::new();
        for descriptor in join_all(asked).await.into_iter().flatten() {
            if !union.iter().any(|kept| kept.digest == descriptor.digest) {
                union.push(descriptor);
            }
        }
        union
    }
}

/// The referrers index `holder` serves at `path`; `None` when it gives none.
async fn list(
    holder: &Holder,
    config: rustls::ClientConfig,
    path: &str,
) -> Option<Vec<Descriptor>> {
    let (body, size) = ask(holder, config, path, 0).await.ok()?;
    let Some(limit) = usize::try_from(size).ok().filter(|_| size <= MAX_MANIFEST) else {
        debug!(node = %holder.node, size, "a peer's referrers index is larger than a manifest");
        return None;
    };
    let bytes = match Limited::new(body, limit).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            debug!(node = %holder.node, error = %err, "a peer's referrers index broke off or is too large");
            return None;
        }
    };
    referrers::index(&bytes)
        .map_err(|err| debug!(node = %holder.node, error = %err, "a peer's referrers answer is no index"))
        .ok()
}

#[cfg(test)]
mod tests;
