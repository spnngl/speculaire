//! Resolving a tag from peers (D123): the first holders of its tag key are asked for the manifest it names.
//!
//! Nothing checks the answer against the tag: any node with a node identity can name any manifest for it, as on
//! Spegel. The manifest is hashed here, so what it names is checked as it is fetched (D7).

use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use http::HeaderValue;
use http_body_util::{BodyExt as _, Limited};
use hyper::Response;
use speculaire_oci::hash;
use speculaire_oci::reference::Digest;
use speculaire_oci::tagged::Tagged;
use tokio::time::timeout;
use tracing::{debug, warn};

use super::{Fetcher, Holder, ask};
use crate::pulls::Body;
use crate::serve::{MAX_MANIFEST, manifest_response, media_type};

/// How many holders of a tag are asked at once: the first good answer wins, and a second that differs is a conflict.
const ASKED: usize = 2;

/// A manifest a peer resolved a tag to.
#[derive(Clone, Debug)]
pub struct Resolved {
    /// The SHA-256 of the manifest, hashed here.
    pub digest: Digest,
    /// The manifest.
    pub bytes: Bytes,
    /// Its media type, read from its bytes.
    pub media_type: HeaderValue,
}

impl Resolved {
    /// The answer that serves it.
    pub(crate) fn response(&self, head: bool) -> Response<Body> {
        manifest_response(&self.bytes, &self.digest, self.media_type.clone(), head)
    }
}

impl Fetcher {
    /// The manifest `tagged` names, from the first of its holders to answer; `None` when `mirror.resolve_tags` is off
    /// or no holder answered.
    pub async fn tag(&self, tagged: &Tagged) -> Option<Resolved> {
        let settings = self.settings();
        if !settings.resolve_tags {
            return None;
        }
        let link = self.0.link.get()?;
        let path = format!("/v2/{}/manifests/{}", tagged.name(), tagged.tag());
        let mut asking: FuturesUnordered<_> = link
            .lookup
            .holders(tagged.key())
            .await
            .into_iter()
            .filter(|holder| self.0.allowed(&holder.node))
            .take(ASKED)
            .map(|holder| {
                let config = link.credentials.client(&holder.node);
                let path = path.clone();
                async move {
                    let answer = timeout(settings.stall_timeout, resolve(&holder, config, &path))
                        .await
                        .ok()
                        .flatten();
                    (holder, answer)
                }
            })
            .collect();
        let first = loop {
            match asking.next().await {
                Some((holder, Some(resolved))) => break Some((holder, resolved)),
                Some((_, None)) => {}
                None => break None,
            }
        };
        self.0.series.tag(first.is_some());
        let (holder, resolved) = first?;
        let shared = Arc::clone(&self.0);
        let (tagged, digest) = (tagged.clone(), resolved.digest.clone());
        // The pull goes on with the first answer; the others are only compared with it.
        tokio::spawn(async move {
            while let Some((other, answer)) = asking.next().await {
                if let Some(answer) = answer
                    && answer.digest != digest
                {
                    shared.series.tag_conflict();
                    warn!(tag = %tagged, node = %holder.node, %digest, other_node = %other.node, other_digest = %answer.digest, "two peers resolved a tag to different digests: the first answer is served (D123)");
                }
            }
        });
        Some(resolved)
    }
}

/// The manifest `holder` serves at `path`, whole; `None` when it gives no manifest.
async fn resolve(holder: &Holder, config: rustls::ClientConfig, path: &str) -> Option<Resolved> {
    let (body, size) = ask(holder, config, path, 0).await.ok()?;
    let Some(limit) = usize::try_from(size).ok().filter(|_| size <= MAX_MANIFEST) else {
        debug!(node = %holder.node, size, "a peer's tag answer is larger than a manifest");
        return None;
    };
    let bytes = match Limited::new(body, limit).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            debug!(node = %holder.node, error = %err, "a peer's tag answer broke off or is too large");
            return None;
        }
    };
    let Some(media_type) = media_type(&bytes).filter(|_| bytes.len() as u64 == size) else {
        debug!(node = %holder.node, "a peer's tag answer is no manifest of its length");
        return None;
    };
    let digest = hash::of("sha256", &bytes).expect("SHA-256 is a known algorithm");
    Some(Resolved {
        digest,
        bytes,
        media_type,
    })
}

#[cfg(test)]
mod tests;
