//! The chain ID of an image's layers, the OCI image spec's "Layer ChainID": the name containerd gives the snapshot
//! of an image's root filesystem, which a container's snapshot is prepared on (D15).
//!
//! containerd reads an image config's `rootfs.diff_ids` (v2.3.7 `core/images/image.go:413-425`) and chains them with
//! `identity.ChainID` (v2.3.7 `client/container_opts.go:259`; image-spec v1.1.1 `identity/chainid.go:30-67`).

use serde::Deserialize;

use crate::hash;
use crate::reference::{Digest, ReferenceError};

/// An image config whose chain ID cannot be known.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The bytes are no JSON with a `rootfs.diff_ids` array.
    #[error("not an image config: {0}")]
    Json(#[from] serde_json::Error),
    /// It lists no layer: containerd prepares such an image's containers on no snapshot.
    #[error("the image has no layer")]
    NoLayers,
    /// A diff ID is no digest.
    #[error("a diff ID is no digest: {0}")]
    Digest(#[from] ReferenceError),
}

#[derive(Deserialize)]
struct Config {
    rootfs: RootFs,
}

#[derive(Deserialize)]
struct RootFs {
    diff_ids: Vec<String>,
}

/// The chain ID of the layers of `bytes`, an image config.
///
/// Go matches JSON keys without regard to case, which this does not: a config whose keys only Go reads, or that
/// repeats a key, gives an error or another chain ID, so it never matches the snapshot containerd made of it.
///
/// # Errors
///
/// When the bytes are no image config, list no layer, or a diff ID is malformed.
pub fn of_config(bytes: &[u8]) -> Result<Digest, Error> {
    let config: Config = serde_json::from_slice(bytes)?;
    let diff_ids = config
        .rootfs
        .diff_ids
        .iter()
        .map(|text| Digest::parse(text))
        .collect::<Result<Vec<_>, _>>()?;
    chain_id(&diff_ids).ok_or(Error::NoLayers)
}

/// The chain ID of `diff_ids`, applied in order: the first, then the SHA-256 of `<chain> <next>` for each next one.
/// `None` for no layer.
///
/// # Panics
///
/// Never: SHA-256 is an algorithm a digest is made by.
#[must_use]
pub fn chain_id(diff_ids: &[Digest]) -> Option<Digest> {
    let (first, rest) = diff_ids.split_first()?;
    Some(rest.iter().fold(first.clone(), |chain, next| {
        hash::of_parts(
            "sha256",
            &[
                chain.algorithm().as_bytes(),
                b":",
                chain.encoded().as_bytes(),
                b" ",
                next.algorithm().as_bytes(),
                b":",
                next.encoded().as_bytes(),
            ],
        )
        .expect("SHA-256 is an algorithm a digest is made by")
    }))
}

#[cfg(test)]
mod tests;
