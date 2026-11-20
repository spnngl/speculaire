//! The image identity of a container the runtime creates, and the names policies match, read from NRI's
//! `CreateContainer` (D15, D65, D169).
//!
//! The gate holds the [`NodeIdentity`] of the node's runtime, which its `Configure` names, and asks it for each
//! container. On containerd 2.4 the request names the digest the image was listed with; on CRI-O it names the
//! image ID, which the agent's copy of the image list maps to the image's listed manifests and names.

use std::collections::HashMap;
use std::future::{Future, ready};
use std::sync::Arc;

use arc_swap::ArcSwap;
use speculaire_nri::api::Container;
use speculaire_oci::reference::Digest;
use speculaire_oci::tagged::Tagged;

use crate::detect::Runtime;
use crate::images::{Image, List, RepoDigest, image_id};

/// The annotation CRI-O puts its image ID in, after the pod's own (v1.37.2 `internal/annotations/annotations.go`).
pub const IMAGE_REF: &str = "io.kubernetes.cri-o.ImageRef";

/// Why no identity is read when the request carries none: an `Unverifiable` reason.
pub const MISSING: &str = "no image identity in the request";

/// Why a CRI-O image ID has no identity: no image the runtime lists has it, so no listed manifest has that config
/// digest (D65); an `Unverifiable` reason.
pub const NOT_CONFIG: &str = "image ID is not a config digest";

/// What a request says about the image of the container it creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Identified<'a> {
    /// containerd's: the digest the image was listed with, and the name containerd resolved it from (D15).
    Listed {
        /// The image's target digest, which the engine keys verdicts by: the index of a multi-platform image.
        digest: Digest,
        /// A tag of the image, or a repository digest when it has none.
        name: &'a str,
    },
    /// CRI-O's: the image of the ID, as last listed; its repository digests are its listed manifests (D65).
    Image(Arc<Image>),
    /// No identity, and why, as an `Unverifiable` reason.
    Unknown(&'static str),
}

impl Identified<'_> {
    /// The digests the engine keys the image's verdicts by: its listed manifests, each once.
    pub fn digests(&self) -> impl Iterator<Item = &Digest> {
        let (listed, repo_digests): (_, &[RepoDigest]) = match self {
            Self::Listed { digest, .. } => (Some(digest), &[]),
            Self::Image(image) => (None, &image.repo_digests),
            Self::Unknown(_) => (None, &[]),
        };
        let unique = repo_digests
            .iter()
            .enumerate()
            .filter(|&(i, repo)| {
                repo_digests[..i]
                    .iter()
                    .all(|seen| seen.digest != repo.digest)
            })
            .map(|(_, repo)| &repo.digest);
        listed.into_iter().chain(unique)
    }

    /// The names policies match: containerd's one; on CRI-O, every repository the image has, by a repository digest
    /// or a tag, each once (D65).
    pub fn names(&self) -> impl Iterator<Item = &str> {
        let (listed, image) = match self {
            Self::Listed { name, .. } => (Some(*name), None),
            Self::Image(image) => (None, Some(image.as_ref())),
            Self::Unknown(_) => (None, None),
        };
        let repositories = image.into_iter().flat_map(repositories);
        listed.into_iter().chain(repositories)
    }
}

/// Every repository of `image`, by a repository digest or a tag, in list order, each once.
fn repositories(image: &Image) -> impl Iterator<Item = &str> {
    let all = || {
        let digests = image
            .repo_digests
            .iter()
            .map(|repo| repo.repository.as_str());
        digests.chain(image.tags.iter().map(Tagged::name))
    };
    all()
        .enumerate()
        .filter(move |&(i, name)| all().take(i).all(|seen| seen != name))
        .map(|(_, name)| name)
}

/// How a container's image identity is read.
pub trait Identity: Send + Sync {
    /// The image identity of `container`, and its names.
    fn identify<'a>(
        &'a self,
        container: &'a Container,
    ) -> impl Future<Output = Identified<'a>> + Send + 'a;
}

/// containerd 2.4's path, `nri`: `Container.image`, which NRI v0.12.2 added (D15).
#[derive(Clone, Copy, Debug, Default)]
pub struct Nri;

impl Nri {
    fn read(container: &Container) -> Identified<'_> {
        let Some(image) = &container.image else {
            return Identified::Unknown(MISSING);
        };
        match Digest::parse(&image.digest) {
            Ok(digest) if !image.name.is_empty() => Identified::Listed {
                digest,
                name: &image.name,
            },
            _ => Identified::Unknown(MISSING),
        }
    }
}

impl Identity for Nri {
    fn identify<'a>(
        &'a self,
        container: &'a Container,
    ) -> impl Future<Output = Identified<'a>> + Send + 'a {
        ready(Self::read(container))
    }
}

/// CRI-O's path, `image_id`: the image ID of [`IMAGE_REF`], looked up in a copy of the image list (D65).
#[derive(Debug, Default)]
pub struct ImageId {
    images: ArcSwap<HashMap<Digest, Arc<Image>>>,
}

impl ImageId {
    /// Replaces the images looked up with `list`'s.
    pub fn keep(&self, list: &List) {
        let images = list
            .images()
            .map(|image| (image.id.clone(), Arc::new(image.clone())))
            .collect();
        self.images.store(Arc::new(images));
    }

    fn read(&self, container: &Container) -> Identified<'static> {
        let Some(id) = container.annotations.get(IMAGE_REF) else {
            return Identified::Unknown(MISSING);
        };
        let Some(id) = image_id(id) else {
            return Identified::Unknown(NOT_CONFIG);
        };
        match self.images.load().get(&id) {
            Some(image) => Identified::Image(Arc::clone(image)),
            None => Identified::Unknown(NOT_CONFIG),
        }
    }
}

impl Identity for ImageId {
    fn identify<'a>(
        &'a self,
        container: &'a Container,
    ) -> impl Future<Output = Identified<'a>> + Send + 'a {
        ready(self.read(container))
    }
}

/// The [`Identity`] of the node's runtime: one type, as [`NodeContent`](crate::NodeContent) is, because `Identity` has
/// no `dyn` form.
#[derive(Debug)]
pub enum NodeIdentity {
    /// containerd's.
    Nri(Nri),
    /// CRI-O's.
    ImageId(ImageId),
}

impl NodeIdentity {
    /// The path of `runtime`, by its name and not its NRI version (D169): CRI-O announces NRI v0.12.2 from 1.37 yet
    /// fills no `Container.image`, and 1.35 and 1.36 announce none NRI reads.
    #[must_use]
    pub fn of(runtime: Runtime) -> Self {
        match runtime {
            Runtime::Containerd => Self::Nri(Nri),
            Runtime::CriO => Self::ImageId(ImageId::default()),
        }
    }

    /// The path, as `speculaire_identity_path` labels it.
    #[must_use]
    pub fn path(&self) -> &'static str {
        match self {
            Self::Nri(_) => "nri",
            Self::ImageId(_) => "image_id",
        }
    }

    /// Gives the path the runtime's image list, at each change: CRI-O's maps image IDs with it.
    pub fn keep(&self, list: &List) {
        match self {
            Self::Nri(_) => {}
            Self::ImageId(image_id) => image_id.keep(list),
        }
    }
}

impl Identity for NodeIdentity {
    async fn identify<'a>(&'a self, container: &'a Container) -> Identified<'a> {
        match self {
            Self::Nri(nri) => nri.identify(container).await,
            Self::ImageId(image_id) => image_id.identify(container).await,
        }
    }
}

#[cfg(test)]
mod tests;
