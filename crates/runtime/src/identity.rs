//! The image identity of a container the runtime creates, and the names policies match, read from NRI's
//! `CreateContainer` (D15, D65, D169, D170).
//!
//! The gate holds the [`NodeIdentity`] of the node's runtime, which its `Configure` names, and asks it for each
//! container. On containerd 2.4 the request names the digest the image was listed with; on containerd 2.3 it names the
//! image by the name the pod asked for, which containerd's image store resolves; on CRI-O it names the image ID, which
//! the agent's copy of the image list maps to the image's listed manifests and names.
//!
//! Policies and exemptions match the name the pod asked for when the runtime gives it and names the image by it; else
//! every name the runtime has for the image, so that another name of it never chooses a laxer policy (D179).

pub mod annotation;

use std::collections::HashMap;
use std::future::{Future, pending, ready};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use speculaire_nri::NriVersion;
use speculaire_nri::create::{Container, Pod};
use speculaire_oci::reference::{Digest, Repository};
use speculaire_oci::tagged::Tagged;

use self::annotation::Annotation;
use crate::images::{Image, List, RepoDigest, image_id};
use crate::version::Release;

/// The annotation CRI-O puts its image ID in, after the pod's own (v1.37.2 `internal/annotations/annotations.go`).
pub const IMAGE_REF: &str = "io.kubernetes.cri-o.ImageRef";

/// Why no identity is read when the request carries none: an `Unverifiable` reason.
pub const MISSING: &str = "no image identity in the request";

/// Why a CRI-O image ID has no identity: it is no digest, or no manifest listed for its image has it as config digest
/// (D65, D172); an `Unverifiable` reason.
pub const NOT_CONFIG: &str = "image ID is not a config digest";

/// Why a container is rejected whose snapshot is not its image's: a `Rejected` reason (D15).
pub const MISMATCH: &str = "image identity mismatch";

/// The NRI version from which `Container.image` names the image (D15).
const IMAGE_FIELD: Release = Release::new(0, 12, 2);

/// What a request says about the image of the container it creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Identified<'a> {
    /// containerd's: the digest the image was listed with, and the name the pod asked for, which names the image (D15,
    /// D179).
    Listed {
        /// The image's target digest, which the engine keys verdicts by: the index of a multi-platform image.
        digest: Digest,
        /// The pod's image: a tag, a repository digest, or a short name of either.
        name: &'a str,
    },
    /// containerd 2.4's when the name the pod asked for is missing or not yet among the image's listed names: the
    /// digest it was listed with, and every repository the request and the list name it by (D179).
    Unconfirmed {
        /// The image's target digest, as `Listed`'s.
        digest: Digest,
        /// The repositories, each once.
        names: Vec<String>,
    },
    /// CRI-O's: the image of the ID, as last listed; its repository digests are its listed manifests (D65).
    Image(Arc<Image>),
    /// CRI-O's: an image ID the agent's copy of the image list lacks, until a list names it (D172).
    Unlisted,
    /// containerd 2.3's: the container's snapshot does not rest on the image its name resolves to; [`MISMATCH`].
    Mismatched,
    /// No identity, and why, as an `Unverifiable` reason.
    Unknown(&'static str),
}

impl Identified<'_> {
    /// The image identity: containerd's listed digest, or CRI-O's image ID; none when no listed image is read (D15).
    #[must_use]
    pub fn identity(&self) -> Option<&Digest> {
        match self {
            Self::Listed { digest, .. } | Self::Unconfirmed { digest, .. } => Some(digest),
            Self::Image(image) => Some(&image.id),
            Self::Unlisted | Self::Mismatched | Self::Unknown(_) => None,
        }
    }

    /// The digests the engine keys the image's verdicts by: its listed manifests, each once.
    pub fn digests(&self) -> impl Iterator<Item = &Digest> {
        let (listed, repo_digests): (_, &[RepoDigest]) = match self {
            Self::Listed { digest, .. } | Self::Unconfirmed { digest, .. } => (Some(digest), &[]),
            Self::Image(image) => (None, &image.repo_digests),
            Self::Unlisted | Self::Mismatched | Self::Unknown(_) => (None, &[]),
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

    /// The names policies and exemptions match: the one the pod asked for when it is known to name the image; else
    /// every repository the image has, each once, and each must pass and be exempt (D65, D179).
    pub fn names(&self) -> impl Iterator<Item = &str> {
        let (listed, unconfirmed, image): (_, &[String], _) = match self {
            Self::Listed { name, .. } => (Some(*name), &[], None),
            Self::Unconfirmed { names, .. } => (None, names, None),
            Self::Image(image) => (None, &[], Some(image.as_ref())),
            Self::Unlisted | Self::Mismatched | Self::Unknown(_) => (None, &[], None),
        };
        let repositories = image.into_iter().flat_map(repositories);
        let unconfirmed = unconfirmed.iter().map(String::as_str);
        listed.into_iter().chain(unconfirmed).chain(repositories)
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
    /// The image identity of `container`, created in `pod`, and its names.
    fn identify<'a>(
        &'a self,
        pod: &Pod<'_>,
        container: &Container<'a>,
    ) -> impl Future<Output = Identified<'a>> + Send;
}

/// A copy of the runtime's image list, by image ID.
#[derive(Debug, Default)]
struct ById(ArcSwap<HashMap<Digest, Arc<Image>>>);

impl ById {
    fn keep(&self, list: &List) {
        let images = list
            .images()
            .map(|image| (image.id.clone(), Arc::new(image.clone())))
            .collect();
        self.0.store(Arc::new(images));
    }

    fn get(&self, id: &Digest) -> Option<Arc<Image>> {
        self.0.load().get(id).cloned()
    }
}

/// containerd 2.4's path, `nri`: `Container.image`, which NRI v0.12.2 added (D15), and the name the pod asked for,
/// which containerd annotates; the image's listed names confirm the pod's (D179).
///
/// `Container.image.name` is the first of the image's names in containerd's order, whichever the pod asked for
/// (v2.4.2 `internal/cri/server/container_create.go:331`), so no policy is chosen by it alone.
#[derive(Debug, Default)]
pub struct Nri {
    images: ById,
}

impl Nri {
    /// Replaces the images whose names confirm the pod's with `list`'s.
    pub fn keep(&self, list: &List) {
        self.images.keep(list);
    }

    fn read<'a>(&self, container: &Container<'a>) -> Identified<'a> {
        let Some(image) = container.image else {
            return Identified::Unknown(MISSING);
        };
        let digest = match Digest::parse(image.digest) {
            Ok(digest) if !image.name.is_empty() => digest,
            _ => return Identified::Unknown(MISSING),
        };
        let asked = container.annotations.get(annotation::IMAGE_NAME);
        let repository = asked.and_then(|asked| Repository::parse(asked).ok());
        let listed = image_id(image.config_digest).and_then(|id| self.images.get(&id));
        if let (Some(asked), Some(repository), Some(listed)) = (asked, &repository, &listed)
            && repositories(listed).any(|name| name == repository.as_str())
        {
            // containerd's digest is its first name's: of the pod's repository, a manifest the list gives it stands in.
            let mut pulled = listed
                .repo_digests
                .iter()
                .filter(|pulled| pulled.repository == repository.as_str())
                .map(|pulled| &pulled.digest);
            let digest = if pulled.clone().any(|pulled| *pulled == digest) {
                digest
            } else {
                pulled.next().cloned().unwrap_or(digest)
            };
            return Identified::Listed {
                digest,
                name: asked,
            };
        }
        let first = Repository::parse(image.name).ok();
        let mut names: Vec<String> = Vec::new();
        let all = repository.iter().chain(&first).map(Repository::as_str);
        for name in all.chain(listed.iter().flat_map(|listed| repositories(listed))) {
            if !names.iter().any(|seen| seen == name) {
                names.push(name.to_owned());
            }
        }
        Identified::Unconfirmed { digest, names }
    }
}

impl Identity for Nri {
    fn identify<'a>(
        &'a self,
        _pod: &Pod<'_>,
        container: &Container<'a>,
    ) -> impl Future<Output = Identified<'a>> + Send {
        ready(self.read(container))
    }
}

/// CRI-O's path, `image_id`: the image ID of [`IMAGE_REF`], looked up in a copy of the image list (D65).
#[derive(Debug, Default)]
pub struct ImageId {
    images: ById,
}

impl ImageId {
    /// Replaces the images looked up with `list`'s.
    pub fn keep(&self, list: &List) {
        self.images.keep(list);
    }

    fn read(&self, container: &Container<'_>) -> Identified<'static> {
        let Some(id) = container.annotations.get(IMAGE_REF) else {
            return Identified::Unknown(MISSING);
        };
        let Some(id) = image_id(id) else {
            return Identified::Unknown(NOT_CONFIG);
        };
        match self.images.get(&id) {
            Some(image) => Identified::Image(image),
            None => Identified::Unlisted,
        }
    }
}

impl Identity for ImageId {
    fn identify<'a>(
        &'a self,
        _pod: &Pod<'_>,
        container: &Container<'a>,
    ) -> impl Future<Output = Identified<'a>> + Send {
        ready(self.read(container))
    }
}

/// The [`Identity`] of the node's runtime: one type, as [`NodeContent`](crate::NodeContent) is, because `Identity` has
/// no `dyn` form.
///
/// The runtime's name chooses between containerd's paths and CRI-O's (D169): CRI-O announces NRI v0.12.2 from 1.37 yet
/// fills no `Container.image`, and 1.35 and 1.36 announce none NRI reads. containerd's NRI version, announced or
/// inferred, chooses between its two at each `Configure` (D170).
#[derive(Debug)]
pub enum NodeIdentity {
    /// containerd's: `nri` until a `Configure` names an NRI version below v0.12.2, `annotation` from then on.
    Containerd {
        /// The `annotation` path, boxed as it is the larger by far.
        annotation: Box<Annotation>,
        /// The `nri` path.
        nri: Nri,
        /// Whether the last `Configure` chose it.
        annotated: AtomicBool,
    },
    /// CRI-O's.
    ImageId(ImageId),
}

impl NodeIdentity {
    /// containerd's paths, `annotation` reading its image store and snapshots through `annotation`.
    #[must_use]
    pub fn containerd(annotation: Annotation) -> Self {
        Self::Containerd {
            annotation: Box::new(annotation),
            nri: Nri::default(),
            annotated: AtomicBool::new(false),
        }
    }

    /// CRI-O's path.
    #[must_use]
    pub fn crio() -> Self {
        Self::ImageId(ImageId::default())
    }

    /// Chooses containerd's path by the NRI version `Configure` names: `nri` from v0.12.2, `annotation` below it or when
    /// the version is unknown, since containerd annotates every version's containers (D170). Returns the path.
    pub fn configure(&self, nri_version: &NriVersion) -> &'static str {
        if let Self::Containerd {
            annotation,
            annotated,
            ..
        } = self
        {
            let version = match nri_version {
                NriVersion::Announced(version) => Release::parse(version),
                NriVersion::Inferred(version) => Release::parse(version),
                NriVersion::Unknown { .. } => None,
            };
            let annotate = version.is_none_or(|version| version < IMAGE_FIELD);
            if annotate {
                annotation.configure();
            }
            annotated.store(annotate, Ordering::Relaxed);
        }
        self.path()
    }

    /// The path, as `speculaire_identity_path` labels it.
    #[must_use]
    pub fn path(&self) -> &'static str {
        match self {
            Self::Containerd { annotated, .. } if annotated.load(Ordering::Relaxed) => "annotation",
            Self::Containerd { .. } => "nri",
            Self::ImageId(_) => "image_id",
        }
    }

    /// The identity of `container`, created in `pod`, when it needs no call to the runtime: always on `nri` and
    /// `image_id`, on `annotation` when the image's chain ID is kept and the snapshot's prepare event read. On a listed
    /// image, it allocates nothing on `nri` and `image_id` (D189).
    #[must_use]
    pub fn identify_now<'a>(
        &'a self,
        pod: &Pod<'_>,
        container: &Container<'a>,
    ) -> Option<Identified<'a>> {
        match self.read(container) {
            Ok(identified) => Some(identified),
            Err(annotation) => annotation.identify_now(pod, container),
        }
    }

    /// The identity of `container` read from memory, or the `annotation` path that asks for it.
    fn read<'a>(&'a self, container: &Container<'a>) -> Result<Identified<'a>, &'a Annotation> {
        match self {
            Self::Containerd {
                annotation,
                annotated,
                ..
            } if annotated.load(Ordering::Relaxed) => Err(annotation),
            Self::Containerd { nri, .. } => Ok(nri.read(container)),
            Self::ImageId(image_id) => Ok(image_id.read(container)),
        }
    }

    /// The image name of `container` for the `gate` audit event (D173, D179): the names policies and exemptions matched
    /// in `identified`, comma-separated; on containerd, its pod-spec string when `identified` has none.
    #[must_use]
    pub fn image_name(
        &self,
        container: &Container<'_>,
        identified: Option<&Identified<'_>>,
    ) -> String {
        let names = identified
            .map(|identified| identified.names().collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        match self {
            Self::Containerd { .. } if names.is_empty() => container
                .annotations
                .get(annotation::IMAGE_NAME)
                .unwrap_or_default()
                .to_owned(),
            Self::Containerd { .. } | Self::ImageId(_) => names,
        }
    }

    /// Gives the path the runtime's image list, at each change: CRI-O's maps image IDs with it, containerd 2.4's
    /// confirms the pod's image name with it.
    pub fn keep(&self, list: &List) {
        match self {
            Self::Containerd { nri, .. } => nri.keep(list),
            Self::ImageId(image_id) => image_id.keep(list),
        }
    }

    /// Follows what the path reads besides the image list, until the agent stops: containerd's image store, so that it
    /// is current when a `Configure` chooses `annotation`. Never returns.
    pub async fn follow(&self) {
        if let Self::Containerd { annotation, .. } = self {
            annotation.follow().await;
        }
        pending::<()>().await;
    }
}

impl Identity for NodeIdentity {
    async fn identify<'a>(&'a self, pod: &Pod<'_>, container: &Container<'a>) -> Identified<'a> {
        match self.read(container) {
            Ok(identified) => identified,
            Err(annotation) => annotation.identify(pod, container).await,
        }
    }
}

#[cfg(test)]
mod tests;
