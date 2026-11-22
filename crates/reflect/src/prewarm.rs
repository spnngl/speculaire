//! What a member prewarms: `prewarm.images` as written, and what each resolves to upstream (D51, D185, D186).

use std::error::Error;
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use speculaire_oci::reference::Reference;

use crate::Key;
use crate::push::{LIST_CAP, Malformed};

/// An entry of `prewarm.images`: the text as written, which picks its seeds (D181), and the reference CRI reads in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    text: Arc<str>,
    reference: Reference,
}

impl Image {
    /// The entry `text`.
    ///
    /// # Errors
    ///
    /// When `text` is not a reference CRI would pull (D60).
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        match Reference::parse_docker_ref(text) {
            Ok(reference) => Ok(Self {
                text: Arc::from(text),
                reference,
            }),
            Err(err) => Err(Malformed::Image(text.to_owned(), err)),
        }
    }

    /// The entry as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The reference CRI reads in it.
    #[must_use]
    pub const fn reference(&self) -> &Reference {
        &self.reference
    }
}

/// `prewarm.images`: at most [`LIST_CAP`] entries, so that the `PrewarmList` of them is one agents take (D187).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Images(Vec<Image>);

impl Images {
    /// The list of `images`.
    ///
    /// # Errors
    ///
    /// When there are more than [`LIST_CAP`].
    pub fn new(images: Vec<Image>) -> Result<Self, Malformed> {
        if images.len() > LIST_CAP {
            return Err(Malformed::Long(images.len()));
        }
        Ok(Self(images))
    }

    /// The entries, in the config's order.
    #[must_use]
    pub fn as_slice(&self) -> &[Image] {
        &self.0
    }
}

/// The `prewarm` settings a member runs its waves by, taken again at each reload (D30).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// `prewarm.images`.
    pub images: Images,
    /// `prewarm.seeds`: how many agents a wave sends an image to first.
    pub seeds: NonZeroU32,
    /// `prewarm.seed_timeout`: how long a round waits for its agents to announce the image (D185).
    pub seed_timeout: Duration,
    /// `prewarm.refresh`: how often a tag is resolved again (D186).
    pub refresh: Duration,
}

/// What an image resolves to upstream: the manifest its reference names, and each platform manifest below it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// The manifest the reference names: an index, or the image manifest itself.
    pub root: Key,
    /// The image manifests an agent may pull, in the index's order.
    pub platforms: Vec<Platform>,
}

impl Resolution {
    /// Whether `other` names the same platform manifests: a new wave starts only when it does not (D186).
    #[must_use]
    pub fn same_platforms(&self, other: &Self) -> bool {
        self.platforms
            .iter()
            .map(|platform| platform.manifest)
            .eq(other.platforms.iter().map(|platform| platform.manifest))
    }
}

/// An image manifest of a resolved image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    /// Its digest.
    pub manifest: Key,
    /// Its layers: an agent that announced each holds the image for that platform (D185).
    pub layers: Vec<Key>,
}

/// Why an image did not resolve, as the resolver words it.
pub type Failure = Box<dyn Error + Send + Sync>;

/// A resolved [`Image`]'s future.
pub type Resolving<'a> = Pin<Box<dyn Future<Output = Result<Resolution, Failure>> + Send + 'a>>;

/// Resolves images upstream, through the node's registry config (D17).
pub trait Resolve: Send + Sync {
    /// What `image` names now. `known` is its last resolution: one that still holds may be answered without fetching
    /// it again, as a tag's manifest digest tells.
    fn resolve<'a>(&'a self, image: &'a Reference, known: Option<&'a Resolution>) -> Resolving<'a>;
}
