//! What a member sends an agent unasked, parsed from its protobuf at the boundary (D51, D183).

use speculaire_oci::reference::{Reference, ReferenceError};

use crate::prewarm::Images;
use crate::proto;

/// How many images a `PrewarmList` names at most (D183).
pub const LIST_CAP: usize = 64;

/// A message a member sends unasked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Push {
    /// Pull the image ahead of use (D51).
    Prewarm(Reference),
    /// The member's `prewarm.images`, which replaces the last list it sent.
    List(PrewarmList),
}

/// The images of a `PrewarmList`: at most [`LIST_CAP`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrewarmList(Vec<Reference>);

impl PrewarmList {
    /// A list of `images`.
    ///
    /// # Errors
    ///
    /// When there are more than [`LIST_CAP`].
    pub fn new(images: Vec<Reference>) -> Result<Self, Malformed> {
        if images.len() > LIST_CAP {
            return Err(Malformed::Long(images.len()));
        }
        Ok(Self(images))
    }

    /// The images, in the member's order.
    #[must_use]
    pub fn images(&self) -> &[Reference] {
        &self.0
    }
}

impl From<&Images> for PrewarmList {
    fn from(images: &Images) -> Self {
        Self(
            images
                .as_slice()
                .iter()
                .map(|image| image.reference().clone())
                .collect(),
        )
    }
}

/// Why a push cannot be parsed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    /// An image is not a reference CRI would pull.
    #[error("{0:?} is not an image reference: {1}")]
    Image(String, ReferenceError),
    /// A list names more than [`LIST_CAP`] images.
    #[error("a list of {0} images, over {LIST_CAP}")]
    Long(usize),
}

/// An image as containerd's CRI plugin reads the name `PullImage` gets (D51).
fn image(text: String) -> Result<Reference, Malformed> {
    Reference::parse_docker_ref(&text).map_err(|err| Malformed::Image(text, err))
}

impl TryFrom<proto::Prewarm> for Push {
    type Error = Malformed;

    fn try_from(prewarm: proto::Prewarm) -> Result<Self, Malformed> {
        image(prewarm.image).map(Self::Prewarm)
    }
}

impl TryFrom<proto::PrewarmList> for PrewarmList {
    type Error = Malformed;

    fn try_from(list: proto::PrewarmList) -> Result<Self, Malformed> {
        // The length first: an outsized list is refused before any of it is parsed.
        if list.images.len() > LIST_CAP {
            return Err(Malformed::Long(list.images.len()));
        }
        let mut images = Vec::with_capacity(list.images.len());
        for text in list.images {
            images.push(image(text)?);
        }
        Ok(Self(images))
    }
}

impl From<&Reference> for proto::Prewarm {
    fn from(image: &Reference) -> Self {
        Self {
            image: image.to_string(),
        }
    }
}

impl From<&PrewarmList> for proto::PrewarmList {
    fn from(list: &PrewarmList) -> Self {
        Self {
            images: list.0.iter().map(ToString::to_string).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(images: &[&str]) -> proto::PrewarmList {
        proto::PrewarmList {
            images: images.iter().map(|&image| image.to_owned()).collect(),
        }
    }

    #[test]
    fn images_parse_as_cri_reads_them_and_print_back_canonically() {
        let prewarm = Push::try_from(proto::Prewarm {
            image: "nginx".to_owned(),
        })
        .unwrap();
        let Push::Prewarm(image) = &prewarm else {
            panic!("{prewarm:?} is not a prewarm");
        };
        assert_eq!(
            proto::Prewarm::from(image).image,
            "docker.io/library/nginx:latest"
        );
        let parsed = PrewarmList::try_from(list(&["nginx:1", "Nginx"]));
        assert_eq!(
            parsed,
            Err(Malformed::Image(
                "Nginx".to_owned(),
                ReferenceError::Uppercase
            ))
        );
        let parsed = PrewarmList::try_from(list(&["nginx:1", "quay.io/a/b"])).unwrap();
        assert_eq!(
            proto::PrewarmList::from(&parsed),
            list(&["docker.io/library/nginx:1", "quay.io/a/b:latest"])
        );
    }

    #[test]
    fn a_list_holds_at_most_sixty_four_images() {
        let full = vec!["nginx"; LIST_CAP];
        let parsed = PrewarmList::try_from(list(&full)).unwrap();
        assert_eq!(parsed.images().len(), LIST_CAP);
        assert_eq!(
            PrewarmList::new(parsed.images().to_vec()),
            Ok(parsed.clone())
        );
        let over = vec!["nginx"; LIST_CAP + 1];
        assert_eq!(
            PrewarmList::try_from(list(&over)),
            Err(Malformed::Long(LIST_CAP + 1))
        );
        let mut images = parsed.images().to_vec();
        images.push(images[0].clone());
        assert_eq!(PrewarmList::new(images), Err(Malformed::Long(LIST_CAP + 1)));
    }
}
