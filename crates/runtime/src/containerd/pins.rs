//! Pinning prewarmed images in containerd, so the kubelet's image garbage collection keeps them (D191).
//!
//! containerd's CRI plugin reports an image as pinned when one of its names carries `io.cri-containerd.pinned=pinned`
//! (v2.4.2 `internal/cri/labels/labels.go:46-49`, `internal/cri/store/image/image.go:178,259`), and reloads that name
//! on its `/images/update` event (`internal/cri/server/events.go:386-388`). The agent marks the names it pins with
//! [`MARK`], so it unpins only those: a name pinned without the mark, such as the sandbox image (`pinned_images` of the
//! CRI config) or an operator's pin, is left alone.

use std::collections::HashMap;
use std::path::Path;

use containerd_client::services::v1::images_client::ImagesClient;
use containerd_client::services::v1::{
    GetImageRequest, Image, ListImagesRequest, UpdateImageRequest,
};
use containerd_client::tonic::{Code, Request};
use speculaire_oci::reference::Reference;

use super::with_namespace;
use crate::cri::{Error, block_on, connect, timed};

/// The CRI plugin's pin label, and its one value.
const PINNED: &str = "io.cri-containerd.pinned";
const PINNED_VALUE: &str = "pinned";

/// The agent's mark on a pin it made; its value is [`PINNED_VALUE`].
const MARK: &str = "speculaire.prewarm";

const GET_METHOD: &str = "containerd.services.images.v1.Images/Get";
const LIST_METHOD: &str = "containerd.services.images.v1.Images/List";
const UPDATE_METHOD: &str = "containerd.services.images.v1.Images/Update";

/// Pins `image` and marks the pin, unless it is pinned already, and answers whether it carries the agent's pin. An
/// image containerd lacks has nothing to pin.
pub(crate) async fn pin(socket: &Path, image: &Reference) -> Result<bool, Error> {
    timed(socket, UPDATE_METHOD, async {
        match stored(socket, &image.to_string()).await? {
            Some(stored) if has(&stored.labels, MARK) => Ok(true),
            Some(stored) if !has(&stored.labels, PINNED) => {
                update(socket, stored, PINNED_VALUE).await.map(|()| true)
            }
            _ => Ok(false),
        }
    })
    .await
}

/// Takes the pin off `image` if the agent marked it, and the mark with it.
pub(crate) async fn unpin(socket: &Path, image: &Reference) -> Result<(), Error> {
    timed(socket, UPDATE_METHOD, async {
        match stored(socket, &image.to_string()).await? {
            Some(stored) if has(&stored.labels, MARK) => update(socket, stored, "").await,
            _ => Ok(()),
        }
    })
    .await
}

/// Takes off every pin the agent marked, and answers the images: what `unconfigure` does (D32). It blocks, on a
/// runtime of its own.
pub(crate) fn unpin_all(socket: &Path) -> Result<Vec<Reference>, Error> {
    block_on(socket, UPDATE_METHOD, async {
        let images = marked(socket).await?;
        for image in &images {
            unpin(socket, image).await?;
        }
        Ok(images)
    })
}

/// The images the agent marked, by the names that parse as references: the agent marks no other.
pub(crate) async fn marked(socket: &Path) -> Result<Vec<Reference>, Error> {
    let mut request = Request::new(ListImagesRequest {
        filters: Vec::new(),
    });
    with_namespace(&mut request);
    let images = timed(socket, LIST_METHOD, async {
        ImagesClient::new(connect(socket).await?)
            .list(request)
            .await
            .map_err(|status| Error::call(socket, LIST_METHOD, &status))
    })
    .await?
    .into_inner()
    .images;
    Ok(images
        .into_iter()
        .filter(|image| has(&image.labels, MARK))
        // The agent marks only the names it pins, which are references in full: an image ID, which a reference would
        // read as `docker.io/library/sha256`, is none.
        .filter_map(|image| {
            Reference::parse_docker_ref(&image.name)
                .ok()
                .filter(|reference| reference.to_string() == image.name)
        })
        .collect())
}

/// The image named `name`, if containerd has it.
async fn stored(socket: &Path, name: &str) -> Result<Option<Image>, Error> {
    let mut request = Request::new(GetImageRequest {
        name: name.to_owned(),
    });
    with_namespace(&mut request);
    match ImagesClient::new(connect(socket).await?).get(request).await {
        Ok(response) => Ok(response.into_inner().image),
        Err(status) if status.code() == Code::NotFound => Ok(None),
        Err(status) => Err(Error::call(socket, GET_METHOD, &status)),
    }
}

/// Sets the pin and the mark of `image` to `value`; containerd deletes a label set empty (v2.4.2
/// `core/metadata/boltutil/helpers.go:96-99`). The request carries the whole image, as containerd reads its target
/// before the field mask, and crashes on an image without one (v2.4.2 `plugins/services/images/helpers.go:50`). The
/// mask names the two labels alone, so a pull that moved the target meanwhile is not undone.
async fn update(socket: &Path, mut image: Image, value: &str) -> Result<(), Error> {
    for key in [PINNED, MARK] {
        image.labels.insert(key.to_owned(), value.to_owned());
    }
    let mut update = UpdateImageRequest {
        image: Some(image),
        ..UpdateImageRequest::default()
    };
    update.update_mask.get_or_insert_default().paths =
        [PINNED, MARK].map(|key| format!("labels.{key}")).to_vec();
    let mut request = Request::new(update);
    with_namespace(&mut request);
    match ImagesClient::new(connect(socket).await?)
        .update(request)
        .await
    {
        // Deleted since: nothing is left to pin or unpin.
        Ok(_) => Ok(()),
        Err(status) if status.code() == Code::NotFound => Ok(()),
        Err(status) => Err(Error::call(socket, UPDATE_METHOD, &status)),
    }
}

/// Whether `labels` sets `key` to [`PINNED_VALUE`].
fn has(labels: &HashMap<String, String>, key: &str) -> bool {
    labels.get(key).is_some_and(|value| value == PINNED_VALUE)
}

#[cfg(test)]
mod tests;
