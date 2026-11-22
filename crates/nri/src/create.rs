//! A `CreateContainerRequest` read in place: the fields the gate reads, borrowed from the message (D189).
//!
//! The runtime sends the container whole, a few KiB of environment, mounts and Linux settings the gate never reads.
//! Read here, it costs one pass that skips them by wire type and allocates nothing. The fields are those of NRI
//! v0.12.3's `pkg/api/api.proto`: `CreateContainerRequest` (`:243-248`), `PodSandbox` (`:392-403`), `Container`
//! (`:416-439`) and `Image` (`:442-452`). A message written twice merges as protobuf merges it: a string is the last
//! one written, annotations are all of them, a later key replacing an earlier one. Fields left unread are skipped
//! without a look, where prost refuses one of the wrong wire type or a string that is not UTF-8.
//!
//! The same types view what prost decoded, such as `Synchronize`'s containers.

use std::collections::HashMap;
use std::fmt;

use crate::api;
pub use crate::wire::Error;
use crate::wire::{Value, fields};

/// `CreateContainerRequest.pod`.
const POD: u32 = 1;
/// `CreateContainerRequest.container`.
const CONTAINER: u32 = 2;
/// `annotations`, in `PodSandbox` and `Container` both.
const ANNOTATIONS: u32 = 6;

/// A container about to be created, and its pod.
#[derive(Debug, Clone, Copy, Default)]
pub struct Request<'a> {
    /// The pod, which NRI always sends.
    pub pod: Option<Pod<'a>>,
    /// The container.
    pub container: Option<Container<'a>>,
}

/// The fields of `PodSandbox` the gate reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pod<'a> {
    /// `name`, 2.
    pub name: &'a str,
    /// `namespace`, 4.
    pub namespace: &'a str,
    /// `annotations`, 6.
    pub annotations: Annotations<'a>,
    /// `runtime_handler`, 7.
    pub runtime_handler: &'a str,
}

/// The fields of `Container` the gate reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct Container<'a> {
    /// `id`, 1.
    pub id: &'a str,
    /// `name`, 3.
    pub name: &'a str,
    /// `annotations`, 6.
    pub annotations: Annotations<'a>,
    /// `image`, 22, which NRI v0.12.2 added.
    pub image: Option<Image<'a>>,
}

/// `Image`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Image<'a> {
    /// `name`, 1.
    pub name: &'a str,
    /// `digest`, 2.
    pub digest: &'a str,
    /// `config_digest`, 3.
    pub config_digest: &'a str,
}

/// A pod's or container's annotations.
#[derive(Clone, Copy)]
pub struct Annotations<'a>(Source<'a>);

/// Where annotations are read from.
#[derive(Clone, Copy)]
enum Source<'a> {
    /// Where they are written, on each lookup.
    Wire {
        /// The request, whose every annotation [`Request::read`] read.
        request: &'a [u8],
        /// The request's field they are in: [`POD`] or [`CONTAINER`].
        holder: u32,
    },
    /// What prost decoded.
    Decoded(&'a HashMap<String, String>),
}

impl<'a> Request<'a> {
    /// Reads `message`, a `CreateContainerRequest`.
    ///
    /// # Errors
    ///
    /// When a field read is not protobuf, or not of its type.
    pub fn read(message: &'a [u8]) -> Result<Self, Error> {
        let mut request = Self::default();
        let annotations = |holder| {
            Annotations(Source::Wire {
                request: message,
                holder,
            })
        };
        for field in fields(message) {
            match field? {
                (POD, value) => {
                    let pod = request.pod.get_or_insert_with(|| Pod {
                        annotations: annotations(POD),
                        ..Pod::default()
                    });
                    pod.read(value.bytes(POD)?)?;
                }
                (CONTAINER, value) => {
                    let container = request.container.get_or_insert_with(|| Container {
                        annotations: annotations(CONTAINER),
                        ..Container::default()
                    });
                    container.read(value.bytes(CONTAINER)?)?;
                }
                _ => {}
            }
        }
        Ok(request)
    }
}

impl<'a> Pod<'a> {
    fn read(&mut self, message: &'a [u8]) -> Result<(), Error> {
        for field in fields(message) {
            match field? {
                (field @ 2, value) => self.name = value.string(field)?,
                (field @ 4, value) => self.namespace = value.string(field)?,
                (ANNOTATIONS, value) => {
                    entry(value)?;
                }
                (field @ 7, value) => self.runtime_handler = value.string(field)?,
                _ => {}
            }
        }
        Ok(())
    }
}

impl<'a> Container<'a> {
    fn read(&mut self, message: &'a [u8]) -> Result<(), Error> {
        for field in fields(message) {
            match field? {
                (field @ 1, value) => self.id = value.string(field)?,
                (field @ 3, value) => self.name = value.string(field)?,
                (ANNOTATIONS, value) => {
                    entry(value)?;
                }
                (field @ 22, value) => self
                    .image
                    .get_or_insert_default()
                    .read(value.bytes(field)?)?,
                _ => {}
            }
        }
        Ok(())
    }
}

impl<'a> Image<'a> {
    fn read(&mut self, message: &'a [u8]) -> Result<(), Error> {
        for field in fields(message) {
            match field? {
                (field @ 1, value) => self.name = value.string(field)?,
                (field @ 2, value) => self.digest = value.string(field)?,
                (field @ 3, value) => self.config_digest = value.string(field)?,
                _ => {}
            }
        }
        Ok(())
    }
}

impl<'a> Annotations<'a> {
    /// The value of annotation `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&'a str> {
        match self.0 {
            Source::Wire { .. } => self
                .iter()
                .filter(|&(written, _)| written == key)
                .last()
                .map(|(_, value)| value),
            Source::Decoded(map) => map.get(key).map(String::as_str),
        }
    }

    /// Each annotation as written: of two with one key, [`Self::get`] reads the later.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + use<'a> {
        let (wire, decoded) = match self.0 {
            Source::Wire { request, holder } => (Some((request, holder)), None),
            Source::Decoded(map) => (None, Some(map)),
        };
        // `Request::read` read every field on this way: none fails.
        let wire = wire.into_iter().flat_map(|(request, holder)| {
            fields(request)
                .filter_map(Result::ok)
                .filter_map(move |(field, value)| (field == holder).then_some(value))
                .filter_map(move |value| value.bytes(holder).ok())
                .flat_map(|message| fields(message).filter_map(Result::ok))
                .filter_map(|(field, value)| {
                    (field == ANNOTATIONS).then(|| entry(value).ok()).flatten()
                })
        });
        let decoded = decoded
            .into_iter()
            .flatten()
            .map(|(key, value)| (key.as_str(), value.as_str()));
        wire.chain(decoded)
    }
}

impl Default for Annotations<'_> {
    fn default() -> Self {
        Self(Source::Wire {
            request: &[],
            holder: POD,
        })
    }
}

impl fmt::Debug for Annotations<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<'a> From<&'a api::CreateContainerRequest> for Request<'a> {
    fn from(request: &'a api::CreateContainerRequest) -> Self {
        Self {
            pod: request.pod.as_ref().map(Pod::from),
            container: request.container.as_ref().map(Container::from),
        }
    }
}

impl<'a> From<&'a api::PodSandbox> for Pod<'a> {
    fn from(pod: &'a api::PodSandbox) -> Self {
        Self {
            name: &pod.name,
            namespace: &pod.namespace,
            annotations: Annotations(Source::Decoded(&pod.annotations)),
            runtime_handler: &pod.runtime_handler,
        }
    }
}

impl<'a> From<&'a api::Container> for Container<'a> {
    fn from(container: &'a api::Container) -> Self {
        Self {
            id: &container.id,
            name: &container.name,
            annotations: Annotations(Source::Decoded(&container.annotations)),
            image: container.image.as_ref().map(|image| Image {
                name: &image.name,
                digest: &image.digest,
                config_digest: &image.config_digest,
            }),
        }
    }
}

/// A map entry's key and value, each empty when unwritten.
fn entry(value: Value<'_>) -> Result<(&str, &str), Error> {
    let mut entry = ("", "");
    for field in fields(value.bytes(ANNOTATIONS)?) {
        match field? {
            (field @ 1, value) => entry.0 = value.string(field)?,
            (field @ 2, value) => entry.1 = value.string(field)?,
            _ => {}
        }
    }
    Ok(entry)
}

#[cfg(test)]
mod tests;
