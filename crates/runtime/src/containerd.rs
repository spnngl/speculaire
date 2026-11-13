//! containerd: what it says about itself, and the files and content of its node (D15, D86, D90).
//!
//! The image service exports two of its settings, `DiscardUnpackedLayers` and `RegistryConfigPath`, for clients that
//! detect them (v2.4.2 `plugins/cri/images/plugin.go:170`). containerd 2.3 exports neither: there the settings come
//! from `config.toml`.

pub mod content;
pub mod hosts;
pub mod inventory;
mod settings;
mod wiring;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use containerd_client::services::v1::PluginsRequest;
use containerd_client::services::v1::introspection_client::IntrospectionClient;
use containerd_client::tonic::transport::Channel;
pub use settings::MINIMUM;
use speculaire_registry_config::containerd::config as containerd_config;

use crate::cri::{Error, block_on, connect};
use crate::paths::Paths;

/// containerd's content directory, where its root is `/var/lib/containerd`.
const CONTENT_DIR: &str = "/var/lib/containerd/io.containerd.content.v1.content";

/// The namespace containerd's CRI plugin keeps its images in; the content service lists a blob only for a namespace
/// that has a reference to it.
const NAMESPACE: &str = "k8s.io";

/// Puts `request` in [`NAMESPACE`].
pub(crate) fn with_namespace<T>(request: &mut containerd_client::tonic::Request<T>) {
    request.metadata_mut().insert(
        "containerd-namespace",
        containerd_client::tonic::metadata::MetadataValue::from_static(NAMESPACE),
    );
}

/// A node that runs containerd: the files it reads, its socket and its content (D90).
#[derive(Clone, Debug)]
pub struct Containerd {
    paths: Paths,
    socket: PathBuf,
    config: Option<PathBuf>,
    content_directory: PathBuf,
    /// A channel to the content service, made once and kept; shared by the clones of this value.
    channel: Arc<tokio::sync::Mutex<Option<Channel>>>,
}

impl Containerd {
    /// The containerd of the node at `paths`, answering on `socket`; `config` is its `config.toml` when that is not
    /// the default one (`runtime.containerd_config`, D87).
    #[must_use]
    pub fn new(paths: Paths, socket: impl Into<PathBuf>, config: Option<PathBuf>) -> Self {
        let content_directory = paths.at(CONTENT_DIR);
        Self {
            paths,
            socket: socket.into(),
            config,
            content_directory,
            channel: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Its CRI socket.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// containerd's `config.toml`.
    #[must_use]
    pub fn config(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(|| self.paths.at(containerd_config::DEFAULT_PATH))
    }

    /// A channel to containerd, made once and kept; `None` while there is no containerd to connect to.
    pub(crate) async fn channel(&self) -> Option<Channel> {
        let mut held = self.channel.lock().await;
        if held.is_none() {
            *held = containerd_client::connect(&self.socket).await.ok();
        }
        held.clone()
    }

    /// Drops the channel: containerd went away or restarted, and the next call connects again.
    pub(crate) async fn forget_channel(&self) {
        *self.channel.lock().await = None;
    }
}

/// Whether `error` is `config` itself missing, where containerd runs on its defaults. A missing import fails containerd's
/// load as any other read does (v2.4.2 `cmd/containerd/server/config/config.go:522`).
pub(crate) fn config_missing(error: &containerd_config::LoadError, config: &Path) -> bool {
    matches!(error, containerd_config::LoadError::Read { path, source }
        if path == config && source.kind() == std::io::ErrorKind::NotFound)
}

const PLUGINS_METHOD: &str = "containerd.services.introspection.v1.Introspection/Plugins";

/// The image service's type and id in `Plugins`.
const IMAGES_TYPE: &str = "io.containerd.cri.v1";
const IMAGES_ID: &str = "images";

/// The settings the CRI image service of a running containerd exports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageExports {
    /// `DiscardUnpackedLayers`: the garbage collector may delete the layers of an unpacked image.
    pub discard_unpacked_layers: bool,
    /// `RegistryConfigPath`: the directories of `hosts.toml` trees, separated by `:`; empty when `mirrors` is used.
    pub registry_config_path: String,
}

/// What the image service exports, if containerd lists it with exports.
///
/// # Errors
///
/// When the socket cannot be connected to, or containerd does not answer in 5 s.
pub fn image_exports(socket: &Path) -> Result<Option<ImageExports>, Error> {
    block_on(socket, PLUGINS_METHOD, async {
        let mut client = IntrospectionClient::new(connect(socket).await?);
        let response = client
            .plugins(PluginsRequest {
                filters: Vec::new(),
            })
            .await
            .map_err(|status| Error::call(socket, PLUGINS_METHOD, &status))?
            .into_inner();
        Ok(response
            .plugins
            .into_iter()
            .find(|plugin| plugin.r#type == IMAGES_TYPE && plugin.id == IMAGES_ID)
            .and_then(|plugin| {
                // A plugin that failed to start exports nothing.
                if plugin.init_err.is_some() {
                    return None;
                }
                Some(ImageExports {
                    discard_unpacked_layers: plugin.exports.get("DiscardUnpackedLayers")? == "true",
                    registry_config_path: plugin.exports.get("RegistryConfigPath")?.clone(),
                })
            }))
    })
}
