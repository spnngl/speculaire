//! What containerd 2.4 says about its CRI image service through its introspection service (D15, D86).
//!
//! The image service exports two of its settings, `DiscardUnpackedLayers` and `RegistryConfigPath`, for clients that
//! detect them (v2.4.2 `plugins/cri/images/plugin.go:170`). containerd 2.3 exports neither: there the settings come
//! from `config.toml`.

use std::path::Path;

use containerd_client::services::v1::PluginsRequest;
use containerd_client::services::v1::introspection_client::IntrospectionClient;

use crate::cri::{Error, block_on, connect};

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
