//! Spike 02: from inside `CreateContainer`, resolve the image to its chain ID and `Stat` the container snapshot.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use containerd_client::services::v1::{
    GetImageRequest, ReadContentRequest, content_client::ContentClient, images_client::ImagesClient,
    snapshots::{StatSnapshotRequest, snapshots_client::SnapshotsClient},
};
use containerd_client::tonic::{Request, transport::Channel};
use containerd_client::{connect, with_namespace};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const NAMESPACE: &str = "k8s.io";
const SNAPSHOTTER: &str = "overlayfs";

#[derive(Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}

#[derive(Deserialize)]
struct Index {
    manifests: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct Manifest {
    config: Descriptor,
}

#[derive(Deserialize)]
struct Config {
    rootfs: Rootfs,
}

#[derive(Deserialize)]
struct Rootfs {
    diff_ids: Vec<String>,
}

pub struct Outcome {
    pub target: String,
    pub chain_id: String,
    pub parent: String,
    pub grandparent: Option<String>,
    pub stat: Duration,
    pub total: Duration,
}

#[derive(Clone)]
pub struct Containerd(Channel);

fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

/// The OCI chain ID: `chain[0] = diff[0]`, `chain[i] = sha256(chain[i-1] + " " + diff[i])`.
fn chain_id(diff_ids: &[String]) -> Result<String> {
    let mut iter = diff_ids.iter();
    let mut chain = iter.next().context("image has no layers")?.clone();
    for diff in iter {
        let digest = Sha256::digest(format!("{chain} {diff}"));
        chain = format!("sha256:{digest:x}");
    }
    Ok(chain)
}

impl Containerd {
    pub async fn connect(socket: &Path) -> Result<Self> {
        Ok(Self(connect(socket).await.context("connect containerd")?))
    }

    async fn blob(&self, digest: &str) -> Result<Vec<u8>> {
        let mut content = ContentClient::new(self.0.clone());
        let req = with_namespace!(ReadContentRequest { digest: digest.into(), offset: 0, size: 0 }, NAMESPACE);
        let mut stream = content.read(req).await?.into_inner();
        let mut out = Vec::new();
        while let Some(chunk) = stream.message().await? {
            out.extend_from_slice(&chunk.data);
        }
        Ok(out)
    }

    /// Resolves `image` (the normalised CRI image name) to its target digest and chain ID, then stats `key`.
    pub async fn check(&self, image: &str, key: &str) -> Result<Outcome> {
        let started = Instant::now();
        let mut images = ImagesClient::new(self.0.clone());
        let image = images
            .get(with_namespace!(GetImageRequest { name: image.into() }, NAMESPACE))
            .await?
            .into_inner()
            .image
            .context("image missing in response")?;
        let target = image.target.context("image has no target")?;

        let mut manifest_digest = target.digest.clone();
        if target.media_type.contains("index") || target.media_type.contains("manifest.list") {
            let index: Index = serde_json::from_slice(&self.blob(&target.digest).await?)?;
            let picked = index
                .manifests
                .iter()
                .find(|m| m.platform.as_ref().is_some_and(|p| p.os == "linux" && p.architecture == node_arch()))
                .context("no manifest for node platform")?;
            manifest_digest = picked.digest.clone();
            let _ = &picked.media_type;
        }
        let manifest: Manifest = serde_json::from_slice(&self.blob(&manifest_digest).await?)?;
        let config: Config = serde_json::from_slice(&self.blob(&manifest.config.digest).await?)?;
        let chain = chain_id(&config.rootfs.diff_ids)?;

        let mut snapshots = SnapshotsClient::new(self.0.clone());
        let stat_started = Instant::now();
        let info = snapshots
            .stat(with_namespace!(StatSnapshotRequest { snapshotter: SNAPSHOTTER.into(), key: key.into() }, NAMESPACE))
            .await?
            .into_inner()
            .info
            .context("snapshot info missing")?;
        let stat = stat_started.elapsed();

        // A user-namespace pod without ID remapping parents a remapped snapshot, whose parent is the chain ID.
        let grandparent = if info.parent != chain && !info.parent.is_empty() {
            let parent = snapshots
                .stat(with_namespace!(
                    StatSnapshotRequest { snapshotter: SNAPSHOTTER.into(), key: info.parent.clone() },
                    NAMESPACE
                ))
                .await?
                .into_inner()
                .info
                .context("parent snapshot info missing")?;
            Some(parent.parent)
        } else {
            None
        };
        if info.parent.is_empty() {
            bail!("snapshot {key} has no parent");
        }
        Ok(Outcome { target: target.digest, chain_id: chain, parent: info.parent, grandparent, stat, total: started.elapsed() })
    }
}
