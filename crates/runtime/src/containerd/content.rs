//! containerd's content: its directory, then its content service.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use containerd_client::services::v1::InfoRequest;
use containerd_client::services::v1::content_client::ContentClient;
use containerd_client::tonic::transport::Channel;
use containerd_client::tonic::{Code, Request};
use speculaire_oci::reference::Digest;

use super::{Containerd, with_namespace};
use crate::content::{Blob, Content, Error};

impl Containerd {
    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.content_directory
            .join("blobs")
            .join(digest.algorithm())
            .join(digest.encoded())
    }

    /// The size of the blob if containerd's content service has it.
    async fn info(&self, digest: &Digest) -> Result<Option<(Channel, u64)>, Error> {
        let Some(channel) = self.channel().await else {
            return Ok(None);
        };
        let mut request = Request::new(InfoRequest {
            digest: digest.to_string(),
        });
        with_namespace(&mut request);
        match ContentClient::new(channel.clone()).info(request).await {
            Ok(response) => Ok(response
                .into_inner()
                .info
                .and_then(|info| u64::try_from(info.size).ok())
                .map(|size| (channel, size))),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            // A containerd that went away or restarted: the next request connects again.
            Err(status) if status.code() == Code::Unavailable => {
                self.forget_channel().await;
                Ok(None)
            }
            Err(status) => Err(Error::Grpc(status)),
        }
    }
}

impl Content for Containerd {
    async fn open(&self, digest: &Digest) -> Result<Option<Blob>, Error> {
        // The blob streams from the handle that gave its size: containerd's garbage collector may delete the file
        // meanwhile. Opened and measured in one blocking task.
        let path = self.blob_path(digest);
        let opened = tokio::task::spawn_blocking(move || open_file(&path))
            .await
            .expect("opening a file does not panic")?;
        if let Some((file, size)) = opened {
            return Ok(Some(Blob::from_open(file, size)));
        }
        Ok(self
            .info(digest)
            .await?
            .map(|(channel, size)| Blob::from_grpc(channel, digest.to_string(), size)))
    }
}

/// The file at `path` and its size, or `None` when no file is there.
fn open_file(path: &Path) -> io::Result<Option<(File, u64)>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    Ok(meta.is_file().then_some((file, meta.len())))
}

#[cfg(test)]
mod tests;
