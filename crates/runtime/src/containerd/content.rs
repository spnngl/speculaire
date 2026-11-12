//! containerd's content: its directory, then its content service.

use std::io;
use std::path::PathBuf;

use containerd_client::services::v1::InfoRequest;
use containerd_client::services::v1::content_client::ContentClient;
use containerd_client::tonic::transport::Channel;
use containerd_client::tonic::{Code, Request};
use speculaire_oci::reference::Digest;

use super::{Containerd, NAMESPACE};
use crate::content::{Blob, Content, Error, with_namespace};

impl Containerd {
    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.content_directory
            .join("blobs")
            .join(digest.algorithm())
            .join(digest.encoded())
    }

    /// A channel to containerd, made once and kept; `None` while there is no containerd to connect to.
    async fn channel(&self) -> Option<Channel> {
        let mut held = self.channel.lock().await;
        if held.is_none() {
            *held = containerd_client::connect(&self.socket).await.ok();
        }
        held.clone()
    }

    async fn forget_channel(&self) {
        *self.channel.lock().await = None;
    }

    /// The size of the blob if containerd's content service has it.
    async fn info(&self, digest: &Digest) -> Result<Option<(Channel, u64)>, Error> {
        let Some(channel) = self.channel().await else {
            return Ok(None);
        };
        let mut request = Request::new(InfoRequest {
            digest: digest.to_string(),
        });
        with_namespace(&mut request, NAMESPACE);
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
        let path = self.blob_path(digest);
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.is_file() => return Ok(Some(Blob::from_file(path, meta.len()))),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
        Ok(self.info(digest).await?.map(|(channel, size)| {
            Blob::from_grpc(channel, digest.to_string(), NAMESPACE.to_owned(), size)
        }))
    }
}

#[cfg(test)]
mod tests;
