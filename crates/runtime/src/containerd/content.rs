//! containerd's content: its directory, then its content service.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use containerd_client::services::v1::content_client::ContentClient;
use containerd_client::services::v1::{InfoRequest, WriteAction, WriteContentRequest};
use containerd_client::tonic::transport::Channel;
use containerd_client::tonic::{Code, Request, Status};
use futures_util::StreamExt as _;
use speculaire_oci::reference::Digest;

use super::{Containerd, with_namespace};
use crate::content::{Blob, Chunks, Content, Error};

/// The most a write message carries: containerd takes 16 MiB a message.
const WRITE: usize = 1 << 20;
/// [`WRITE`] as an offset.
const WRITE_I64: i64 = 1 << 20;

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

    /// Writes the blob `digest` from `chunks` through containerd's content service, which checks the digest as it
    /// commits, and leaves a blob it holds as it is (D195). The manifest that names the blob keeps it from containerd's
    /// garbage collector.
    ///
    /// # Errors
    ///
    /// When containerd is out of reach or refuses the blob, or `chunks` fails: the write is then left uncommitted, and
    /// containerd drops it.
    pub async fn write(&self, digest: &Digest, mut chunks: Chunks) -> Result<(), Error> {
        let Some(channel) = self.channel().await else {
            return Err(Error::Grpc(Status::unavailable(
                "containerd is out of reach",
            )));
        };
        let (requests, taken) = tokio::sync::mpsc::channel(1);
        let mut request = Request::new(futures_util::stream::unfold(taken, |mut taken| async {
            taken.recv().await.map(|message| (message, taken))
        }));
        with_namespace(&mut request);
        let message = |action: WriteAction, offset: i64, data: Vec<u8>| WriteContentRequest {
            action: action.into(),
            r#ref: format!("speculaire-{digest}"),
            expected: digest.to_string(),
            offset,
            data,
            ..WriteContentRequest::default()
        };
        // Sends `chunks` in messages of `WRITE` bytes, then the rest in the one that commits; it stops once containerd
        // does.
        let feed = async move {
            let mut offset = 0_i64;
            let mut data = Vec::new();
            while let Some(chunk) = chunks.next().await.transpose()? {
                data.extend_from_slice(&chunk);
                while data.len() >= WRITE {
                    let rest = data.split_off(WRITE);
                    let sent = std::mem::replace(&mut data, rest);
                    if requests
                        .send(message(WriteAction::Write, offset, sent))
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }
                    offset = offset.saturating_add(WRITE_I64);
                }
            }
            // An error means containerd ended the write, which `answers` tells.
            let _ = requests
                .send(message(WriteAction::Commit, offset, data))
                .await;
            Ok(())
        };
        let answers = async {
            let mut answers = ContentClient::new(channel)
                .write(request)
                .await?
                .into_inner();
            while answers.message().await?.is_some() {}
            Ok::<_, Status>(())
        };
        match tokio::join!(answers, feed) {
            (_, Err(err)) => Err(err),
            (Err(status), Ok(())) if status.code() == Code::AlreadyExists => Ok(()),
            (Err(status), Ok(())) => Err(Error::Grpc(status)),
            (Ok(()), Ok(())) => Ok(()),
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
