//! CRI-O's images as [`Images`]: CRI `ListImages`, read again each time `images.json` is replaced (D65, D116).
//!
//! CRI-O streams no image events. Its store rewrites `images.json` whole, by a rename, at each change (go.podman.io/storage
//! v1.63.0, as CRI-O v1.37.0 vendors it, `images.go:566-586` through `ioutils.AtomicWriteFile`); the agent watches the
//! file's directory with inotify, since a watch on the file would follow the replaced one.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::sync::mpsc;

use super::{CriO, config, images_directory};
use crate::images::{self, Images, Lost, RELIST, Update};

impl Images for CriO {
    fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()> {
        Box::pin(async move { self.follow_images(&updates, RELIST).await })
    }
}

impl CriO {
    /// Follows the image list, reading it every `every`, until `updates` closes.
    pub(crate) async fn follow_images(&self, updates: &mpsc::Sender<Update>, every: Duration) {
        images::follow(&self.socket, updates, every, "CRI-O", |hint| {
            self.image_hints(hint)
        })
        .await;
    }

    /// Sends a hint each time `images.json` is replaced, until its directory goes away.
    async fn image_hints(&self, hint: mpsc::Sender<()>) -> Lost {
        let socket = self.socket.clone();
        let read = tokio::task::spawn_blocking(move || config(&socket))
            .await
            .expect("reading CRI-O's config does not panic");
        match read.and_then(|text| images_directory(&text)) {
            Ok(directory) => watch(&self.paths.at(&directory), &hint).await,
            Err(e) => Lost::Unreachable(e.to_string()),
        }
    }
}

/// The file whose replacement hints that the list changed.
#[cfg(target_os = "linux")]
const LIST: &[u8] = b"images.json";

/// How long a watch waits for events before it checks whether anyone still reads its hints.
#[cfg(target_os = "linux")]
const WAKE: rustix::event::Timespec = rustix::event::Timespec {
    tv_sec: 1,
    tv_nsec: 0,
};

/// Hints at each `images.json` moved into, or written in, `directory`, and when the kernel dropped events.
///
/// The watch blocks a thread: tokio registers a descriptor only through `unsafe` (`AsyncFd::register`), which this
/// crate denies. The thread ends within [`WAKE`] of the hints' reader.
#[cfg(target_os = "linux")]
async fn watch(directory: &Path, hint: &mpsc::Sender<()>) -> Lost {
    let directory = directory.to_owned();
    let hint = hint.clone();
    tokio::task::spawn_blocking(move || watch_blocking(&directory, &hint))
        .await
        .expect("watching a directory does not panic")
}

#[cfg(target_os = "linux")]
fn watch_blocking(directory: &Path, hint: &mpsc::Sender<()>) -> Lost {
    use std::mem::MaybeUninit;

    use rustix::event::{PollFd, PollFlags, poll};
    use rustix::fs::inotify::{self, CreateFlags, ReadFlags, Reader, WatchFlags};
    use rustix::io::Errno;

    let unreachable = |e: Errno| Lost::Unreachable(format!("{}: {e}", directory.display()));
    // The kernel sends `IGNORED` when the directory goes, whatever the mask.
    let flags = WatchFlags::MOVED_TO | WatchFlags::CLOSE_WRITE | WatchFlags::ONLYDIR;
    let fd = match inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC)
        .and_then(|fd| inotify::add_watch(&fd, directory, flags).map(|_| fd))
    {
        Ok(fd) => fd,
        Err(e) => return unreachable(e),
    };
    let mut buffer = [MaybeUninit::uninit(); 4096];
    while !hint.is_closed() {
        match poll(&mut [PollFd::new(&fd, PollFlags::IN)], Some(&WAKE)) {
            Ok(_) | Err(Errno::INTR) => {}
            Err(e) => return unreachable(e),
        }
        let mut events = Reader::new(&fd, &mut buffer);
        loop {
            match events.next() {
                // The watch is gone with its directory: a new store needs a new watch.
                Ok(event) if event.events().contains(ReadFlags::IGNORED) => return Lost::Ended,
                Ok(event) => {
                    let list = event
                        .file_name()
                        .is_some_and(|name| name.to_bytes() == LIST);
                    if list || event.events().contains(ReadFlags::QUEUE_OVERFLOW) {
                        // A full channel holds a hint already: the list is read once for both.
                        let _ = hint.try_send(());
                    }
                }
                Err(Errno::AGAIN) => break,
                Err(e) => return unreachable(e),
            }
        }
    }
    Lost::Closed
}

/// CRI-O runs on Linux alone; elsewhere tests run it, and the list is read every interval.
#[cfg(not(target_os = "linux"))]
async fn watch(_directory: &Path, _hint: &mpsc::Sender<()>) -> Lost {
    std::future::pending().await
}

#[cfg(test)]
mod tests;
