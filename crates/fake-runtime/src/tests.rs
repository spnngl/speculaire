//! The fake's own lifecycle.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};

use super::{Answers, Fake};

/// A process another test spawns holds the fake's socket until it execs: a stopped fake refuses even then.
#[test]
fn a_stopped_fake_refuses_connections_while_another_process_holds_its_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let child = listener.try_clone().unwrap();
    drop(Fake::serve(listener, Answers::containerd("v2.4.2")).unwrap());
    let refused = UnixStream::connect(&socket).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    drop(child);
}
