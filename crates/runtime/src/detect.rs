//! Which runtime serves the node: the one whose socket accepts a connection (D64).

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use std::{fmt, io};

/// containerd's socket.
pub const CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";

/// CRI-O's socket, which also serves its inspect API.
pub const CRIO_SOCKET: &str = "/var/run/crio/crio.sock";

/// How long a socket may take to accept before it counts as not answering.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// A CRI runtime the agent supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    /// containerd, 2.3 and later (D15).
    Containerd,
    /// CRI-O, 1.35 and later (D64).
    CriO,
}

impl Runtime {
    /// The name NRI's `Configure.runtime_name` gives it, and `--runtime` takes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Containerd => "containerd",
            Self::CriO => "cri-o",
        }
    }
}

impl fmt::Display for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where each runtime's socket is.
#[derive(Clone, Debug)]
pub struct Sockets {
    /// containerd's.
    pub containerd: PathBuf,
    /// CRI-O's.
    pub crio: PathBuf,
}

impl Sockets {
    /// The sockets of a node: [`CONTAINERD_SOCKET`] and [`CRIO_SOCKET`].
    #[must_use]
    pub fn system() -> Self {
        Self {
            containerd: PathBuf::from(CONTAINERD_SOCKET),
            crio: PathBuf::from(CRIO_SOCKET),
        }
    }
}

/// What a socket answered to a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// It accepted.
    Accepted,
    /// It did not: the reason, as the system or the probe gives it.
    Refused(String),
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted => f.write_str("accepted a connection"),
            Self::Refused(reason) => f.write_str(reason),
        }
    }
}

/// Neither socket, or both, answered.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "{} ({}): {containerd}; {} ({}): {crio}; exactly one runtime must answer (--runtime names it)",
    Runtime::Containerd,
    containerd_path.display(),
    Runtime::CriO,
    crio_path.display()
)]
pub struct DetectError {
    containerd_path: PathBuf,
    containerd: Answer,
    crio_path: PathBuf,
    crio: Answer,
}

impl DetectError {
    /// Whether both runtimes accepted, rather than neither.
    #[must_use]
    pub fn is_ambiguous(&self) -> bool {
        self.containerd == Answer::Accepted && self.crio == Answer::Accepted
    }
}

/// The runtime whose socket accepts a connection, when exactly one does.
///
/// # Errors
///
/// When neither or both do; the error names both sockets and what each answered.
pub fn detect(sockets: &Sockets) -> Result<Runtime, DetectError> {
    let containerd = probe(&sockets.containerd);
    let crio = probe(&sockets.crio);
    match (&containerd, &crio) {
        (Answer::Accepted, Answer::Refused(_)) => Ok(Runtime::Containerd),
        (Answer::Refused(_), Answer::Accepted) => Ok(Runtime::CriO),
        _ => Err(DetectError {
            containerd_path: sockets.containerd.clone(),
            containerd,
            crio_path: sockets.crio.clone(),
            crio,
        }),
    }
}

/// Connects to `path` and drops the connection at once, as `crictl` does when it checks an endpoint.
fn probe(path: &Path) -> Answer {
    let (sender, receiver) = mpsc::channel();
    let target = path.to_owned();
    // A socket whose backlog is full blocks `connect`; the thread is left to it when the probe gives up.
    std::thread::spawn(move || {
        // The probe has stopped listening when the send fails: nothing more to do.
        drop(sender.send(UnixStream::connect(target).map(drop)));
    });
    match receiver.recv_timeout(PROBE_TIMEOUT) {
        Ok(Ok(())) => Answer::Accepted,
        Ok(Err(e)) => Answer::Refused(reason(&e)),
        Err(_) => Answer::Refused(format!("no answer in {}s", PROBE_TIMEOUT.as_secs())),
    }
}

fn reason(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "no such socket".to_owned(),
        _ => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    struct Node {
        dir: tempfile::TempDir,
        listeners: Vec<UnixListener>,
    }

    impl Node {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                listeners: Vec::new(),
            }
        }

        fn serve(&mut self, name: &str) -> PathBuf {
            let path = self.dir.path().join(name);
            self.listeners.push(UnixListener::bind(&path).unwrap());
            path
        }

        fn sockets(&self, containerd: &str, crio: &str) -> Sockets {
            Sockets {
                containerd: self.dir.path().join(containerd),
                crio: self.dir.path().join(crio),
            }
        }
    }

    #[test]
    fn the_one_socket_that_accepts_names_the_runtime() {
        let mut node = Node::new();
        node.serve("containerd.sock");
        assert_eq!(
            detect(&node.sockets("containerd.sock", "crio.sock")),
            Ok(Runtime::Containerd)
        );
        let mut node = Node::new();
        node.serve("crio.sock");
        assert_eq!(
            detect(&node.sockets("containerd.sock", "crio.sock")),
            Ok(Runtime::CriO)
        );
    }

    #[test]
    fn neither_or_both_is_refused_naming_both_sockets_and_their_answers() {
        let node = Node::new();
        let sockets = node.sockets("containerd.sock", "crio.sock");
        let err = detect(&sockets).unwrap_err();
        assert!(!err.is_ambiguous());
        let text = err.to_string();
        for want in [
            "containerd (",
            "containerd.sock): no such socket",
            "cri-o (",
            "crio.sock): no such socket",
            "--runtime",
        ] {
            assert!(text.contains(want), "{text}");
        }

        let mut node = Node::new();
        node.serve("containerd.sock");
        node.serve("crio.sock");
        let err = detect(&node.sockets("containerd.sock", "crio.sock")).unwrap_err();
        assert!(err.is_ambiguous());
        assert_eq!(err.to_string().matches("accepted a connection").count(), 2);
    }

    #[test]
    fn a_path_that_is_not_a_socket_is_refused_with_the_systems_reason() {
        let mut node = Node::new();
        node.serve("crio.sock");
        std::fs::write(node.dir.path().join("containerd.sock"), "").unwrap();
        let sockets = node.sockets("containerd.sock", "crio.sock");
        assert_eq!(detect(&sockets), Ok(Runtime::CriO));
        let Answer::Refused(reason) = probe(&sockets.containerd) else {
            panic!("a file accepted a connection");
        };
        assert!(!reason.is_empty() && reason != "no such socket", "{reason}");
    }

    #[test]
    fn names_are_those_of_nri_and_the_flag() {
        assert_eq!(Runtime::Containerd.to_string(), "containerd");
        assert_eq!(Runtime::CriO.to_string(), "cri-o");
        assert_eq!(Sockets::system().containerd, Path::new(CONTAINERD_SOCKET));
        assert_eq!(Sockets::system().crio, Path::new(CRIO_SOCKET));
    }
}
