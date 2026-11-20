//! The NRI subcommands (D29): `nri-version` answers NRI's inference of a runtime's NRI version, and `nri-runtime` is
//! a session with an NRI runtime on `pkg/adaptation`, which drives plugins as containerd and CRI-O do, or with its raw
//! mode, which writes the two frames `pkg/adaptation` never sends: one over `maxPayloadSize`, and a stall.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command as Process, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Oracle, answer};

/// One `nri-version` case: a runtime as `Configure` names it, and its version.
#[derive(Debug, Clone, Serialize)]
pub struct VersionCase {
    /// `containerd` or `cri-o`.
    pub runtime: String,
    /// As `v2.4.2`.
    pub version: String,
}

/// NRI's answer to a [`VersionCase`] (`pkg/api/version.go:35` at v0.12.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionAnswer {
    /// The NRI version the runtime links, as `v0.11.0`.
    NriVersion(String),
    /// Why NRI cannot tell.
    Error(String),
}

/// How a runtime starts: what it announces in `Configure`, and its limits.
#[derive(Debug, Clone, Serialize)]
pub struct Start {
    /// The socket the runtime listens on.
    pub socket: PathBuf,
    /// `containerd` or `cri-o`, as `Configure` names the runtime.
    pub runtime_name: String,
    /// As `v2.4.2`.
    pub runtime_version: String,
    /// The NRI version `Configure` announces: `None` keeps the oracle's, NRI v0.12.3; CRI-O 1.35 and 1.36 announce
    /// `Some("")` (D64).
    pub nri_version: Option<String>,
    /// How long a plugin has to register.
    #[serde(rename = "registration_timeout_ms", serialize_with = "millis")]
    pub registration_timeout: Duration,
    /// How long a plugin has to answer a request.
    #[serde(rename = "request_timeout_ms", serialize_with = "millis")]
    pub request_timeout: Duration,
    /// Plugins without which NRI's default validator rejects every container.
    pub required_plugins: Vec<String>,
}

impl Start {
    /// A runtime with NRI's default timeouts, 5 s and 2 s (`pkg/api/timeouts.go:25-27` at v0.12.3).
    #[must_use]
    pub fn new(socket: PathBuf, runtime_name: &str, runtime_version: &str) -> Self {
        Self {
            socket,
            runtime_name: runtime_name.to_owned(),
            runtime_version: runtime_version.to_owned(),
            nri_version: None,
            registration_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(2),
            required_plugins: Vec::new(),
        }
    }
}

/// The pods and containers each connecting plugin gets in `Synchronize`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct State {
    /// The pods.
    pub pods: Vec<Pod>,
    /// The containers, running.
    pub containers: Vec<Container>,
}

impl State {
    /// `pods` pods and `containers` containers spread over them, each container with an annotation of `padding` bytes.
    #[must_use]
    pub fn padded(pods: usize, containers: usize, padding: usize) -> Self {
        let pod = |i: usize| Pod {
            id: format!("pod-{i}"),
            name: format!("pod-{i}"),
            namespace: "default".to_owned(),
            ..Pod::default()
        };
        let container = |i: usize| Container {
            id: format!("container-{i}"),
            pod_id: format!("pod-{}", i % pods.max(1)),
            name: format!("container-{i}"),
            annotations: BTreeMap::from([("padding".to_owned(), "x".repeat(padding))]),
            ..Container::default()
        };
        Self {
            pods: (0..pods).map(pod).collect(),
            containers: (0..containers).map(container).collect(),
        }
    }
}

/// A pod sandbox as the runtime describes it to plugins.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Pod {
    /// The sandbox ID.
    pub id: String,
    /// The pod's name.
    pub name: String,
    /// The pod's UID.
    pub uid: String,
    /// The pod's namespace.
    pub namespace: String,
    /// The pod's annotations.
    pub annotations: BTreeMap<String, String>,
}

/// A container as the runtime describes it to plugins.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Container {
    /// The container ID.
    pub id: String,
    /// Its pod's sandbox ID; in a [`Create`], empty means the pod's.
    pub pod_id: String,
    /// The container's name.
    pub name: String,
    /// The image, which runtimes send from NRI v0.12.2 on.
    pub image: Option<Image>,
    /// The container's annotations.
    pub annotations: BTreeMap<String, String>,
}

/// The image of a container (`pkg/api/api.proto:442-452` at v0.12.3).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Image {
    /// The image reference.
    pub name: String,
    /// The index or manifest digest.
    pub digest: String,
    /// The config digest.
    pub config_digest: String,
}

/// A `CreateContainer` request.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Create {
    /// The container's pod.
    pub pod: Pod,
    /// The container.
    pub container: Container,
}

/// What the plugins answered a [`Create`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every plugin allowed the container.
    Allowed,
    /// The error that refused it.
    Rejected(String),
}

/// NRI's own `pkg/stub` plugin, run inside the oracle.
#[derive(Debug, Clone, Serialize)]
pub struct Stub {
    /// Its name.
    pub name: String,
    /// Its index, as `10`.
    pub index: String,
    /// The error it answers each `CreateContainer` with; `None` allows every container.
    pub reject: Option<String>,
}

/// What a [`Stub`] learnt from `Configure`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Configured {
    /// The runtime's NRI version, announced or inferred.
    pub runtime_nri_version: String,
    /// The registration timeout.
    #[serde(rename = "registration_timeout_ms", deserialize_with = "from_millis")]
    pub registration_timeout: Duration,
    /// The request timeout.
    #[serde(rename = "request_timeout_ms", deserialize_with = "from_millis")]
    pub request_timeout: Duration,
}

/// The connected plugins and, in raw mode, the frames left unread.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Report {
    /// The plugins connected and synchronized.
    pub plugins: Vec<Plugin>,
    /// In raw mode, the stalled connection.
    pub stalled: Option<Stalled>,
}

/// One connected plugin.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Plugin {
    /// Its index and name, as `10-speculaire`.
    pub name: String,
    /// The events it is subscribed to, as `CREATE_CONTAINER`.
    pub events: Vec<String>,
    /// The `Synchronize` requests that reached a plugin of this name since the runtime started or last closed its
    /// connections.
    pub synchronize_requests: usize,
}

/// The frames the raw mode read off `ConnID` 2, where the plugin calls the runtime, and never delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Stalled {
    /// Frames read.
    pub frames: usize,
    /// Their payload bytes.
    pub bytes: u64,
}

/// The bytes of a frame that reached the socket, and why the rest did not.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Written {
    /// Header and payload bytes written.
    pub bytes: u64,
    /// The write's error, as a plugin that closed the connection.
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct Closed {
    closed: usize,
}

/// A command of `nri-runtime`: a JSON object whose only key names it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Command<'a> {
    Start(&'a Start),
    State(&'a State),
    Stub(&'a Stub),
    Wait {
        plugins: usize,
        #[serde(rename = "timeout_ms", serialize_with = "millis")]
        timeout: Duration,
    },
    Create(&'a Create),
    Close {},
    Report {},
    Raw {
        socket: &'a PathBuf,
        #[serde(rename = "request_timeout_ms", serialize_with = "millis")]
        request_timeout: Duration,
    },
    Accept {
        #[serde(rename = "timeout_ms", serialize_with = "millis")]
        timeout: Duration,
    },
    Oversize {
        conn_id: u32,
    },
}

/// A running `nri-runtime`, killed when dropped. Each method writes one command and reads its answer.
#[derive(Debug)]
pub struct Runtime {
    path: PathBuf,
    timeout: Duration,
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<std::io::Result<String>>,
    sent: usize,
}

impl Oracle {
    /// Starts `nri-runtime`. NRI's logs go to the test's stderr.
    ///
    /// # Errors
    ///
    /// When the binary cannot run.
    pub fn nri_runtime(&self) -> Result<Runtime, Error> {
        self.session(&["nri-runtime"])
    }

    fn session(&self, args: &[&str]) -> Result<Runtime, Error> {
        let run = |source| Error::Run {
            path: self.path.clone(),
            source,
        };
        let mut child = Process::new(&self.path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(run)?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return Err(run(std::io::Error::other("the child lacks a pipe")));
        };
        // A thread reads the answers, so that a hung oracle meets the timeout. It ends with the child's stdout.
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if send.send(line).is_err() {
                    return;
                }
            }
        });
        Ok(Runtime {
            path: self.path.clone(),
            timeout: self.timeout,
            child,
            stdin,
            lines,
            sent: 0,
        })
    }
}

impl Runtime {
    /// Starts a runtime on `pkg/adaptation`, listening on [`Start::socket`].
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session, and as [`Error::Refused`] when the runtime cannot start.
    pub fn start(&mut self, start: &Start) -> Result<(), Error> {
        self.call::<IgnoredAny>(&Command::Start(start)).map(drop)
    }

    /// Replaces the state each plugin that connects from now on gets in `Synchronize`.
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session.
    pub fn state(&mut self, state: &State) -> Result<(), Error> {
        self.call::<IgnoredAny>(&Command::State(state)).map(drop)
    }

    /// Connects NRI's own `pkg/stub` plugin, and returns once the runtime has configured it.
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session, and as [`Error::Refused`] when the stub fails to register.
    pub fn stub(&mut self, stub: &Stub) -> Result<Configured, Error> {
        self.call(&Command::Stub(stub))
    }

    /// Waits until `plugins` plugins are connected and synchronized, and reports them.
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session, and as [`Error::Refused`] when the count differs after `timeout`.
    pub fn wait(&mut self, plugins: usize, timeout: Duration) -> Result<Report, Error> {
        self.call(&Command::Wait { plugins, timeout })
    }

    /// Relays `CreateContainer` to the plugins, through `pkg/adaptation` or, in raw mode, on `ConnID` 1.
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session.
    pub fn create(&mut self, create: &Create) -> Result<Verdict, Error> {
        self.call(&Command::Create(create))
    }

    /// Closes every plugin's connection, as a runtime that exits does, and returns how many it closed.
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session.
    pub fn close(&mut self) -> Result<usize, Error> {
        self.call::<Closed>(&Command::Close {}).map(|c| c.closed)
    }

    /// Reports the connected plugins and, in raw mode, the stalled connection.
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session.
    pub fn report(&mut self) -> Result<Report, Error> {
        self.call(&Command::Report {})
    }

    /// Starts the raw mode, listening on `socket`; `create` then waits `request_timeout` for an answer.
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session, and as [`Error::Refused`] when the socket cannot be bound.
    pub fn raw(&mut self, socket: &PathBuf, request_timeout: Duration) -> Result<(), Error> {
        self.call::<IgnoredAny>(&Command::Raw {
            socket,
            request_timeout,
        })
        .map(drop)
    }

    /// Accepts a plugin's connection in raw mode, waiting at most `timeout`.
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session, and as [`Error::Refused`] when no plugin connects in time.
    pub fn accept(&mut self, timeout: Duration) -> Result<(), Error> {
        self.call::<IgnoredAny>(&Command::Accept { timeout })
            .map(drop)
    }

    /// Writes, in raw mode, one frame on `conn_id` whose length is `maxPayloadSize + 1`, header and payload.
    ///
    /// # Errors
    ///
    /// For an [`Error`] of the session.
    pub fn oversize(&mut self, conn_id: u32) -> Result<Written, Error> {
        self.call(&Command::Oversize { conn_id })
    }

    fn call<A: DeserializeOwned>(&mut self, command: &Command<'_>) -> Result<A, Error> {
        let index = self.sent;
        self.sent += 1;
        let mut line = serde_json::to_vec(command).map_err(|e| Error::Json {
            index,
            message: e.to_string(),
        })?;
        line.push(b'\n');
        if let Err(source) = self
            .stdin
            .write_all(&line)
            .and_then(|()| self.stdin.flush())
        {
            return Err(self.exited().unwrap_or(Error::Run {
                path: self.path.clone(),
                source,
            }));
        }
        match self.lines.recv_timeout(self.timeout) {
            Ok(Ok(line)) => answer(index, &line),
            Ok(Err(source)) => Err(Error::Run {
                path: self.path.clone(),
                source,
            }),
            Err(RecvTimeoutError::Timeout) => Err(Error::Timeout {
                path: self.path.clone(),
                after: self.timeout,
            }),
            Err(RecvTimeoutError::Disconnected) => {
                Err(self.exited().unwrap_or_else(|source| Error::Run {
                    path: self.path.clone(),
                    source,
                }))
            }
        }
    }

    /// The oracle's exit, once its stdout has closed.
    fn exited(&mut self) -> Result<Error, std::io::Error> {
        let status = self.child.wait()?;
        Ok(Error::Exit {
            path: self.path.clone(),
            status,
            stderr: "on the test's stderr".to_owned(),
        })
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // The child may have exited already: there is nothing to report from a drop.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn millis<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

fn from_millis<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    u64::deserialize(deserializer).map(Duration::from_millis)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A session of `sh -c script`. A script that hangs `exec`s its last command, so that the kill reaches it whichever
    /// shell `sh` is: a forked child would outlive the kill holding the test's stderr, which nextest fails (D72).
    fn fake(script: &str, timeout: Duration) -> Runtime {
        let oracle = Oracle {
            path: PathBuf::from("sh"),
            timeout,
        };
        oracle.session(&["-c", script]).unwrap()
    }

    #[test]
    fn commands_are_objects_named_by_their_only_key() {
        let socket = PathBuf::from("/run/nri.sock");
        let mut start = Start::new(socket.clone(), "cri-o", "v1.35.10");
        start.nri_version = Some(String::new());
        let cases = [
            (
                Command::Start(&start),
                json!({"start": {
                    "socket": "/run/nri.sock", "runtime_name": "cri-o", "runtime_version": "v1.35.10",
                    "nri_version": "", "registration_timeout_ms": 5000, "request_timeout_ms": 2000,
                    "required_plugins": [],
                }}),
            ),
            (
                Command::Wait {
                    plugins: 1,
                    timeout: Duration::from_millis(1500),
                },
                json!({"wait": {"plugins": 1, "timeout_ms": 1500}}),
            ),
            (Command::Close {}, json!({"close": {}})),
            (
                Command::Raw {
                    socket: &socket,
                    request_timeout: Duration::from_secs(1),
                },
                json!({"raw": {"socket": "/run/nri.sock", "request_timeout_ms": 1000}}),
            ),
            (
                Command::Oversize { conn_id: 1 },
                json!({"oversize": {"conn_id": 1}}),
            ),
        ];
        for (command, expected) in cases {
            assert_eq!(serde_json::to_value(&command).unwrap(), expected);
        }
    }

    #[test]
    fn a_padded_state_spreads_its_containers_over_its_pods() {
        let pod = |i: usize| {
            json!({"id": format!("pod-{i}"), "name": format!("pod-{i}"), "uid": "", "namespace": "default",
                "annotations": {}})
        };
        let container = |i: usize, pod: usize| {
            json!({"id": format!("container-{i}"), "pod_id": format!("pod-{pod}"), "name": format!("container-{i}"),
                "image": null, "annotations": {"padding": "xxxx"}})
        };
        assert_eq!(
            serde_json::to_value(State::padded(2, 3, 4)).unwrap(),
            json!({"pods": [pod(0), pod(1)], "containers": [container(0, 0), container(1, 1), container(2, 0)]})
        );
    }

    #[test]
    fn answers_are_read_in_the_shape_of_their_command() {
        // The fake answers each command with the next line of a script, after reading it.
        let mut runtime = fake(
            r#"read l; echo '{"closed":2}'; read l; echo '"allowed"'; read l; echo '{"rejected":"no"}'"#,
            Duration::from_secs(10),
        );
        assert_eq!(runtime.close().unwrap(), 2);
        assert_eq!(
            runtime.create(&Create::default()).unwrap(),
            Verdict::Allowed
        );
        assert_eq!(
            runtime.create(&Create::default()).unwrap(),
            Verdict::Rejected("no".to_owned())
        );
    }

    #[test]
    fn a_command_the_oracle_refuses_is_an_error_naming_it() {
        let mut runtime = fake(
            r#"read l; echo '{}'; while read l; do echo '{"oracle_error":"bad"}'; done"#,
            Duration::from_secs(10),
        );
        let second = Duration::from_secs(1);
        runtime.accept(second).unwrap();
        let socket = PathBuf::from("/run/nri.sock");
        let refusals = [
            runtime.accept(second),
            runtime.start(&Start::new(socket.clone(), "containerd", "v2.4.2")),
            runtime.state(&State::default()),
            runtime.raw(&socket, second),
        ];
        for (index, refusal) in (1..).zip(refusals) {
            assert_eq!(
                refusal.unwrap_err().to_string(),
                format!("case {index}: the oracle refused it: bad")
            );
        }
    }

    #[test]
    fn a_stub_answers_the_timeouts_it_was_configured_with() {
        let mut runtime = fake(
            r#"read l; echo '{"runtime_nri_version":"v0.11.0","registration_timeout_ms":3000,"request_timeout_ms":1500}'"#,
            Duration::from_secs(10),
        );
        let stub = Stub {
            name: "speculaire".to_owned(),
            index: "10".to_owned(),
            reject: None,
        };
        assert_eq!(
            runtime.stub(&stub).unwrap(),
            Configured {
                runtime_nri_version: "v0.11.0".to_owned(),
                registration_timeout: Duration::from_secs(3),
                request_timeout: Duration::from_millis(1500),
            }
        );
    }

    #[test]
    fn a_dropped_runtime_kills_the_oracle() {
        let runtime = fake("exec sleep 600", Duration::from_secs(10));
        let pid = runtime.child.id().to_string();
        drop(runtime);
        let alive = Process::new("kill")
            .args(["-0", &pid])
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!alive.success(), "{pid} outlived its runtime");
    }

    #[test]
    fn an_oracle_that_exits_is_an_error_with_its_status() {
        let mut runtime = fake("read l; exit 3", Duration::from_secs(10));
        let err = runtime.report().unwrap_err();
        assert!(
            matches!(&err, Error::Exit { status, .. } if status.code() == Some(3)),
            "{err}"
        );
    }

    #[test]
    fn an_oracle_that_hangs_is_an_error_at_its_timeout() {
        let mut runtime = fake("exec sleep 600", Duration::from_millis(100));
        let err = runtime.report().unwrap_err();
        assert!(matches!(err, Error::Timeout { .. }), "{err}");
    }
}
